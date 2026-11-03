/**
 * @module grounding-compiler
 * @description Zero-LLM Turn-0 Workspace Schema & Raw-RAG Grounding Compiler (`INV-GH-01`, `INV-GH-02`, `INV-GH-04`, `INV-GH-09`).
 *
 * Deterministically introspects workspace tabular files (RFC-4180 CSV/TSV), JSON/JSONL datasets,
 * read-only SQLite databases, source code symbol headers, and documentation chunks at Turn 0 with
 * zero LLM ingestion calls (`llmIngestionCalls === 0`) and bit-identical KV-cache prefix hashing.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { okEnvelope } from '@krusch/toolkit/http';
import { openSqliteDb } from '@krusch/toolkit/sqlite';
import { createRawRagIndex, estimateTokenCount } from '@krusch/toolkit/raw-rag';
import { normalizePromptCachePrefix } from '@krusch/toolkit/harness-engineering';
import { resolveScaleProfile, buildScaleAwareDirective } from './scale-policy.js';
import { createToolBudgetGate } from './delta-tool-gate.js';

const SKIPPED_DIRS = new Set([
    '.git', 'node_modules', '.venv', 'venv', '__pycache__',
    'dist', 'build', '.next', '.cache', 'coverage'
]);

const TABULAR_EXTS = new Set(['.csv', '.tsv']);
const JSON_EXTS = new Set(['.json', '.jsonl', '.ndjson']);
const SQLITE_EXTS = new Set(['.sqlite', '.sqlite3', '.db']);
const CODE_EXTS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.py']);
const DOC_EXTS = new Set(['.md', '.txt', '.rst']);

const EXACT_ROW_COUNT_MAX_BYTES = 8 * 1024 * 1024;
const JSON_FULL_PARSE_MAX_BYTES = 1024 * 1024;
const MAX_COLUMNS = 30;
const MAX_SQLITE_TABLES = 12;
const MAX_CODE_SYMBOLS = 20;
const MAX_DOC_HEADINGS = 12;

const LOW_FORAGING_RULE =
    'Workspace schemas and key rules are pre-grounded below; do NOT run exploratory ls/cat/head reads unless a file is absent from Turn-0 schemas.';

const SQLITE_SIDECAR_RE = /\.(?:sqlite3?|db)-(?:wal|shm|journal)$/i;
const PANDAS_NA_LITERAL_RE = /^(?:NA|N\/A)$/i;
const EXPLICIT_NULL_TOKEN_RE = /^(?:null|nil|none|nan|#n\/a)$/i;
const INTEGER_RE = /^[+-]?(?:0|[1-9]\d{0,18})$/;
const FLOAT_RE = /^[+-]?(?:(?:0|[1-9]\d*)\.\d+|\.\d+|(?:0|[1-9]\d*)(?:\.\d+)?[eE][+-]?\d+)$/;
const BOOLEAN_RE = /^(?:true|false)$/i;
const ISO_DATE_RE = /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:[T\s]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;

function compareAscii(a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
}

function isSkippedFile(name) {
    return name === '.env' || name.startsWith('.env.') || name === '.DS_Store' || SQLITE_SIDECAR_RE.test(name);
}

function truncatePreview(value, maxChars = 48) {
    const clean = String(value ?? '').replace(/\s+/g, ' ').trim();
    return clean.length <= maxChars ? clean : `${clean.slice(0, Math.max(1, maxChars - 3))}...`;
}

function readBoundedBuffer(fullPath, maxBytes) {
    if (maxBytes <= 0) return Buffer.alloc(0);
    let fd = null;
    try {
        fd = fs.openSync(fullPath, 'r');
        const targetLen = Math.max(0, Math.trunc(maxBytes));
        const buf = Buffer.allocUnsafe(targetLen);
        let totalRead = 0;
        while (totalRead < targetLen) {
            const bytesRead = fs.readSync(fd, buf, totalRead, targetLen - totalRead, totalRead);
            if (bytesRead <= 0) break;
            totalRead += bytesRead;
        }
        return totalRead === targetLen ? buf : buf.subarray(0, totalRead);
    } finally {
        if (fd !== null) {
            try { fs.closeSync(fd); } catch { /* ignore */ }
        }
    }
}

function parseRfc4180Sample(rawText, delimiter, isTruncated) {
    const text = rawText.startsWith('\uFEFF') ? rawText.slice(1) : rawText;
    const rows = [];
    let currentRow = [];
    let field = '';
    let inQuotes = false;

    for (let i = 0; i < text.length; i += 1) {
        const ch = text[i];
        if (inQuotes) {
            if (ch === '"') {
                if (text[i + 1] === '"') {
                    field += '"';
                    i += 1;
                } else {
                    inQuotes = false;
                }
            } else {
                field += ch;
            }
            continue;
        }
        if (ch === '"' && field.length === 0) {
            inQuotes = true;
        } else if (ch === delimiter) {
            currentRow.push(field);
            field = '';
        } else if (ch === '\r') {
            currentRow.push(field);
            rows.push(currentRow);
            currentRow = [];
            field = '';
            if (text[i + 1] === '\n') i += 1;
        } else if (ch === '\n') {
            currentRow.push(field);
            rows.push(currentRow);
            currentRow = [];
            field = '';
        } else {
            field += ch;
        }
    }

    if ((!isTruncated || rows.length === 0) && (field.length > 0 || currentRow.length > 0)) {
        currentRow.push(field);
        rows.push(currentRow);
    }
    return rows.filter((row, idx) => idx === 0 || !(row.length === 1 && row[0] === ''));
}

function countCsvRowsBounded(fullPath, fileSize, parsedSampleRows, sampleByteLength) {
    if (fileSize === 0 || parsedSampleRows.length === 0) return { rowCount: 0, estimated: false };
    if (fileSize <= sampleByteLength) return { rowCount: Math.max(0, parsedSampleRows.length - 1), estimated: false };
    if (fileSize > EXACT_ROW_COUNT_MAX_BYTES) {
        const avgRowBytes = Math.max(1, sampleByteLength / Math.max(1, parsedSampleRows.length));
        return { rowCount: Math.max(0, Math.round(fileSize / avgRowBytes) - 1), estimated: true };
    }

    let fd = null;
    try {
        fd = fs.openSync(fullPath, 'r');
        const chunk = Buffer.allocUnsafe(65536);
        let offset = 0;
        let inQuotes = false;
        let quoteSafeNewlines = 0;
        let rawNewlines = 0;
        let lastByte = 0x0a;

        while (offset < fileSize) {
            const bytesRead = fs.readSync(fd, chunk, 0, Math.min(chunk.length, fileSize - offset), offset);
            if (bytesRead <= 0) break;
            for (let i = 0; i < bytesRead; i += 1) {
                const b = chunk[i];
                if (b === 0x22) inQuotes = !inQuotes;
                else if (b === 0x0a) {
                    rawNewlines += 1;
                    if (!inQuotes) quoteSafeNewlines += 1;
                }
            }
            lastByte = chunk[bytesRead - 1];
            offset += bytesRead;
        }

        const effectiveNewlines = inQuotes ? rawNewlines : quoteSafeNewlines;
        const totalRecords = lastByte === 0x0a ? effectiveNewlines : effectiveNewlines + 1;
        return { rowCount: Math.max(0, totalRecords - 1), estimated: false };
    } finally {
        if (fd !== null) {
            try { fs.closeSync(fd); } catch { /* ignore */ }
        }
    }
}

function classifyScalarString(raw) {
    const trimmed = String(raw ?? '').trim();
    if (trimmed === '' || EXPLICIT_NULL_TOKEN_RE.test(trimmed)) return 'empty';
    if (BOOLEAN_RE.test(trimmed)) return 'boolean';
    if (INTEGER_RE.test(trimmed)) return 'integer';
    if (FLOAT_RE.test(trimmed)) return 'float';
    if (ISO_DATE_RE.test(trimmed)) return 'iso_date';
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
        try {
            const parsed = JSON.parse(trimmed);
            if (parsed !== null && typeof parsed === 'object') return 'json';
        } catch { /* fall through */ }
    }
    return 'string';
}

function mergeScalarTypes(typesSet) {
    if (typesSet.size === 0) return 'empty';
    if (typesSet.size === 1) return [...typesSet][0];
    if (typesSet.size === 2 && typesSet.has('integer') && typesSet.has('float')) return 'float';
    return 'string';
}

function introspectDelimitedFile(fullPath, relPath, ext, fileSize, sha256, sampleBuffer, sampleRowsLimit) {
    const delimiter = ext === '.tsv' ? '\t' : ',';
    const isTruncated = fileSize > sampleBuffer.length;
    const parsedRows = parseRfc4180Sample(sampleBuffer.toString('utf8'), delimiter, isTruncated);
    const { rowCount, estimated } = countCsvRowsBounded(fullPath, fileSize, parsedRows, sampleBuffer.length);
    const base = { relPath, ext, kind: 'tabular', bytes: fileSize, sha256, delimiter };

    if (parsedRows.length === 0) {
        return {
            ...base,
            rowCount: 0,
            rowCountEstimated: false,
            columnCount: 0,
            hasLiteralNaHazard: false,
            naHazardColumns: [],
            columns: []
        };
    }

    const rawHeaders = parsedRows[0];
    const dataRows = parsedRows.slice(1);
    const colLimit = Math.min(rawHeaders.length, MAX_COLUMNS);
    const columns = [];

    for (let c = 0; c < colLimit; c += 1) {
        const name = String(rawHeaders[c] ?? '').trim() || `col_${c + 1}`;
        const typesSeen = new Set();
        const literalNaTokens = new Set();
        const orderedCandidates = [];
        let hasLiteralNaString = false;
        let nullable = dataRows.length === 0;

        for (let r = 0; r < dataRows.length; r += 1) {
            const trimmedCell = String(c < dataRows[r].length ? dataRows[r][c] ?? '' : '').trim();
            if (trimmedCell === '' || EXPLICIT_NULL_TOKEN_RE.test(trimmedCell)) {
                nullable = true;
                continue;
            }
            if (PANDAS_NA_LITERAL_RE.test(trimmedCell)) {
                hasLiteralNaString = true;
                if (literalNaTokens.size < 4) literalNaTokens.add(trimmedCell);
                orderedCandidates.push({ isNaLiteral: true, preview: truncatePreview(trimmedCell, 48) });
                continue;
            }
            const cellType = classifyScalarString(trimmedCell);
            if (cellType !== 'empty') typesSeen.add(cellType);
            orderedCandidates.push({ isNaLiteral: false, preview: truncatePreview(trimmedCell, 48) });
        }

        const regularMergedType = mergeScalarTypes(typesSeen);
        const treatNaAsString = hasLiteralNaString && (regularMergedType === 'empty' || regularMergedType === 'string');
        if (hasLiteralNaString) {
            if (treatNaAsString) {
                typesSeen.add('string');
            } else {
                nullable = true;
            }
        }
        if (typesSeen.size === 0) nullable = true;

        const sampleValues = [];
        const sampleSet = new Set();
        for (const candidate of orderedCandidates) {
            if (candidate.isNaLiteral && !treatNaAsString) continue;
            if (sampleValues.length >= sampleRowsLimit) break;
            if (!sampleSet.has(candidate.preview)) {
                sampleSet.add(candidate.preview);
                sampleValues.push(candidate.preview);
            }
        }

        if (treatNaAsString && sampleRowsLimit > 0 && literalNaTokens.size > 0) {
            const hasNaInSamples = sampleValues.some((v) => PANDAS_NA_LITERAL_RE.test(v));
            if (!hasNaInSamples) {
                const firstNaPreview = truncatePreview([...literalNaTokens][0], 48);
                if (sampleValues.length < sampleRowsLimit) {
                    sampleValues.push(firstNaPreview);
                } else {
                    sampleValues[sampleValues.length - 1] = firstNaPreview;
                }
            }
        }

        columns.push({
            name,
            inferredType: mergeScalarTypes(typesSeen),
            nullable,
            hasLiteralNaString,
            literalNaTokens: [...literalNaTokens],
            sampleValues
        });
    }

    const naHazardColumns = columns.filter((col) => col.hasLiteralNaString).map((col) => col.name);

    return {
        ...base,
        rowCount,
        rowCountEstimated: estimated,
        columnCount: rawHeaders.length,
        hasLiteralNaHazard: naHazardColumns.length > 0,
        naHazardColumns,
        columns
    };
}

function classifyJsValue(value) {
    if (value === null || value === undefined) return 'null';
    if (Array.isArray(value)) return 'array';
    if (typeof value === 'boolean') return 'boolean';
    if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'float';
    if (typeof value === 'string') return ISO_DATE_RE.test(value.trim()) ? 'iso_date' : 'string';
    if (typeof value === 'object') return 'object';
    return typeof value;
}

function summarizeObjectsSchema(objects) {
    const keyMetaMap = new Map();
    for (const obj of objects) {
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) continue;
        for (const key of Object.keys(obj)) {
            if (!keyMetaMap.has(key) && keyMetaMap.size >= MAX_COLUMNS) continue;
            let meta = keyMetaMap.get(key);
            if (!meta) {
                meta = {
                    nonNullTypes: new Set(),
                    hasNull: false,
                    hasEmptyArray: false,
                    hasNonEmptyArray: false
                };
                keyMetaMap.set(key, meta);
            }
            const val = obj[key];
            if (val === null) {
                meta.hasNull = true;
            } else if (val !== undefined) {
                if (Array.isArray(val)) {
                    meta.nonNullTypes.add('array');
                    if (val.length === 0) meta.hasEmptyArray = true;
                    else meta.hasNonEmptyArray = true;
                } else {
                    const valType = classifyJsValue(val);
                    if (valType !== 'null') meta.nonNullTypes.add(valType);
                }
            }
        }
    }

    const topLevelKeys = [...keyMetaMap.keys()];
    const valueTypes = {};
    const nullFields = [];
    const emptyArrayFields = [];
    const wildcardCandidateFields = [];

    for (const key of topLevelKeys) {
        const meta = keyMetaMap.get(key);
        if (meta.hasNull) nullFields.push(key);
        if (meta.hasEmptyArray) emptyArrayFields.push(key);
        if (meta.hasNull || meta.hasEmptyArray) {
            wildcardCandidateFields.push(key);
        }

        if (meta.nonNullTypes.size === 0) {
            valueTypes[key] = 'null';
            continue;
        }

        const normalizedSet = new Set(meta.nonNullTypes);
        if (normalizedSet.size === 2 && normalizedSet.has('integer') && normalizedSet.has('float')) {
            normalizedSet.delete('integer');
        }
        const renderedParts = [...normalizedSet].sort(compareAscii).map((t) => {
            if (t !== 'array') return t;
            if (meta.hasEmptyArray && meta.hasNonEmptyArray) return 'array(empty []|non-empty)';
            if (meta.hasEmptyArray) return 'array(empty [])';
            return 'array';
        });
        const baseLabel = renderedParts.join('|');
        valueTypes[key] = meta.hasNull ? `${baseLabel}|null` : baseLabel;
    }

    return { topLevelKeys, valueTypes, nullFields, emptyArrayFields, wildcardCandidateFields };
}

function countNonEmptyLinesBounded(fullPath, fileSize, sampleLinesCount, sampleByteLength) {
    if (fileSize === 0) return { count: 0, estimated: false };
    if (fileSize <= sampleByteLength) return { count: sampleLinesCount, estimated: false };
    if (fileSize > EXACT_ROW_COUNT_MAX_BYTES) {
        const avgLineBytes = Math.max(1, sampleByteLength / Math.max(1, sampleLinesCount));
        return { count: Math.max(1, Math.round(fileSize / avgLineBytes)), estimated: true };
    }
    const count = readBoundedBuffer(fullPath, fileSize)
        .toString('utf8')
        .split(/\r?\n/)
        .filter((l) => l.trim().length > 0).length;
    return { count, estimated: false };
}

function extractLeadingJsonObjectsFromPrefix(sampleText, maxObjects = 25) {
    const objects = [];
    let i = sampleText.search(/\S/);
    if (i < 0 || sampleText[i] !== '[') return objects;
    i += 1;

    while (i < sampleText.length && objects.length < maxObjects) {
        while (i < sampleText.length && /[\s,]/.test(sampleText[i])) i += 1;
        if (i >= sampleText.length || sampleText[i] !== '{') break;
        const start = i;
        let depth = 0;
        let inString = false;
        let escaped = false;
        let end = -1;
        for (let j = start; j < sampleText.length; j += 1) {
            const ch = sampleText[j];
            if (inString) {
                if (escaped) escaped = false;
                else if (ch === '\\') escaped = true;
                else if (ch === '"') inString = false;
                continue;
            }
            if (ch === '"') inString = true;
            else if (ch === '{') depth += 1;
            else if (ch === '}') {
                depth -= 1;
                if (depth === 0) { end = j + 1; break; }
            }
        }
        if (end === -1) break;
        try { objects.push(JSON.parse(sampleText.slice(start, end))); } catch { break; }
        i = end;
    }
    return objects;
}

function introspectJsonFile(fullPath, relPath, ext, fileSize, sha256, sampleBuffer) {
    const base = { relPath, ext, kind: 'json', bytes: fileSize, sha256 };
    if (ext === '.jsonl' || ext === '.ndjson') {
        const isTruncated = fileSize > sampleBuffer.length;
        const rawLines = sampleBuffer.toString('utf8').split(/\r?\n/);
        const usable = isTruncated && rawLines.length > 1 ? rawLines.slice(0, -1) : rawLines;
        const nonEmpty = usable.map((l) => l.trim()).filter(Boolean);
        const parsedObjects = [];
        for (const line of nonEmpty.slice(0, 200)) {
            try {
                const parsed = JSON.parse(line);
                if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) parsedObjects.push(parsed);
            } catch { /* skip malformed line */ }
        }
        const { count, estimated } = countNonEmptyLinesBounded(fullPath, fileSize, nonEmpty.length, sampleBuffer.length);
        const {
            topLevelKeys,
            valueTypes,
            nullFields,
            emptyArrayFields,
            wildcardCandidateFields
        } = summarizeObjectsSchema(parsedObjects);
        return {
            ...base,
            format: 'jsonl',
            rootType: 'jsonl',
            recordCount: count,
            recordCountEstimated: estimated,
            topLevelKeys,
            valueTypes,
            nullFields,
            emptyArrayFields,
            wildcardCandidateFields
        };
    }

    const parseBuffer = fileSize > sampleBuffer.length && fileSize <= JSON_FULL_PARSE_MAX_BYTES
        ? readBoundedBuffer(fullPath, fileSize)
        : sampleBuffer;
    const text = parseBuffer.toString('utf8');

    try {
        const parsed = JSON.parse(text);
        if (Array.isArray(parsed)) {
            const {
                topLevelKeys,
                valueTypes,
                nullFields,
                emptyArrayFields,
                wildcardCandidateFields
            } = summarizeObjectsSchema(parsed.slice(0, 500));
            return {
                ...base,
                format: 'json',
                rootType: 'array',
                recordCount: parsed.length,
                recordCountEstimated: false,
                topLevelKeys,
                valueTypes,
                nullFields,
                emptyArrayFields,
                wildcardCandidateFields
            };
        }
        if (parsed !== null && typeof parsed === 'object') {
            const allKeys = Object.keys(parsed);
            const topLevelKeys = allKeys.slice(0, MAX_COLUMNS);
            const valueTypes = {};
            const nullFields = [];
            const emptyArrayFields = [];
            const wildcardCandidateFields = [];
            for (const key of topLevelKeys) {
                const val = parsed[key];
                if (val === null) {
                    valueTypes[key] = 'null';
                    nullFields.push(key);
                    wildcardCandidateFields.push(key);
                } else if (Array.isArray(val)) {
                    valueTypes[key] = val.length === 0 ? 'array(empty [])' : `array(${val.length})`;
                    if (val.length === 0) {
                        emptyArrayFields.push(key);
                        wildcardCandidateFields.push(key);
                    }
                } else {
                    valueTypes[key] = classifyJsValue(val);
                }
            }
            return {
                ...base,
                format: 'json',
                rootType: 'object',
                recordCount: allKeys.length,
                recordCountEstimated: false,
                topLevelKeys,
                valueTypes,
                nullFields,
                emptyArrayFields,
                wildcardCandidateFields
            };
        }
        return {
            ...base,
            format: 'json',
            rootType: classifyJsValue(parsed),
            recordCount: 1,
            recordCountEstimated: false,
            topLevelKeys: [],
            valueTypes: {},
            nullFields: [],
            emptyArrayFields: [],
            wildcardCandidateFields: []
        };
    } catch {
        const trimmed = text.trimStart();
        if (trimmed.startsWith('[')) {
            const sampleObjs = extractLeadingJsonObjectsFromPrefix(trimmed, 25);
            const {
                topLevelKeys,
                valueTypes,
                nullFields,
                emptyArrayFields,
                wildcardCandidateFields
            } = summarizeObjectsSchema(sampleObjs);
            const avgBytes = sampleObjs.length > 0 ? Math.max(16, text.length / sampleObjs.length) : 256;
            const estCount = sampleObjs.length > 0 ? Math.max(sampleObjs.length, Math.round(fileSize / avgBytes)) : 0;
            return {
                ...base,
                format: 'json',
                rootType: 'array',
                recordCount: estCount,
                recordCountEstimated: true,
                topLevelKeys,
                valueTypes,
                nullFields,
                emptyArrayFields,
                wildcardCandidateFields
            };
        }
        const topLevelKeys = [];
        const seen = new Set();
        for (const m of trimmed.matchAll(/"([A-Za-z0-9_.-]{1,64})"\s*:/g)) {
            if (!seen.has(m[1]) && topLevelKeys.length < MAX_COLUMNS) {
                seen.add(m[1]);
                topLevelKeys.push(m[1]);
            }
        }
        return {
            ...base,
            format: 'json',
            rootType: trimmed.startsWith('{') ? 'object' : 'unknown',
            recordCount: topLevelKeys.length,
            recordCountEstimated: true,
            topLevelKeys,
            valueTypes: {},
            nullFields: [],
            emptyArrayFields: [],
            wildcardCandidateFields: []
        };
    }
}

function introspectSqliteFile(fullPath, relPath, ext, fileSize, sha256) {
    const base = { relPath, ext, kind: 'sqlite', bytes: fileSize, sha256 };
    let handle = null;
    try {
        handle = openSqliteDb(fullPath, { readOnly: true, wal: false });
        const rawObjects = handle.query(
            `SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name`
        );
        const tables = [];

        for (const item of rawObjects.slice(0, MAX_SQLITE_TABLES)) {
            const tableName = String(item.name || '');
            if (!tableName) continue;
            const tableType = item.type === 'view' ? 'view' : 'table';
            const quoted = `"${tableName.replace(/"/g, '""')}"`;

            let columns = [];
            try {
                columns = handle.query(`PRAGMA table_info(${quoted})`).slice(0, 40).map((col) => ({
                    name: String(col.name ?? ''),
                    type: String(col.type || 'ANY'),
                    notnull: Boolean(col.notnull),
                    pk: Boolean(col.pk)
                }));
            } catch { columns = []; }

            let rowCount = 0;
            try {
                const cntRow = handle.queryOne(`SELECT COUNT(*) AS cnt FROM ${quoted}`);
                rowCount = Number(cntRow?.cnt ?? 0);
            } catch { rowCount = 0; }

            tables.push({ name: tableName, type: tableType, rowCount, columns });
        }

        return { ...base, validSqlite: true, tableCount: rawObjects.length, tables };
    } catch {
        return { ...base, validSqlite: false, tableCount: 0, tables: [] };
    } finally {
        if (handle) {
            try { handle.close(); } catch { /* ignore */ }
        }
    }
}

function introspectCodeFile(relPath, ext, fileSize, sha256, sampleBuffer) {
    const text = sampleBuffer.toString('utf8');
    const symbols = [];
    const seen = new Set();

    const pushSymbol = (rawSig) => {
        if (symbols.length >= MAX_CODE_SYMBOLS) return;
        const normalized = rawSig.replace(/\s+/g, ' ').trim();
        if (normalized && !seen.has(normalized)) {
            seen.add(normalized);
            symbols.push(normalized);
        }
    };

    if (ext === '.py') {
        const pyPattern = /^(?:async\s+def|def|class)\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*\([^)]*\))?/gm;
        let match;
        while ((match = pyPattern.exec(text)) !== null && symbols.length < MAX_CODE_SYMBOLS) {
            pushSymbol(match[0]);
        }
        return { relPath, ext, kind: 'code', language: 'python', bytes: fileSize, sha256, symbols };
    }

    const patterns = [
        /^export\s+(?:default\s+)?(?:async\s+)?function\s*\*?\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\([^)]*\)/gm,
        /^export\s+(?:default\s+)?class\s+[A-Za-z_$][A-Za-z0-9_$]*/gm,
        /^export\s+(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*/gm,
        /^export\s+(?:interface|type|enum)\s+[A-Za-z_$][A-Za-z0-9_$]*/gm,
        /^(?:async\s+)?function\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\([^)]*\)|^class\s+[A-Za-z_$][A-Za-z0-9_$]*/gm
    ];
    for (const pattern of patterns) {
        let match;
        while ((match = pattern.exec(text)) !== null && symbols.length < MAX_CODE_SYMBOLS) {
            pushSymbol(match[0]);
        }
    }
    const language = ext === '.ts' || ext === '.tsx' ? 'typescript' : 'javascript';
    return { relPath, ext, kind: 'code', language, bytes: fileSize, sha256, symbols };
}

function extractDocHeadings(text) {
    const headings = [];
    const lines = String(text || '').split(/\r?\n/);
    for (const line of lines) {
        if (headings.length >= MAX_DOC_HEADINGS) break;
        const mdMatch = /^(#{1,4})\s+(.+?)\s*$/.exec(line);
        if (mdMatch) headings.push(`${mdMatch[1]} ${mdMatch[2]}`);
    }
    if (headings.length === 0) {
        const firstLine = lines.map((l) => l.trim()).find((l) => l.length > 0);
        if (firstLine) headings.push(truncatePreview(firstLine, 72));
    }
    return headings;
}

function buildSchemaSummaryMarkdown(rootName, files, totalBytes) {
    if (files.length === 0) return '';
    const lines = [`### Workspace: \`${rootName}\` (${files.length} files, ${totalBytes} bytes)`];

    for (const f of files) {
        if (f.kind === 'tabular') {
            const rowLabel = f.rowCountEstimated ? `~${f.rowCount}` : `${f.rowCount}`;
            const colSummaries = f.columns.map((col) => {
                const nullFlag = col.nullable ? '?' : '';
                const samplePart = col.sampleValues.length > 0
                    ? ` [ex: ${col.sampleValues.map((v) => JSON.stringify(v)).join(', ')}]`
                    : '';
                const naFlag = col.hasLiteralNaString ? ' [LITERAL "NA" -> keep_default_na=False]' : '';
                return `${col.name}: ${col.inferredType}${nullFlag}${samplePart}${naFlag}`;
            });
            const extraCols = f.columnCount > f.columns.length ? `, +${f.columnCount - f.columns.length} more` : '';
            lines.push(`- \`${f.relPath}\` (${f.ext.slice(1).toUpperCase()}, ${rowLabel} rows, ${f.columnCount} cols): ${colSummaries.join('; ')}${extraCols}`);
            if (f.hasLiteralNaHazard && Array.isArray(f.naHazardColumns) && f.naHazardColumns.length > 0) {
                lines.push(`  - [CSV NA-LITERAL HAZARD in \`${f.relPath}\` (${f.naHazardColumns.join(', ')})]: Contains literal "NA"/"N/A" tokens that pandas.read_csv() silently converts to NaN; pass keep_default_na=False.`);
            }
        } else if (f.kind === 'json') {
            const recLabel = f.recordCountEstimated ? `~${f.recordCount}` : `${f.recordCount}`;
            const keySummaries = f.topLevelKeys.map((k) => (f.valueTypes[k] ? `${k}: ${f.valueTypes[k]}` : k));
            lines.push(`- \`${f.relPath}\` (${f.rootType}, ${recLabel} records/keys)${keySummaries.length > 0 ? `: { ${keySummaries.join(', ')} }` : ''}`);
            const hasEmptyArr = Array.isArray(f.emptyArrayFields) && f.emptyArrayFields.length > 0;
            const hasNulls = Array.isArray(f.nullFields) && f.nullFields.length > 0;
            if (hasEmptyArr || hasNulls) {
                const hazardParts = [];
                if (hasEmptyArr) hazardParts.push(`empty [] fields=[${f.emptyArrayFields.join(', ')}]`);
                if (hasNulls) hazardParts.push(`null fields=[${f.nullFields.join(', ')}]`);
                lines.push(`  - [JSON NULL / EMPTY-LIST [] WILDCARD HAZARD in \`${f.relPath}\`]: ${hazardParts.join('; ')} — empty arrays [] and null frequently denote wildcards ("match all") in rule/filter schemas rather than empty sets; handle both explicitly before membership checks.`);
            }
        } else if (f.kind === 'sqlite') {
            if (!f.validSqlite) {
                lines.push(`- \`${f.relPath}\` (binary/non-SQLite db, ${f.bytes} bytes)`);
            } else {
                const tblParts = f.tables.map((t) => {
                    const cols = t.columns.map((c) => `${c.name}:${c.type}${c.pk ? '[PK]' : ''}${c.notnull ? '!' : ''}`).join(', ');
                    return `${t.name} (${t.type}, ${t.rowCount} rows: ${cols})`;
                });
                lines.push(`- \`${f.relPath}\` (SQLite, ${f.tableCount} tables/views): ${tblParts.join(' | ')}`);
            }
        } else if (f.kind === 'code') {
            const symPart = f.symbols.length > 0 ? `: ${f.symbols.join(' | ')}` : '';
            lines.push(`- \`${f.relPath}\` (${f.language}, ${f.bytes} bytes)${symPart}`);
        } else if (f.kind === 'doc') {
            const headingPart = f.headings.length > 0 ? ` — sections: ${f.headings.join(' | ')}` : '';
            lines.push(`- \`${f.relPath}\` (doc, ${f.bytes} bytes)${headingPart}`);
        } else {
            lines.push(`- \`${f.relPath}\` (${f.bytes} bytes)`);
        }
    }
    return lines.join('\n');
}

/**
 * Deterministically introspect workspace schemas, SQLite DDL/counts, code exports, and doc files.
 *
 * @param {string|null|undefined} workspaceDir
 * @param {object} [options={}]
 */
export function introspectWorkspaceSchemas(workspaceDir, options = {}) {
    const emptyResult = {
        rootName: '', fileCount: 0, totalBytes: 0,
        files: [], docFiles: [], fileDigests: {}, schemaSummaryText: ''
    };
    if (!workspaceDir || typeof workspaceDir !== 'string' || !fs.existsSync(workspaceDir)) {
        return emptyResult;
    }

    const resolvedRoot = path.resolve(workspaceDir);
    let rootStat;
    try { rootStat = fs.statSync(resolvedRoot); } catch { return emptyResult; }
    if (!rootStat.isDirectory()) return emptyResult;

    const maxDepth = options.maxDepth ?? 3;
    const maxFiles = options.maxFiles ?? 60;
    const maxSampleBytes = options.maxSampleBytes ?? 65536;
    const sampleRows = options.sampleRows ?? 3;
    const maxDocBytes = options.maxDocBytes ?? 131072;

    const rootName = path.basename(resolvedRoot);
    const files = [];
    const docFiles = [];
    const fileDigests = {};
    let totalBytes = 0;

    function walk(currentDir, depth) {
        if (depth > maxDepth || files.length >= maxFiles) return;
        let entries;
        try { entries = fs.readdirSync(currentDir, { withFileTypes: true }); } catch { return; }
        entries.sort((a, b) => compareAscii(a.name, b.name));

        for (const entry of entries) {
            if (files.length >= maxFiles) break;
            if (entry.isSymbolicLink()) continue;

            const fullPath = path.join(currentDir, entry.name);
            if (entry.isDirectory()) {
                if (!SKIPPED_DIRS.has(entry.name) && depth < maxDepth) walk(fullPath, depth + 1);
                continue;
            }
            if (!entry.isFile() || isSkippedFile(entry.name)) continue;

            let fileStat;
            try { fileStat = fs.statSync(fullPath); } catch { continue; }

            const relPath = path.relative(resolvedRoot, fullPath).split(path.sep).join('/');
            const ext = path.extname(entry.name).toLowerCase();
            const fileSize = Number(fileStat.size || 0);
            totalBytes += fileSize;

            let headBuffer;
            try {
                headBuffer = readBoundedBuffer(fullPath, Math.min(fileSize, Math.max(maxSampleBytes, maxDocBytes)));
            } catch { continue; }

            const docSlice = headBuffer.subarray(0, Math.min(headBuffer.length, maxDocBytes));
            const sampleSlice = headBuffer.subarray(0, Math.min(headBuffer.length, maxSampleBytes));
            const sha256 = crypto.createHash('sha256').update(docSlice).digest('hex');
            fileDigests[relPath] = sha256;

            if (TABULAR_EXTS.has(ext)) {
                files.push(introspectDelimitedFile(fullPath, relPath, ext, fileSize, sha256, sampleSlice, sampleRows));
            } else if (JSON_EXTS.has(ext)) {
                files.push(introspectJsonFile(fullPath, relPath, ext, fileSize, sha256, sampleSlice));
            } else if (SQLITE_EXTS.has(ext)) {
                files.push(introspectSqliteFile(fullPath, relPath, ext, fileSize, sha256));
            } else if (CODE_EXTS.has(ext)) {
                files.push(introspectCodeFile(relPath, ext, fileSize, sha256, sampleSlice));
            } else if (DOC_EXTS.has(ext)) {
                const docText = docSlice.toString('utf8');
                docFiles.push({ relPath, text: docText, sha256, bytes: fileSize });
                files.push({ relPath, ext, kind: 'doc', bytes: fileSize, sha256, headings: extractDocHeadings(docText) });
            } else {
                files.push({ relPath, ext, kind: 'other', bytes: fileSize, sha256 });
            }
        }
    }

    walk(resolvedRoot, 0);
    return {
        rootName,
        fileCount: files.length,
        totalBytes,
        files,
        docFiles,
        fileDigests,
        schemaSummaryText: buildSchemaSummaryMarkdown(rootName, files, totalBytes)
    };
}

function truncateTextToTokenBudget(text, maxTokens) {
    const clean = String(text || '').trim();
    if (!clean || maxTokens <= 0) return '';
    if (estimateTokenCount(clean) <= maxTokens) return clean;

    const keptLines = [];
    let runningTokens = 0;
    for (const line of clean.split('\n')) {
        const lineTokens = estimateTokenCount(line);
        if (keptLines.length > 0 && runningTokens + lineTokens > maxTokens) break;
        if (keptLines.length === 0 && lineTokens > maxTokens) {
            let partial = '';
            for (const part of line.split(/(\s+)/)) {
                if (estimateTokenCount(partial + part) > maxTokens) break;
                partial += part;
            }
            return partial.trim();
        }
        keptLines.push(line);
        runningTokens += lineTokens;
    }
    return keptLines.join('\n').trim();
}

function normalizeStandingInvariants(standingInvariants) {
    if (!Array.isArray(standingInvariants)) return [];
    const normalized = [];
    for (const item of standingInvariants) {
        if (typeof item === 'string' && item.trim()) {
            normalized.push(item.trim());
        } else if (item && typeof item === 'object') {
            const body = String(item.content ?? item.rule ?? item.text ?? '').trim();
            if (body) normalized.push(`${item.id ? `[${String(item.id).trim()}] ` : ''}${body}`);
        }
    }
    return normalized;
}

function collectDocTurns(docFiles, extraDocs) {
    const turns = [];
    const appendSections = (turnIdBase, speaker, header, body) => {
        const sections = body.split(/\n(?=##\s+)/).map((s) => s.trim()).filter(Boolean);
        if (sections.length > 1) {
            sections.forEach((sec, idx) => {
                turns.push({ turnId: `${turnIdBase}#sec_${idx}`, speaker, content: `${header}${sec}` });
            });
        } else {
            turns.push({ turnId: turnIdBase, speaker, content: `${header}${body}` });
        }
    };

    if (Array.isArray(docFiles)) {
        for (const doc of docFiles) {
            const text = String(doc?.text || '').trim();
            if (!text) continue;
            const relPath = String(doc.relPath || 'doc');
            appendSections(relPath, 'workspace_doc', `[FILE: ${relPath}]\n`, text);
        }
    }

    if (Array.isArray(extraDocs)) {
        for (let i = 0; i < extraDocs.length; i += 1) {
            const entry = extraDocs[i];
            if (typeof entry === 'string' && entry.trim()) {
                appendSections(`extra_doc_${i}`, 'extra_doc', '', entry.trim());
            } else if (entry && typeof entry === 'object') {
                const body = String(entry.text ?? entry.content ?? '').trim();
                if (!body) continue;
                const docId = String(entry.id ?? entry.title ?? `extra_doc_${i}`).trim() || `extra_doc_${i}`;
                const header = entry.title ? `[DOC: ${String(entry.title).trim()}]\n` : '';
                appendSections(docId, 'extra_doc', header, body);
            }
        }
    }
    return turns;
}

/**
 * Compile Turn-0 grounding bundle with deterministic workspace schemas, zero-LLM Raw-RAG doc
 * evidence, deferred BM25 tool gating, scale-aware directives, and KV-cache prefix normalization.
 *
 * @param {object} [options={}]
 */
export async function compileTurnZeroGrounding(options = {}) {
    const {
        goal = '',
        workspaceDir = null,
        standingInvariants = [],
        extraDocs = [],
        tools = [],
        toolConfig = undefined,
        disableAutoToolConfigNone = false,
        pinnedToolNames = [],
        deferThreshold = 12,
        model = '',
        activeParamsB,
        totalParamsB,
        thinkingEnabled,
        thinkingLevel,
        reasoningEffort,
        explicitTier,
        preferThinkingStepForSmallActive = false,
        baseSystemPrompt = 'You are a grounded, low-tool-call autonomous engineering agent.',
        maxGroundingTokens = 3200,
        maxDocEvidenceTokens = 1400,
        topKChunks = 6,
        workspaceOptions = {}
    } = options || {};

    const safeMaxGroundingTokens = Math.max(64, Number(maxGroundingTokens) || 3200);
    const safeMaxDocEvidenceTokens = Math.max(0, Number(maxDocEvidenceTokens ?? 1400));
    const safeTopKChunks = Math.max(1, Math.trunc(Number(topKChunks) || 6));

    const scaleProfile = resolveScaleProfile({
        model, activeParamsB, totalParamsB, thinkingEnabled,
        thinkingLevel, reasoningEffort, explicitTier, preferThinkingStepForSmallActive
    });
    const scaleDirective = buildScaleAwareDirective(scaleProfile);

    const workspace = introspectWorkspaceSchemas(workspaceDir, workspaceOptions);
    const docTurns = collectDocTurns(workspace.docFiles, extraDocs);

    const toolGate = createToolBudgetGate({ tools, pinnedToolNames, deferThreshold });
    const exposedTools = toolGate.exposedTools;
    const toolSavings = toolGate.savings;

    // Static system prompt excludes per-query goal and volatile timestamps to keep prefixHash stable.
    const cleanBasePrompt = String(
        baseSystemPrompt || 'You are a grounded, low-tool-call autonomous engineering agent.'
    ).trim();
    const invariantLines = normalizeStandingInvariants(standingInvariants);
    const staticSections = [cleanBasePrompt, LOW_FORAGING_RULE];

    if (invariantLines.length > 0) {
        staticSections.push(`## Standing Invariants\n${invariantLines.map((line) => `- ${line}`).join('\n')}`);
    }
    if (typeof scaleDirective === 'string' && scaleDirective.trim().length > 0) {
        staticSections.push(scaleDirective.trim());
    }

    const staticSystemCap = docTurns.length > 0
        ? Math.max(48, Math.floor(safeMaxGroundingTokens * 0.6))
        : Math.max(48, Math.floor(safeMaxGroundingTokens * 0.85));
    const nonSchemaTokens = estimateTokenCount(staticSections.join('\n\n'));

    let boundedSchemaSummaryText = '';
    if (workspace.schemaSummaryText) {
        const schemaBudget = Math.max(0, staticSystemCap - nonSchemaTokens - 8);
        boundedSchemaSummaryText = truncateTextToTokenBudget(workspace.schemaSummaryText, schemaBudget);
        if (boundedSchemaSummaryText) {
            staticSections.push(`## Pre-Grounded Workspace Schemas\n${boundedSchemaSummaryText}`);
        }
    }

    const rawCompiledSystemPrompt = truncateTextToTokenBudget(staticSections.join('\n\n'), staticSystemCap);
    const prefixBundle = normalizePromptCachePrefix(
        [{ role: 'system', content: rawCompiledSystemPrompt }],
        { tools: exposedTools, normalizeHeaderTimestamps: true }
    );
    const compiledSystemPrompt = prefixBundle.messages[0]?.content || rawCompiledSystemPrompt;
    const systemTokens = estimateTokenCount(compiledSystemPrompt);

    const cleanGoal = String(goal || '').trim();
    const goalSection = cleanGoal ? `## Task Goal\n${cleanGoal}` : '';
    const goalTokens = goalSection ? estimateTokenCount(goalSection) : 0;
    const availableContextTokens = Math.max(0, safeMaxGroundingTokens - systemTokens);
    const effectiveDocBudget = Math.max(
        0,
        Math.min(safeMaxDocEvidenceTokens, availableContextTokens - goalTokens - 12)
    );

    const retrievedChunks = [];
    if (docTurns.length > 0 && effectiveDocBudget > 0) {
        const rag = createRawRagIndex({
            windowTokens: 256,
            overlapTokens: 32,
            offline: true,
            finalRerankK: safeTopKChunks,
            maxEvidenceTokens: effectiveDocBudget
        });
        await rag.addTurns(docTurns);
        const ragResult = await rag.retrieve(
            cleanGoal || 'workspace overview rules constraints schema',
            { topK: safeTopKChunks, maxEvidenceTokens: effectiveDocBudget, offline: true }
        );

        let usedDocTokens = 0;
        const candidateWindows = Array.isArray(ragResult.selectedWindows) ? ragResult.selectedWindows : [];
        for (let i = 0; i < candidateWindows.length; i += 1) {
            const win = candidateWindows[i];
            const rawChunkText = String(win.text || '').trim();
            if (!rawChunkText) continue;

            const remaining = effectiveDocBudget - usedDocTokens;
            if (remaining <= 0) break;

            let chunkText = rawChunkText;
            let chunkTokens = Number.isFinite(win.tokenCount) && win.tokenCount > 0
                ? win.tokenCount
                : estimateTokenCount(chunkText);

            if (chunkTokens > remaining) {
                if (retrievedChunks.length > 0) break;
                chunkText = truncateTextToTokenBudget(chunkText, remaining);
                if (!chunkText) break;
                chunkTokens = estimateTokenCount(chunkText);
            }

            retrievedChunks.push({
                chunkId: String(win.windowId || win.contentHash?.slice(0, 16) || `chunk_${i}`),
                text: chunkText,
                score: Number(Number(win.rerankScore ?? win.denseScore ?? 0).toFixed(6)),
                tokenCount: chunkTokens
            });
            usedDocTokens += chunkTokens;
        }
    }

    const seenChunkIds = retrievedChunks.map((c) => c.chunkId);
    const contextSections = [];
    if (retrievedChunks.length > 0) {
        contextSections.push(
            `## Workspace Documentation Evidence\n${retrievedChunks.map((c) => `[${c.chunkId}] ${c.text}`).join('\n\n')}`
        );
    }
    if (goalSection) contextSections.push(goalSection);

    let compiledContextBlock = contextSections.length > 0
        ? contextSections.join('\n\n')
        : 'Proceed using the pre-grounded workspace schemas.';

    if (availableContextTokens > 0 && estimateTokenCount(compiledContextBlock) > availableContextTokens) {
        compiledContextBlock = cleanGoal && estimateTokenCount(goalSection) <= availableContextTokens
            ? goalSection
            : truncateTextToTokenBudget(compiledContextBlock, availableContextTokens);
    }

    const contextTokens = estimateTokenCount(compiledContextBlock);
    const totalGroundingTokens = systemTokens + contextTokens;
    const normalizedExposedTools = prefixBundle.tools || exposedTools;
    let geminiToolConfig = null;
    if (toolConfig && typeof toolConfig === 'object') {
        geminiToolConfig = toolConfig;
    } else if (!disableAutoToolConfigNone && (!Array.isArray(normalizedExposedTools) || normalizedExposedTools.length === 0)) {
        geminiToolConfig = { functionCallingConfig: { mode: 'NONE' } };
    }
    const messages = [...prefixBundle.messages, { role: 'user', content: compiledContextBlock }];
    const summary = `Compiled Turn-0 grounding (${scaleProfile.tier}, ${workspace.fileCount} files, ${retrievedChunks.length} doc chunks, ${totalGroundingTokens}/${safeMaxGroundingTokens} tokens, prefix=${prefixBundle.prefixHash.slice(0, 12)})`;

    return okEnvelope('krusch_ground_turn_zero', summary, {
        scaleProfile,
        prefixHash: prefixBundle.prefixHash,
        geminiToolConfig,
        workspace: {
            rootName: workspace.rootName,
            fileCount: workspace.fileCount,
            totalBytes: workspace.totalBytes,
            files: workspace.files,
            schemaSummaryText: boundedSchemaSummaryText
        },
        retrievedChunks,
        seenChunkIds,
        fileDigests: workspace.fileDigests,
        compiledSystemPrompt,
        compiledContextBlock,
        messages,
        exposedTools: normalizedExposedTools,
        toolSavings,
        tokenStats: {
            systemTokens,
            contextTokens,
            totalGroundingTokens,
            maxGroundingTokens: safeMaxGroundingTokens
        },
        llmIngestionCalls: 0
    });
}
