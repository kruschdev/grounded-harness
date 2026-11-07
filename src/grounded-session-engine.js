/**
 * @module grounded-session-engine
 * @description SQLite-backed Grounded Session Engine enforcing Turn-0 delta deduplication,
 * frozen hardline policy floor, secret-leak blocking, duplicate-write prevention,
 * normalized spin-loop blocking & read memoization (`maxReadStreak === 0`),
 * scale-aware `SMALL_MODEL` soft-holds, staged-diff-only verify-on-stop,
 * zero-turn defect-only output gating, Gemini tool-less `mode: 'NONE'` config,
 * and partial `stdout` preservation on timeouts (`INV-GH-03` .. `INV-GH-10`).
 *
 * Pure Node 22 ESM built on `@krusch/toolkit` bricks (`INV-GH-06`, `INV-GH-07`).
 */

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { okEnvelope, errorEnvelope } from '@krusch/toolkit/http';
import {
  createFrozenPolicyFloor,
  evaluateTruncationPoisoningGuard,
  evaluateVerifyOnStopGuard
} from '@krusch/toolkit/harness-engineering';
import {
  SCALE_TIERS,
  resolveScaleProfile,
  buildScaleAwareDirective
} from './scale-policy.js';
import {
  createDeltaContextTracker,
  measureToolSchemaSavings
} from './delta-tool-gate.js';

/**
 * Canonical SQLite DDL for `grounded_sessions` and `grounded_events` (`spec.md` §3.4).
 */
export const GROUNDED_HARNESS_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS grounded_sessions (
  session_id TEXT PRIMARY KEY,
  goal TEXT NOT NULL,
  model TEXT NOT NULL DEFAULT '',
  scale_tier TEXT NOT NULL,
  scale_profile_json TEXT NOT NULL,
  anchor_date TEXT NOT NULL DEFAULT '',
  prefix_hash TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  max_duplicate_writes INTEGER NOT NULL DEFAULT 1,
  seen_chunks_json TEXT NOT NULL DEFAULT '[]',
  file_digests_json TEXT NOT NULL DEFAULT '{}',
  schema_tokens_saved INTEGER NOT NULL DEFAULT 0,
  schema_reduction_pct REAL NOT NULL DEFAULT 0,
  turn0_tokens INTEGER NOT NULL DEFAULT 0,
  exploratory_reads INTEGER NOT NULL DEFAULT 0,
  committed_reads INTEGER NOT NULL DEFAULT 0,
  committed_mutations INTEGER NOT NULL DEFAULT 0,
  memoized_reads INTEGER NOT NULL DEFAULT 0,
  spin_loops_blocked INTEGER NOT NULL DEFAULT 0,
  output_defects_caught INTEGER NOT NULL DEFAULT 0,
  timeouts_with_partial_stdout INTEGER NOT NULL DEFAULT 0,
  turn0_duplicates_suppressed INTEGER NOT NULL DEFAULT 0,
  duplicate_writes_blocked INTEGER NOT NULL DEFAULT 0,
  policy_floor_blocks INTEGER NOT NULL DEFAULT 0,
  truncation_recoveries INTEGER NOT NULL DEFAULT 0,
  verify_nudges_used INTEGER NOT NULL DEFAULT 0,
  pending_diffs_count INTEGER NOT NULL DEFAULT 0,
  latest_verification_passed INTEGER NOT NULL DEFAULT 1,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS grounded_events (
  event_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  step INTEGER NOT NULL DEFAULT 0,
  tool_name TEXT NOT NULL,
  is_mutating INTEGER NOT NULL DEFAULT 0,
  is_foraging INTEGER NOT NULL DEFAULT 0,
  canonical_args_json TEXT NOT NULL,
  call_signature TEXT NOT NULL,
  decision TEXT NOT NULL,
  status TEXT NOT NULL,
  issues_json TEXT NOT NULL DEFAULT '[]',
  result_preview TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_grounded_events_session_step
  ON grounded_events(session_id, step);
`;

const READ_ONLY_EXACT_TOOLS = new Set([
  'tool_search',
  'tool_describe',
  'ls',
  'cat',
  'head',
  'tail',
  'grep',
  'rg',
  'glob',
  'tree',
  'pwd',
  'whoami',
  'status',
  'doctor'
]);

const MUTATING_EXACT_TOOLS = new Set([
  'execute_write',
  'bash',
  'sh',
  'shell',
  'run_command',
  'exec'
]);

const READ_ONLY_VERBS = [
  'describe',
  'inspect',
  'search',
  'lookup',
  'query',
  'check',
  'count',
  'fetch',
  'list',
  'read',
  'view',
  'find',
  'show',
  'stat',
  'ping',
  'get'
];

const MUTATING_VERBS = [
  'reschedule',
  'truncate',
  'schedule',
  'transfer',
  'replace',
  'execute',
  'archive',
  'approve',
  'forward',
  'create',
  'update',
  'delete',
  'remove',
  'insert',
  'commit',
  'deploy',
  'cancel',
  'submit',
  'assign',
  'invite',
  'refund',
  'write',
  'apply',
  'patch',
  'reply',
  'order',
  'edit',
  'send',
  'post',
  'drop',
  'push',
  'book',
  'put',
  'pay',
  'add'
];

const FORAGING_TOOL_NAMES = new Set([
  'ls',
  'find',
  'glob',
  'tree',
  'list_dir',
  'list_files',
  'list_directory',
  'cat',
  'head',
  'tail',
  'read_file',
  'view_file'
]);

const SHELL_TOOL_NAMES = new Set(['bash', 'sh', 'shell', 'run_command', 'exec']);

const SHELL_FORAGING_CMD_RE = /^\s*(?:ls|find|tree|cat|head|tail)\b/;

const OUTBOUND_TOOL_HINT_RE =
  /(?:^|[._:/-])(?:send_|post_|webhook|email|gmail|mail|slack|curl|wget|http|fetch_url)|\b(?:webhook|email|slack|curl|http)\b/i;

const SECRET_LEAK_PATTERNS = [
  { id: 'API_SECRET_KEY', regex: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b/ },
  { id: 'GITHUB_CLASSIC_PAT', regex: /\bghp_[A-Za-z0-9]{20,}\b/ },
  { id: 'GITHUB_FINE_GRAINED_PAT', regex: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/ },
  { id: 'AWS_ACCESS_KEY_ID', regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'PEM_PRIVATE_KEY', regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ }
];

const PLACEHOLDER_TEMPLATE_RE =
  /\bTBD\b|\bTODO\b|<insert[_-\s][^>]+>|\[INSERT[_-\s][^\]]+\]|\{\{[a-zA-Z0-9_.-]+\}\}/i;

const ISO_CALENDAR_DATE_SCAN_RE =
  /(?<![A-Za-z0-9-])(\d{4})-(\d{2})-(\d{2})(?:(?=T\d{2}:)|(?![A-Za-z0-9-]))/g;

const SERIALIZED_TOOL_CALL_RE =
  /<tool_call\b[^>]*>[\s\S]*?<\/tool_call>|<function=[A-Za-z0-9_.-]+>|\[TOOL_CALLS\]|```(?:json|tool_call)\s*\{\s*"(?:name|tool|tool_name)"\s*:/i;

const INLINE_GEMINI_CALL_RE = /\bcall:[A-Za-z_][A-Za-z0-9_.-]*\s*\{/;

const EMPTY_OR_NULL_STRING_RE = /^(?:none|null|nan|\[\s*\]|\{\s*\})$/i;

const RAW_PANDAS_NUMPY_PATTERNS = [
  /\bnp\.(?:float(?:16|32|64)|int(?:8|16|32|64)|uint\d+|bool_|str_)\s*\(/,
  /\bdtype:\s*(?:object|int\d*|float\d*|bool|category|datetime64)\b/i,
  /\[\d+\s+rows\s+x\s+\d+\s+columns\]/i,
  /\bEmpty\s+DataFrame\b[\s\S]{0,80}\bColumns:\s*\[/,
  /^(?:DataFrame\(|Series\(\[|Index\(\[)/m
];

const TRUNCATED_FINISH_REASONS = new Set([
  'max_tokens',
  'length',
  'model_context_window_exceeded',
  'malformed_function_call'
]);

const CODE_SNIPPET_ARG_KEYS = new Set([
  'code',
  'script',
  'python',
  'py',
  'sql',
  'query_sql',
  'command',
  'cmd',
  'CommandLine',
  'commandLine'
]);

const POLICY_ABSTENTION_RE =
  /cannot\b|can't\b|unable to\b|not authorized|unauthorized|permission|policy|approval required|refuse|decline|not applicable|insufficient information/i;

const UNSENT_DRAFT_HEADER_RE = /^\s*(?:\*\*)?(?:Subject|To)(?:\*\*)?:\s+\S+/im;

const OUTBOUND_ACTION_GOAL_RE = /\b(?:send|email|reply|post|create|schedule|update)\b/i;

const DRAFT_ONLY_GOAL_EXEMPT_RE =
  /\b(?:draft\s+only|only\s+draft|do\s+not\s+send|don't\s+send|do\s+not\s+execute|don't\s+execute)\b/i;

const MAX_RESULT_PREVIEW_CHARS = 500;
const MAX_ARG_SCAN_DEPTH = 16;

/**
 * Resolve Gemini `toolConfig`, automatically injecting `{ functionCallingConfig: { mode: 'NONE' } }`
 * when `tools` is omitted or empty (`INV-GH-09`).
 *
 * @param {object} [options={}]
 * @param {Array<object>|object|null} [options.tools]
 * @param {object|null} [options.toolConfig]
 * @param {boolean} [options.disableAutoToolConfigNone=false]
 * @returns {object|null}
 */
export function buildSafeGeminiToolConfig({
  tools,
  toolConfig,
  disableAutoToolConfigNone = false
} = {}) {
  if (toolConfig && typeof toolConfig === 'object' && !Array.isArray(toolConfig)) {
    return toolConfig;
  }
  let hasTools = false;
  if (Array.isArray(tools)) {
    hasTools = tools.length > 0;
  } else if (tools !== null && typeof tools === 'object') {
    hasTools = Object.keys(tools).length > 0;
  }
  if (!hasTools && !disableAutoToolConfigNone) {
    return { functionCallingConfig: { mode: 'NONE' } };
  }
  return null;
}

/**
 * Resolve comment-stripping dialect from an argument/language hint (`INV-GH-04`).
 *
 * @param {string} keyHint
 * @returns {'sql'|'js'|'shell'|'python'}
 */
function resolveSnippetCommentMode(keyHint) {
  const hint = String(keyHint ?? '').trim().toLowerCase();
  if (hint === 'sql' || hint === 'query_sql') {
    return 'sql';
  }
  if (hint === 'js' || hint === 'ts' || hint === 'javascript' || hint === 'typescript') {
    return 'js';
  }
  if (hint === 'command' || hint === 'cmd' || hint === 'commandline' || hint === 'command_line') {
    return 'shell';
  }
  return 'python';
}

/**
 * Quote-safe comment & whitespace normalizer for deterministic spin-loop hashing (`INV-GH-04`).
 * Preserves all characters inside string literals, Python `//` floor division, shell `foo#bar` / `$#`,
 * and leading line indentation.
 *
 * @param {string} [source='']
 * @param {string} [keyHint='']
 * @returns {string}
 */
export function normalizeCodeSnippetForHash(source = '', keyHint = '') {
  if (typeof source !== 'string') {
    source = String(source ?? '');
  }
  if (!source) {
    return '';
  }

  const input = source.replace(/\r\n?/g, '\n');
  const mode = resolveSnippetCommentMode(keyHint);
  const len = input.length;
  let out = '';
  /** @type {string|null} */
  let quote = null;
  let i = 0;

  while (i < len) {
    const ch = input[i];

    if (quote !== null) {
      if (ch === '\\' && i + 1 < len) {
        out += ch + input[i + 1];
        i += 2;
        continue;
      }
      if (quote.length === 3) {
        if (input.slice(i, i + 3) === quote) {
          out += quote;
          quote = null;
          i += 3;
          continue;
        }
        out += ch;
        i += 1;
        continue;
      }
      if (ch === quote) {
        out += ch;
        quote = null;
        i += 1;
        continue;
      }
      out += ch;
      i += 1;
      continue;
    }

    // Outside string literals: handle backslash-escaped characters (e.g. shell `\#` or `\'`)
    if (ch === '\\' && i + 1 < len && input[i + 1] !== '\n') {
      out += ch + input[i + 1];
      i += 2;
      continue;
    }

    // Check block comments (`/* ... */`) strictly in SQL and JS/TS modes (never Python `/ *args` or shell globs)
    if ((mode === 'js' || mode === 'sql') && ch === '/' && input[i + 1] === '*') {
      const closeIdx = input.indexOf('*/', i + 2);
      if (closeIdx === -1) {
        break;
      }
      // Preserve newline separation if a block comment spanned multiple lines
      const skipped = input.slice(i + 2, closeIdx);
      let nextIdx = closeIdx + 2;
      if (skipped.includes('\n')) {
        out += '\n';
      } else if (
        out.length === 0
        || out.endsWith('\n')
        || out.endsWith(' ')
        || out.endsWith('\t')
      ) {
        while (nextIdx < len && (input[nextIdx] === ' ' || input[nextIdx] === '\t')) {
          nextIdx += 1;
        }
      }
      i = nextIdx;
      continue;
    }

    // SQL `-- ...` line comments
    if (mode === 'sql' && ch === '-' && input[i + 1] === '-') {
      const nlIdx = input.indexOf('\n', i + 2);
      if (nlIdx === -1) {
        break;
      }
      i = nlIdx;
      continue;
    }

    // JS/TS `// ...` line comments (NEVER active in Python mode where `//` is floor division!)
    if (mode === 'js' && ch === '/' && input[i + 1] === '/') {
      const nlIdx = input.indexOf('\n', i + 2);
      if (nlIdx === -1) {
        break;
      }
      i = nlIdx;
      continue;
    }

    // Python `# ...` line comments
    if (mode === 'python' && ch === '#') {
      const nlIdx = input.indexOf('\n', i + 1);
      if (nlIdx === -1) {
        break;
      }
      i = nlIdx;
      continue;
    }

    // Shell `# ...` line comments ONLY at start-of-line or preceded by whitespace
    if (mode === 'shell' && ch === '#') {
      const prev = i === 0 ? '\n' : input[i - 1];
      if (prev === '\n' || prev === ' ' || prev === '\t') {
        const nlIdx = input.indexOf('\n', i + 1);
        if (nlIdx === -1) {
          break;
        }
        i = nlIdx;
        continue;
      }
    }

    // Enter triple-quoted literals in Python/default mode
    if (mode === 'python' && (ch === '\'' || ch === '"')) {
      const triple = ch + ch + ch;
      if (input.slice(i, i + 3) === triple) {
        quote = triple;
        out += triple;
        i += 3;
        continue;
      }
    }

    // Enter single, double, or backtick quoted literals
    if (ch === '\'' || ch === '"' || ch === '`') {
      quote = ch;
      out += ch;
      i += 1;
      continue;
    }

    out += ch;
    i += 1;
  }

  return out
    .split('\n')
    .map((line) => line.replace(/[ \t]+$/g, ''))
    .filter((line) => line.trim().length > 0)
    .join('\n');
}

function extractBalancedBraceSlice(text, openBraceIdx) {
  if (openBraceIdx < 0 || text[openBraceIdx] !== '{') {
    return null;
  }
  let depth = 0;
  let quote = null;
  for (let i = openBraceIdx; i < text.length; i += 1) {
    const ch = text[i];
    if (quote !== null) {
      if (ch === '\\' && i + 1 < text.length) {
        i += 1;
        continue;
      }
      if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === '\'') {
      quote = ch;
      continue;
    }
    if (ch === '{') {
      depth += 1;
    } else if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        return { slice: text.slice(openBraceIdx, i + 1), endIdx: i + 1 };
      }
    }
  }
  return null;
}

function parseLooseToolObject(rawText) {
  const trimmed = String(rawText ?? '').trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    try {
      const quotedKeys = trimmed.replace(
        /([{,]\s*)([A-Za-z_][A-Za-z0-9_.-]*)(\s*:)/g,
        '$1"$2"$3'
      );
      return JSON.parse(quotedKeys);
    } catch {
      return null;
    }
  }
}

function normalizeRescuedCallRecord(candidate) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return null;
  }
  const name = String(candidate.name ?? candidate.tool ?? candidate.tool_name ?? '').trim();
  if (!name) return null;
  const rawArgs = candidate.args ?? candidate.arguments ?? candidate.parameters ?? {};
  const parsedArgs =
    typeof rawArgs === 'string'
      ? (parseLooseToolObject(rawArgs) ?? { _raw: rawArgs })
      : rawArgs && typeof rawArgs === 'object'
        ? rawArgs
        : {};
  return { name, args: parsedArgs };
}

function extractSerializedToolCallsFromText(text) {
  const rescued = [];
  if (!text) return rescued;

  // 1. `<tool_call>...</tool_call>` blocks
  for (const match of text.matchAll(/<tool_call\b[^>]*>([\s\S]*?)<\/tool_call>/gi)) {
    const parsed = parseLooseToolObject(match[1]);
    const rec = normalizeRescuedCallRecord(parsed);
    if (rec) rescued.push(rec);
  }

  // 2. Fenced ```json / ```tool_call blocks
  for (const match of text.matchAll(/```(?:json|tool_call)\s*([\s\S]*?)```/gi)) {
    const parsed = parseLooseToolObject(match[1]);
    const rec = normalizeRescuedCallRecord(parsed);
    if (rec) rescued.push(rec);
  }

  // 3. `<function=tool_name>{...}</function>` or `<function=tool_name>`
  for (const match of text.matchAll(/<function=([A-Za-z0-9_.-]+)>([\s\S]*?)(?:<\/function>|$)/gi)) {
    const fnName = String(match[1] ?? '').trim();
    if (!fnName) continue;
    const body = String(match[2] ?? '').trim();
    let parsedArgs = {};
    if (body.startsWith('{')) {
      const brace = extractBalancedBraceSlice(body, 0);
      parsedArgs = parseLooseToolObject(brace ? brace.slice : body) ?? {};
    }
    rescued.push({ name: fnName, args: parsedArgs });
  }

  // 4. Gemini-style `call:tool_name{...}`
  const callRegex = /\bcall:([A-Za-z_][A-Za-z0-9_.-]*)\s*\{/g;
  let callMatch;
  while ((callMatch = callRegex.exec(text)) !== null) {
    const fnName = callMatch[1];
    const openBraceIdx = callMatch.index + callMatch[0].length - 1;
    const balanced = extractBalancedBraceSlice(text, openBraceIdx);
    const parsedArgs = balanced
      ? (parseLooseToolObject(balanced.slice) ?? {})
      : {};
    rescued.push({ name: fnName, args: parsedArgs });
    if (balanced) {
      callRegex.lastIndex = balanced.endIdx;
    }
  }

  // 5. `[TOOL_CALLS]` JSON array or object payload
  const tcIdx = text.indexOf('[TOOL_CALLS]');
  if (tcIdx !== -1 && rescued.length === 0) {
    const after = text.slice(tcIdx + '[TOOL_CALLS]'.length).trim();
    const parsed = parseLooseToolObject(after);
    if (Array.isArray(parsed)) {
      for (const item of parsed) {
        const rec = normalizeRescuedCallRecord(item);
        if (rec) rescued.push(rec);
      }
    } else {
      const rec = normalizeRescuedCallRecord(parsed);
      if (rec) rescued.push(rec);
    }
  }

  return rescued;
}

function hasRawPandasOrNumpyRepr(str) {
  if (!str) return false;
  for (const re of RAW_PANDAS_NUMPY_PATTERNS) {
    if (re.test(str)) {
      return true;
    }
  }
  return false;
}

/**
 * Zero-turn *defect-only* output gate (`INV-GH-05`).
 * Passes healthy outputs in `0` extra turns (`0` false positives on `"0"`, `0`, `false`,
 * `"Not Applicable"`, `"N/A"`, or code blocks) while catching objective bailouts/truncations/leaks.
 *
 * @param {object} [input={}]
 * @returns {{
 *   hasDefect: boolean,
 *   defects: Array<{ code: string, message: string }>,
 *   primaryDefect: { code: string, message: string } | null,
 *   correctivePrompt: string | null,
 *   rescuedToolCalls: Array<{ name: string, args: object }>
 * }}
 */
export function inspectOutputDefects(input = {}) {
  const safe = input && typeof input === 'object' ? input : {};
  if (safe.enableOutputDefectGate === false || safe.enable_output_defect_gate === false) {
    return {
      hasDefect: false,
      defects: [],
      primaryDefect: null,
      correctivePrompt: null,
      rescuedToolCalls: []
    };
  }
  const candidateAnswer = Object.prototype.hasOwnProperty.call(safe, 'candidateAnswer')
    ? safe.candidateAnswer
    : safe.candidate_answer;
  const rawAssistant = safe.assistantText ?? safe.assistant_text ?? '';
  const text = typeof rawAssistant === 'string' ? rawAssistant : String(rawAssistant ?? '');
  const finishReason = safe.finishReason ?? safe.finish_reason ?? null;
  const stopReason = safe.stopReason ?? safe.stop_reason ?? null;
  const rawTruncatedCalls = safe.truncatedToolCalls ?? safe.truncated_tool_calls ?? false;
  const rawToolCalls = safe.toolCalls ?? safe.tool_calls;
  const effectiveToolCalls = Array.isArray(rawToolCalls) ? rawToolCalls : [];
  const expectNonEmptyAnswer = Boolean(
    safe.expectNonEmptyAnswer ?? safe.expect_non_empty_answer ?? false
  );

  /** @type {Array<{ code: string, message: string }>} */
  const defects = [];
  /** @type {Array<{ name: string, args: object }>} */
  let rescuedToolCalls = [];

  // 1. TRUNCATED_OUTPUT
  const normFinish = typeof finishReason === 'string' ? finishReason.trim().toLowerCase() : '';
  const normStop = typeof stopReason === 'string' ? stopReason.trim().toLowerCase() : '';
  const hasExplicitTruncatedFlag =
    rawTruncatedCalls === true
    || (Array.isArray(rawTruncatedCalls) && rawTruncatedCalls.length > 0);
  const truncGuard = evaluateTruncationPoisoningGuard({
    finishReason,
    stopReason,
    toolCalls: effectiveToolCalls,
    truncatedToolCalls: Array.isArray(rawTruncatedCalls) ? rawTruncatedCalls : []
  });

  if (
    truncGuard.poisoned === true
    || hasExplicitTruncatedFlag
    || TRUNCATED_FINISH_REASONS.has(normFinish)
    || TRUNCATED_FINISH_REASONS.has(normStop)
  ) {
    const reasonTag = String(finishReason || stopReason || truncGuard.reason || 'TRUNCATED').toUpperCase();
    defects.push({
      code: 'TRUNCATED_OUTPUT',
      message: `Model response terminated with truncation/malformed state (${reasonTag}).`
    });
  }

  // 2. SERIALIZED_TOOL_CALL_IN_TEXT
  if (
    effectiveToolCalls.length === 0
    && (SERIALIZED_TOOL_CALL_RE.test(text) || INLINE_GEMINI_CALL_RE.test(text))
  ) {
    rescuedToolCalls = extractSerializedToolCallsFromText(text);
    defects.push({
      code: 'SERIALIZED_TOOL_CALL_IN_TEXT',
      message: 'Assistant emitted a serialized tool call in plain text instead of invoking the structured tool API.'
    });
  }

  // 3. EMPTY_OR_NULL_BAILOUT
  if (expectNonEmptyAnswer === true || candidateAnswer !== undefined) {
    const val = candidateAnswer !== undefined ? candidateAnswer : text;
    let isBailout = false;
    if (val === null || val === undefined) {
      isBailout = true;
    } else if (typeof val === 'number' && Number.isNaN(val)) {
      isBailout = true;
    } else if (Array.isArray(val) && val.length === 0) {
      isBailout = true;
    } else if (
      typeof val === 'object'
      && !Array.isArray(val)
      && Object.keys(val).length === 0
    ) {
      isBailout = true;
    } else if (typeof val === 'string') {
      const trimmed = val.trim();
      if (trimmed === '' || EMPTY_OR_NULL_STRING_RE.test(trimmed)) {
        isBailout = true;
      }
    }

    if (isBailout) {
      defects.push({
        code: 'EMPTY_OR_NULL_BAILOUT',
        message: 'Output is an empty, null, None, NaN, [], or {} bailout instead of a grounded answer.'
      });
    }
  }

  // 4. RAW_DATAFRAME_OR_NUMPY_REPR
  const candidateStr =
    candidateAnswer !== undefined && candidateAnswer !== null
      ? (typeof candidateAnswer === 'string'
        ? candidateAnswer
        : String(candidateAnswer))
      : '';
  const candidateJsonStr =
    candidateAnswer !== undefined && candidateAnswer !== null && typeof candidateAnswer === 'object'
      ? (JSON.stringify(candidateAnswer) || '')
      : '';
  const strippedProseText = text
    .replace(/```[\s\S]*?```/g, '\n')
    .replace(/`[^`]*`/g, ' ');

  if (
    hasRawPandasOrNumpyRepr(candidateStr)
    || hasRawPandasOrNumpyRepr(candidateJsonStr)
    || hasRawPandasOrNumpyRepr(strippedProseText)
  ) {
    defects.push({
      code: 'RAW_DATAFRAME_OR_NUMPY_REPR',
      message: 'Output leaked unformatted Python pandas DataFrame/Series or numpy scalar repr (e.g. np.float64(...)).'
    });
  }

  if (defects.length === 0) {
    return {
      hasDefect: false,
      defects: [],
      primaryDefect: null,
      correctivePrompt: null,
      rescuedToolCalls: []
    };
  }

  const primaryDefect = defects[0];
  let correctivePrompt;
  switch (primaryDefect.code) {
    case 'SERIALIZED_TOOL_CALL_IN_TEXT':
      correctivePrompt =
        'You emitted a serialized tool call in plain text instead of invoking the structured tool API. Invoke the tool directly now, or provide your final answer if no tool call is needed.';
      break;
    case 'TRUNCATED_OUTPUT':
      correctivePrompt =
        'Your previous response was cut off or terminated with a malformed function call. Emit a concise, complete response or smaller well-formed tool arguments.';
      break;
    case 'RAW_DATAFRAME_OR_NUMPY_REPR':
      correctivePrompt =
        'Your answer contains raw pandas DataFrame/Series or numpy scalar reprs (such as np.float64(...)). Convert values to native scalars/strings with exact required formatting and restate the final answer.';
      break;
    case 'EMPTY_OR_NULL_BAILOUT':
    default:
      correctivePrompt =
        'Your answer resolved to an empty/null/None/NaN bailout. Compute and return the concrete grounded answer (or state explicitly if Not Applicable).';
      break;
  }

  return {
    hasDefect: true,
    defects,
    primaryDefect,
    correctivePrompt,
    rescuedToolCalls
  };
}

function truncateHeadTailChars(rawText, maxChars = 8000) {
  const str = typeof rawText === 'string' ? rawText : String(rawText ?? '');
  const limit =
    Number.isFinite(Number(maxChars)) && Number(maxChars) > 0
      ? Math.trunc(Number(maxChars))
      : 8000;
  if (str.length <= limit) {
    return str;
  }
  const marker = '\n...[truncated]...\n';
  if (limit <= marker.length + 2) {
    return str.slice(0, limit);
  }
  const budget = limit - marker.length;
  const headLen = Math.ceil(budget / 2);
  const tailLen = budget - headLen;
  return `${str.slice(0, headLen)}${marker}${str.slice(str.length - tailLen)}`;
}

/**
 * Format a subprocess/sandbox timeout while preserving partial `stdout` emitted prior to timeout
 * and clearing any stale `finalAnswer` (`INV-GH-10`).
 *
 * @param {object} [options={}]
 * @returns {{
 *   ok: false,
 *   timedOut: true,
 *   stdout: string,
 *   stderr: string,
 *   hasFinalAnswer: false,
 *   finalAnswer: null,
 *   error: string,
 *   formattedObservation: string
 * }}
 */
export function formatTimeoutWithPartialStdout({
  timeoutMs,
  timeoutSeconds,
  stdout = '',
  stderr = '',
  maxStdoutChars = 8000,
  label = 'Sandbox execution'
} = {}) {
  const resolvedSeconds =
    timeoutSeconds ?? (timeoutMs ? Number((timeoutMs / 1000).toFixed(2)) : 15);
  const boundedStdout = truncateHeadTailChars(stdout, maxStdoutChars);
  const boundedStderr = truncateHeadTailChars(stderr, maxStdoutChars);
  const cleanLabel = String(label || 'Sandbox execution');
  const error = `TimeoutError: ${cleanLabel} exceeded ${resolvedSeconds}s time limit.`;

  const parts = ['[PARTIAL STDOUT BEFORE TIMEOUT]'];
  if (boundedStdout.length > 0) {
    parts.push(boundedStdout.replace(/\n+$/g, ''));
  } else {
    parts.push('(no stdout emitted before timeout)');
  }
  if (boundedStderr.trim().length > 0) {
    parts.push('[PARTIAL STDERR BEFORE TIMEOUT]', boundedStderr.replace(/\n+$/g, ''));
  }
  parts.push(error);

  return {
    ok: false,
    timedOut: true,
    stdout: boundedStdout,
    stderr: boundedStderr,
    hasFinalAnswer: false,
    finalAnswer: null,
    error,
    formattedObservation: parts.join('\n')
  };
}

function appendBoundedStreamText(current, chunkStr, maxBytes) {
  const next = current + chunkStr;
  if (Buffer.byteLength(next, 'utf8') <= maxBytes) {
    return next;
  }
  // Preserve both head and latest tail within maxBytes character approximation
  const maxChars = Math.max(64, maxBytes);
  if (next.length <= maxChars) {
    return next;
  }
  const half = Math.floor(maxChars / 2);
  return `${next.slice(0, half)}\n${next.slice(next.length - half)}`;
}

/**
 * Execute a subprocess (`shell: false` by default) while streaming and preserving partial `stdout`
 * if `timeoutMs` expires before process exit (`INV-GH-06`, `INV-GH-10`).
 *
 * @param {string} command
 * @param {string[]} [args=[]]
 * @param {object} [options={}]
 * @returns {Promise<object>}
 */
export async function execCommandWithPartialStdout(command, args = [], options = {}) {
  const safeOpts = options && typeof options === 'object' ? options : {};
  const safeArgs = Array.isArray(args) ? args.map((a) => String(a)) : [];
  const timeoutMs =
    Number.isFinite(Number(safeOpts.timeoutMs)) && Number(safeOpts.timeoutMs) > 0
      ? Number(safeOpts.timeoutMs)
      : 15000;
  const maxOutputBytes =
    Number.isFinite(Number(safeOpts.maxOutputBytes)) && Number(safeOpts.maxOutputBytes) > 0
      ? Math.trunc(Number(safeOpts.maxOutputBytes))
      : 262144;
  const maxStdoutChars =
    Number.isFinite(Number(safeOpts.maxStdoutChars)) && Number(safeOpts.maxStdoutChars) > 0
      ? Math.trunc(Number(safeOpts.maxStdoutChars))
      : 8000;
  const label = safeOpts.label || String(command || 'Subprocess');

  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let didTimeout = false;
    let settled = false;
    let timeoutTimer = null;
    let killTimer = null;
    let settleTimer = null;

    const clearAllTimers = () => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (killTimer) clearTimeout(killTimer);
      if (settleTimer) clearTimeout(settleTimer);
      timeoutTimer = null;
      killTimer = null;
      settleTimer = null;
    };

    const finalize = (payload) => {
      if (settled) return;
      settled = true;
      clearAllTimers();
      resolve(payload);
    };

    let child;
    try {
      child = spawn(String(command), safeArgs, {
        shell: safeOpts.shell === true,
        cwd: safeOpts.cwd,
        env: safeOpts.env,
        stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch (spawnErr) {
      const msg = spawnErr instanceof Error ? spawnErr.message : String(spawnErr);
      finalize({
        ok: false,
        timedOut: false,
        exitCode: null,
        stdout: '',
        stderr: msg,
        hasFinalAnswer: false,
        finalAnswer: null,
        error: msg,
        formattedObservation: msg
      });
      return;
    }

    if (child.stdout) {
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (chunk) => {
        stdout = appendBoundedStreamText(stdout, String(chunk), maxOutputBytes);
      });
    }

    if (child.stderr) {
      child.stderr.setEncoding('utf8');
      child.stderr.on('data', (chunk) => {
        stderr = appendBoundedStreamText(stderr, String(chunk), maxOutputBytes);
      });
    }

    const resolveTimeoutOutcome = () => {
      const formatted = formatTimeoutWithPartialStdout({
        timeoutMs,
        timeoutSeconds: safeOpts.timeoutSeconds,
        stdout,
        stderr,
        maxStdoutChars,
        label
      });
      finalize({
        ...formatted,
        exitCode: null
      });
    };

    timeoutTimer = setTimeout(() => {
      didTimeout = true;
      try {
        child.kill('SIGTERM');
      } catch {
        // Process already exited.
      }
      killTimer = setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {
          // Process already exited.
        }
        try {
          child.stdout?.destroy();
          child.stderr?.destroy();
        } catch {
          // Ignore stream destroy errors.
        }
        settleTimer = setTimeout(resolveTimeoutOutcome, 50);
      }, 100);
    }, timeoutMs);

    child.on('error', (err) => {
      if (didTimeout) {
        resolveTimeoutOutcome();
        return;
      }
      const msg = err instanceof Error ? err.message : String(err);
      finalize({
        ok: false,
        timedOut: false,
        exitCode: null,
        stdout,
        stderr: stderr || msg,
        hasFinalAnswer: false,
        finalAnswer: null,
        error: msg,
        formattedObservation: stdout || stderr || msg
      });
    });

    child.on('close', (code) => {
      if (didTimeout) {
        resolveTimeoutOutcome();
        return;
      }
      finalize({
        ok: code === 0,
        timedOut: false,
        exitCode: code,
        stdout,
        stderr,
        hasFinalAnswer: false,
        finalAnswer: null,
        error: code === 0 ? null : `Exited with code ${code}`,
        formattedObservation: stdout || stderr || ''
      });
    });
  });
}

/**
 * Strip optional MCP or namespace prefixes (`mcp__srv__tool`, `ns.tool`, `ns:tool`, `ns/tool`).
 *
 * @param {string} toolName
 * @returns {string}
 */
function stripToolNamespace(toolName) {
  let base = String(toolName || '').trim();
  if (!base) return '';
  base = base.replace(/^mcp__(?:[^_]|_(?!_))+__/i, '');
  base = base.replace(/^(?:[A-Za-z0-9_-]+[.:/])+/, '');
  return base;
}

/**
 * Check whether `segment` starts with one of `verbs` at a clean `_`, `-`, camelCase, or exact boundary.
 *
 * @param {string} segment
 * @param {string[]} verbs
 * @returns {boolean}
 */
function matchesVerbPrefix(segment, verbs) {
  if (!segment) return false;
  const lower = segment.toLowerCase();
  for (const verb of verbs) {
    if (!lower.startsWith(verb)) continue;
    if (segment.length === verb.length) return true;
    const nextChar = segment[verb.length];
    if (nextChar === '_' || nextChar === '-') return true;
    const prevChar = segment[verb.length - 1];
    const isPrevLower = prevChar >= 'a' && prevChar <= 'z';
    const isNextUpper = nextChar >= 'A' && nextChar <= 'Z';
    if (isPrevLower && isNextUpper) return true;
  }
  return false;
}

/**
 * Classify whether a tool invocation is mutating (`true`) or read-only (`false`).
 * Explicit boolean override takes highest precedence; unknown tools default conservatively to `false`.
 *
 * @param {string} toolName - Tool identifier.
 * @param {boolean} [explicitMutating] - Optional caller-supplied mutability override.
 * @returns {boolean}
 */
export function classifyToolMutability(toolName, explicitMutating) {
  if (typeof explicitMutating === 'boolean') {
    return explicitMutating;
  }

  const baseName = stripToolNamespace(toolName);
  if (!baseName) {
    return false;
  }

  const lowerBase = baseName.toLowerCase();
  if (READ_ONLY_EXACT_TOOLS.has(lowerBase)) {
    return false;
  }
  if (MUTATING_EXACT_TOOLS.has(lowerBase)) {
    return true;
  }

  if (matchesVerbPrefix(baseName, READ_ONLY_VERBS)) {
    return false;
  }
  if (matchesVerbPrefix(baseName, MUTATING_VERBS)) {
    return true;
  }

  // Handle noun-prefixed tool names (e.g., `gmail_send_message`, `fs_read_page`).
  const parts = baseName.split(/[_-]+/).filter(Boolean);
  for (let i = 1; i < parts.length; i += 1) {
    const token = parts[i];
    const lowerToken = token.toLowerCase();
    if (READ_ONLY_EXACT_TOOLS.has(lowerToken) || matchesVerbPrefix(token, READ_ONLY_VERBS)) {
      return false;
    }
    if (MUTATING_EXACT_TOOLS.has(lowerToken) || matchesVerbPrefix(token, MUTATING_VERBS)) {
      return true;
    }
  }

  return false;
}

/**
 * Identify whether a non-mutating tool call represents exploratory workspace discovery ("foraging").
 *
 * @param {string} toolName
 * @param {object} [args={}]
 * @returns {boolean}
 */
function isForagingTool(toolName, args = {}) {
  const baseName = stripToolNamespace(toolName).toLowerCase();
  if (!baseName) {
    return false;
  }
  if (FORAGING_TOOL_NAMES.has(baseName)) {
    return true;
  }
  if (SHELL_TOOL_NAMES.has(baseName) && args && typeof args === 'object') {
    const cmd = String(
      args.command ?? args.cmd ?? args.CommandLine ?? args.commandLine ?? ''
    );
    if (SHELL_FORAGING_CMD_RE.test(cmd)) {
      return true;
    }
  }
  return false;
}

/**
 * Normalize raw tool arguments (object, JSON string, or nullish) prior to canonical serialization.
 *
 * @param {unknown} args
 * @returns {unknown}
 */
function normalizeRawArgs(args) {
  if (args === undefined || args === null) {
    return {};
  }
  if (typeof args === 'string') {
    const trimmed = args.trim();
    if (!trimmed) return {};
    if (
      (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
      (trimmed.startsWith('[') && trimmed.endsWith(']'))
    ) {
      try {
        return JSON.parse(trimmed);
      } catch {
        return { _raw: args };
      }
    }
    return { _raw: args };
  }
  return args;
}

/**
 * Recursively sort object keys and normalize code/SQL/shell snippet keys so semantically
 * equivalent tool calls produce identical canonical JSON (`INV-GH-04`).
 *
 * @param {unknown} value
 * @param {WeakSet<object>} [seen]
 * @returns {unknown}
 */
function canonicalizeJsonValue(value, seen = new WeakSet()) {
  if (value === null || value === undefined) {
    return value === undefined ? undefined : null;
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      return null;
    }
    return value;
  }
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value.toISOString();
  }
  if (seen.has(value)) {
    return '[Circular]';
  }
  seen.add(value);

  if (Array.isArray(value)) {
    const arr = value.map((item) => {
      if (item === undefined || typeof item === 'function' || typeof item === 'symbol') {
        return null;
      }
      const next = canonicalizeJsonValue(item, seen);
      return next === undefined ? null : next;
    });
    seen.delete(value);
    return arr;
  }

  const sortedKeys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const out = {};
  for (const key of sortedKeys) {
    const propVal = value[key];
    if (propVal === undefined || typeof propVal === 'function' || typeof propVal === 'symbol') {
      continue;
    }
    if (typeof propVal === 'string' && CODE_SNIPPET_ARG_KEYS.has(key)) {
      out[key] = normalizeCodeSnippetForHash(propVal, key);
      continue;
    }
    const canonicalProp = canonicalizeJsonValue(propVal, seen);
    if (canonicalProp !== undefined) {
      out[key] = canonicalProp;
    }
  }
  seen.delete(value);
  return out;
}

/**
 * Canonicalize tool arguments with deterministic key sorting, comment/whitespace code normalization,
 * and compute a 64-char SHA-256 signature (`INV-GH-04`).
 *
 * @param {string} toolName - Tool identifier.
 * @param {object} [args={}] - Tool call arguments.
 * @returns {{ canonicalArgsJson: string, callSignature: string }}
 */
export function canonicalizeToolCallKey(toolName, args = {}) {
  const normalizedTool = String(toolName || '').trim();
  const canonicalArgs = canonicalizeJsonValue(normalizeRawArgs(args));
  const serialized = JSON.stringify(canonicalArgs === undefined ? {} : canonicalArgs);
  const canonicalArgsJson = typeof serialized === 'string' ? serialized : '{}';
  const callSignature = crypto
    .createHash('sha256')
    .update(`${normalizedTool}\n${canonicalArgsJson}`)
    .digest('hex');

  return { canonicalArgsJson, callSignature };
}

function normalizeNonNegativeInt(raw, fallback) {
  if (raw === undefined || raw === null || raw === '') return fallback;
  const num = Number(raw);
  if (!Number.isFinite(num) || num < 0) return fallback;
  return Math.trunc(num);
}

function safeParseJsonArray(rawJson) {
  if (typeof rawJson !== 'string' || !rawJson.trim()) return [];
  try {
    const parsed = JSON.parse(rawJson);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function safeParseJsonObject(rawJson) {
  if (typeof rawJson !== 'string' || !rawJson.trim()) return {};
  try {
    const parsed = JSON.parse(rawJson);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function extractChunkId(chunk) {
  if (typeof chunk === 'string') {
    return chunk;
  }
  if (!chunk || typeof chunk !== 'object') {
    return '';
  }
  return String(
    chunk.chunkId
      ?? chunk.windowId
      ?? chunk.entryId
      ?? chunk.id
      ?? chunk.contentHash
      ?? chunk.chunk_id
      ?? ''
  );
}

function walkStringValues(node, visitor, pathPrefix = '', depth = 0, seen = new WeakSet()) {
  if (depth > MAX_ARG_SCAN_DEPTH || node === null || node === undefined) {
    return;
  }
  if (typeof node === 'string') {
    visitor(pathPrefix || 'args', node);
    return;
  }
  if (typeof node !== 'object' || seen.has(node)) {
    return;
  }
  seen.add(node);

  if (Array.isArray(node)) {
    for (let idx = 0; idx < node.length; idx += 1) {
      const nextPath = pathPrefix ? `${pathPrefix}[${idx}]` : `[${idx}]`;
      walkStringValues(node[idx], visitor, nextPath, depth + 1, seen);
    }
    seen.delete(node);
    return;
  }

  for (const key of Object.keys(node)) {
    const nextPath = pathPrefix ? `${pathPrefix}.${key}` : key;
    walkStringValues(node[key], visitor, nextPath, depth + 1, seen);
  }
  seen.delete(node);
}

function daysInCalendarMonth(year, month) {
  if (month === 2) {
    const isLeap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    return isLeap ? 29 : 28;
  }
  if (month === 4 || month === 6 || month === 9 || month === 11) {
    return 30;
  }
  return 31;
}

function findInvalidCalendarDates(text) {
  const invalid = [];
  for (const match of text.matchAll(ISO_CALENDAR_DATE_SCAN_RE)) {
    const rawDate = match[0];
    const year = Number.parseInt(match[1], 10);
    const month = Number.parseInt(match[2], 10);
    const day = Number.parseInt(match[3], 10);

    if (month < 1 || month > 12) {
      invalid.push({
        value: rawDate,
        message: `Impossible ISO calendar month "${match[2]}" in "${rawDate}" (must be 01..12).`
      });
      continue;
    }

    const maxDay = daysInCalendarMonth(year, month);
    if (day < 1 || day > maxDay) {
      invalid.push({
        value: rawDate,
        message: `Impossible ISO calendar date "${rawDate}" (${match[1]}-${match[2]} has valid days 01..${String(maxDay).padStart(2, '0')}).`
      });
    }
  }
  return invalid;
}

function scanSmallModelArgumentIssues(args) {
  const issues = [];
  walkStringValues(args, (field, strVal) => {
    const placeholderMatch = strVal.match(PLACEHOLDER_TEMPLATE_RE);
    if (placeholderMatch) {
      issues.push({
        field,
        code: 'UNRESOLVED_PLACEHOLDER',
        value: placeholderMatch[0],
        message: `Field "${field}" contains unresolved template placeholder "${placeholderMatch[0]}".`
      });
    }

    const badDates = findInvalidCalendarDates(strVal);
    for (const bad of badDates) {
      issues.push({
        field,
        code: 'INVALID_CALENDAR_DATE',
        value: bad.value,
        message: `Field "${field}": ${bad.message}`
      });
    }
  });
  return issues;
}

function scanArgsForSecretLeak(canonicalArgsJson, args) {
  for (const rule of SECRET_LEAK_PATTERNS) {
    if (rule.regex.test(canonicalArgsJson)) {
      return rule.id;
    }
  }
  let matchedRuleId = null;
  walkStringValues(args, (_field, strVal) => {
    if (matchedRuleId) return;
    for (const rule of SECRET_LEAK_PATTERNS) {
      if (rule.regex.test(strVal)) {
        matchedRuleId = rule.id;
        return;
      }
    }
  });
  return matchedRuleId;
}

function buildPolicyFloorArgs(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    return args;
  }
  if (args.path === undefined) {
    const altPath = args.file_path ?? args.relPath ?? args.rel_path ?? args.target_path;
    if (typeof altPath === 'string' && altPath.length > 0) {
      return { ...args, path: altPath };
    }
  }
  return args;
}

function assertValidDbHandle(db) {
  if (
    !db
    || typeof db !== 'object'
    || typeof db.exec !== 'function'
    || typeof db.run !== 'function'
    || typeof db.query !== 'function'
    || typeof db.queryOne !== 'function'
    || typeof db.transaction !== 'function'
  ) {
    throw new TypeError(
      'createGroundedSessionEngine requires a valid SqliteDbHandle (openSqliteDb) with exec, run, query, queryOne, and transaction methods'
    );
  }
}

/**
 * Create a SQLite-backed Grounded Session Engine (`INV-GH-03` .. `INV-GH-10`).
 *
 * @param {object} [options={}]
 * @param {object} options.db - `SqliteDbHandle` from `openSqliteDb` (`@krusch/toolkit/sqlite`).
 * @param {string[]} [options.protectedPaths=[]] - Additional protected paths for `createFrozenPolicyFloor`.
 * @param {Array<object>} [options.extraFloorRules=[]] - Additional hardline policy rules.
 */
export function createGroundedSessionEngine({
  db,
  protectedPaths = [],
  extraFloorRules = []
} = {}) {
  assertValidDbHandle(db);
  db.exec(GROUNDED_HARNESS_SCHEMA_SQL);

  // Safe idempotent column migrations for pre-existing SQLite databases
  const migrationColumnDefs = [
    'spin_loops_blocked INTEGER NOT NULL DEFAULT 0',
    'output_defects_caught INTEGER NOT NULL DEFAULT 0',
    'timeouts_with_partial_stdout INTEGER NOT NULL DEFAULT 0'
  ];
  for (const colDef of migrationColumnDefs) {
    try {
      db.exec(`ALTER TABLE grounded_sessions ADD COLUMN ${colDef}`);
    } catch {
      // Column already exists on pre-existing database.
    }
  }

  const policyFloor = createFrozenPolicyFloor({
    protectedPaths,
    extraRules: extraFloorRules
  });

  /** @type {Map<string, ReturnType<typeof createDeltaContextTracker>>} */
  const trackers = new Map();

  function loadSessionRow(sessionId) {
    const cleanId = String(sessionId ?? '').trim();
    if (!cleanId) return null;
    return db.queryOne('SELECT * FROM grounded_sessions WHERE session_id = ?', [cleanId]);
  }

  function hydrateScaleProfile(sessionRow) {
    const parsed = safeParseJsonObject(sessionRow.scale_profile_json);
    if (parsed && typeof parsed.tier === 'string') {
      return parsed;
    }
    return resolveScaleProfile({
      model: sessionRow.model,
      explicitTier: sessionRow.scale_tier
    });
  }

  function getOrHydrateTracker(sessionRow) {
    const sessionId = sessionRow.session_id;
    const seenChunkIds = safeParseJsonArray(sessionRow.seen_chunks_json)
      .map((id) => String(id ?? ''))
      .filter(Boolean);
    const fileDigests = safeParseJsonObject(sessionRow.file_digests_json);

    let tracker = trackers.get(sessionId);
    if (!tracker) {
      tracker = createDeltaContextTracker({
        initialChunkIds: seenChunkIds,
        initialFileDigests: fileDigests
      });
      const committedReads = db.query(
        `SELECT call_signature, result_preview, step
         FROM grounded_events
         WHERE session_id = ? AND is_mutating = 0 AND status = 'COMMITTED'
         ORDER BY created_at_ms ASC, rowid ASC`,
        [sessionId]
      );
      for (const row of committedReads) {
        if (row.call_signature) {
          tracker.recordReadMemo(String(row.call_signature), {
            preview: String(row.result_preview ?? ''),
            step: Number(row.step ?? 0)
          });
        }
      }
      trackers.set(sessionId, tracker);
    } else {
      tracker.seedTurnZero({ chunkIds: seenChunkIds, fileDigests });
    }

    return tracker;
  }

  async function startSession(params = {}) {
    const safeParams = params && typeof params === 'object' ? params : {};
    const rawSessionId = safeParams.session_id ?? safeParams.sessionId;
    const session_id = String(rawSessionId ?? '').trim() || crypto.randomUUID();
    const goal = String(safeParams.goal ?? '').trim();

    if (!goal) {
      return errorEnvelope(
        'VALIDATION_ERROR',
        'goal is required',
        null,
        'krusch_grounded_session_start'
      );
    }

    const model = String(safeParams.model ?? '');
    const scaleProfile = resolveScaleProfile({
      model,
      activeParamsB: safeParams.activeParamsB,
      totalParamsB: safeParams.totalParamsB,
      thinkingEnabled: safeParams.thinkingEnabled,
      thinkingLevel: safeParams.thinkingLevel,
      reasoningEffort: safeParams.reasoningEffort,
      explicitTier: safeParams.explicitTier,
      preferThinkingStepForSmallActive: safeParams.preferThinkingStepForSmallActive === true
    });
    const scaleDirective = buildScaleAwareDirective(scaleProfile);

    const allTools = Array.isArray(safeParams.all_tools ?? safeParams.allTools)
      ? (safeParams.all_tools ?? safeParams.allTools)
      : [];
    const exposedTools = Array.isArray(safeParams.exposed_tools ?? safeParams.exposedTools)
      ? (safeParams.exposed_tools ?? safeParams.exposedTools)
      : [];
    const savings = measureToolSchemaSavings(allTools, exposedTools);

    const rawChunkIds = safeParams.seen_chunk_ids ?? safeParams.seenChunkIds;
    const seenChunkIds = Array.isArray(rawChunkIds)
      ? Array.from(new Set(rawChunkIds.map((id) => String(id ?? '')).filter(Boolean)))
      : [];

    const rawDigests = safeParams.file_digests ?? safeParams.fileDigests;
    const fileDigests =
      rawDigests && typeof rawDigests === 'object' && !Array.isArray(rawDigests)
        ? Object.fromEntries(
            Object.entries(rawDigests)
              .filter(([k, v]) => Boolean(k) && v !== undefined && v !== null)
              .map(([k, v]) => [String(k), String(v)])
          )
        : {};

    const anchor_date = String(safeParams.anchor_date ?? safeParams.anchorDate ?? '');
    const prefix_hash = String(safeParams.prefix_hash ?? safeParams.prefixHash ?? '');
    const turn0_tokens = normalizeNonNegativeInt(
      safeParams.turn0_tokens ?? safeParams.turn0Tokens,
      0
    );
    const max_duplicate_writes = normalizeNonNegativeInt(
      safeParams.max_duplicate_writes ?? safeParams.maxDuplicateWrites,
      1
    );
    const now = Date.now();

    db.transaction(() => {
      db.run('DELETE FROM grounded_events WHERE session_id = ?', [session_id]);
      db.run(
        `INSERT INTO grounded_sessions (
          session_id, goal, model, scale_tier, scale_profile_json,
          anchor_date, prefix_hash, status, max_duplicate_writes,
          seen_chunks_json, file_digests_json,
          schema_tokens_saved, schema_reduction_pct, turn0_tokens,
          exploratory_reads, committed_reads, committed_mutations,
          memoized_reads, spin_loops_blocked, output_defects_caught,
          timeouts_with_partial_stdout, turn0_duplicates_suppressed, duplicate_writes_blocked,
          policy_floor_blocks, truncation_recoveries, verify_nudges_used,
          pending_diffs_count, latest_verification_passed,
          created_at_ms, updated_at_ms
        ) VALUES (
          ?, ?, ?, ?, ?,
          ?, ?, 'ACTIVE', ?,
          ?, ?,
          ?, ?, ?,
          0, 0, 0,
          0, 0, 0,
          0, 0, 0,
          0, 0, 0,
          0, 1,
          ?, ?
        )
        ON CONFLICT(session_id) DO UPDATE SET
          goal = excluded.goal,
          model = excluded.model,
          scale_tier = excluded.scale_tier,
          scale_profile_json = excluded.scale_profile_json,
          anchor_date = excluded.anchor_date,
          prefix_hash = excluded.prefix_hash,
          status = 'ACTIVE',
          max_duplicate_writes = excluded.max_duplicate_writes,
          seen_chunks_json = excluded.seen_chunks_json,
          file_digests_json = excluded.file_digests_json,
          schema_tokens_saved = excluded.schema_tokens_saved,
          schema_reduction_pct = excluded.schema_reduction_pct,
          turn0_tokens = excluded.turn0_tokens,
          exploratory_reads = 0,
          committed_reads = 0,
          committed_mutations = 0,
          memoized_reads = 0,
          spin_loops_blocked = 0,
          output_defects_caught = 0,
          timeouts_with_partial_stdout = 0,
          turn0_duplicates_suppressed = 0,
          duplicate_writes_blocked = 0,
          policy_floor_blocks = 0,
          truncation_recoveries = 0,
          verify_nudges_used = 0,
          pending_diffs_count = 0,
          latest_verification_passed = 1,
          updated_at_ms = excluded.updated_at_ms`,
        [
          session_id,
          goal,
          model,
          scaleProfile.tier,
          JSON.stringify(scaleProfile),
          anchor_date,
          prefix_hash,
          max_duplicate_writes,
          JSON.stringify(seenChunkIds),
          JSON.stringify(fileDigests),
          Number(savings.savedSchemaTokens || 0),
          Number(savings.reductionPct || 0),
          turn0_tokens,
          now,
          now
        ]
      );
    });

    const tracker = createDeltaContextTracker({
      initialChunkIds: seenChunkIds,
      initialFileDigests: fileDigests
    });
    trackers.set(session_id, tracker);

    return okEnvelope(
      'krusch_grounded_session_start',
      `Started grounded session ${session_id} (${scaleProfile.tier})`,
      {
        session_id,
        goal,
        scaleProfile,
        scaleDirective,
        prefix_hash,
        schemaSavings: savings,
        turn0_tokens,
        seededChunks: seenChunkIds.length,
        trackedFiles: Object.keys(fileDigests).length
      }
    );
  }

  function evaluateTurn(params = {}) {
    const safeParams = params && typeof params === 'object' ? params : {};
    const sessionId = String(safeParams.session_id ?? safeParams.sessionId ?? '').trim();
    const sessionRow = loadSessionRow(sessionId);

    if (!sessionRow) {
      return errorEnvelope(
        'NOT_FOUND',
        `Grounded session not found: "${sessionId}"`,
        { session_id: sessionId },
        'krusch_grounded_evaluate_turn'
      );
    }

    const turnResponse = safeParams.turn_response ?? safeParams.turnResponse ?? {};
    const candidateChunks = Array.isArray(safeParams.candidate_chunks ?? safeParams.candidateChunks)
      ? (safeParams.candidate_chunks ?? safeParams.candidateChunks)
      : [];

    const truncation = evaluateTruncationPoisoningGuard(turnResponse);
    if (truncation.poisoned) {
      db.run(
        `UPDATE grounded_sessions
         SET truncation_recoveries = truncation_recoveries + 1, updated_at_ms = ?
         WHERE session_id = ?`,
        [Date.now(), sessionId]
      );

      return okEnvelope(
        'krusch_grounded_evaluate_turn',
        'Aborted turn due to truncation poisoning',
        {
          session_id: sessionId,
          poisoned: true,
          safeToExecuteTools: false,
          reason: truncation.reason,
          truncatedCallIds: truncation.truncatedCallIds,
          recoveryPrompt: truncation.recoveryPrompt,
          novelChunks: [],
          suppressedChunkCount: 0
        }
      );
    }

    const tracker = getOrHydrateTracker(sessionRow);
    const delta = tracker.filterDeltaChunks(candidateChunks);
    const novelChunks = Array.isArray(delta?.novelChunks) ? delta.novelChunks : [];
    const suppressedCount = Number(delta?.suppressedCount ?? 0);

    if (suppressedCount > 0 || novelChunks.length > 0) {
      const seenSet = new Set(
        safeParseJsonArray(sessionRow.seen_chunks_json)
          .map((id) => String(id ?? ''))
          .filter(Boolean)
      );
      for (const chunk of novelChunks) {
        const chunkId = extractChunkId(chunk);
        if (chunkId) {
          seenSet.add(chunkId);
        }
      }
      db.run(
        `UPDATE grounded_sessions
         SET turn0_duplicates_suppressed = turn0_duplicates_suppressed + ?,
             seen_chunks_json = ?,
             updated_at_ms = ?
         WHERE session_id = ?`,
        [suppressedCount, JSON.stringify(Array.from(seenSet)), Date.now(), sessionId]
      );
    }

    return okEnvelope(
      'krusch_grounded_evaluate_turn',
      `Evaluated turn (${novelChunks.length} novel chunk(s), ${suppressedCount} duplicate(s) suppressed)`,
      {
        session_id: sessionId,
        poisoned: false,
        safeToExecuteTools: true,
        reason: null,
        truncatedCallIds: [],
        recoveryPrompt: null,
        novelChunks,
        suppressedChunkCount: suppressedCount
      }
    );
  }

  function interceptToolCall(params = {}) {
    const safeParams = params && typeof params === 'object' ? params : {};
    const sessionId = String(safeParams.session_id ?? safeParams.sessionId ?? '').trim();
    const sessionRow = loadSessionRow(sessionId);

    if (!sessionRow) {
      return errorEnvelope(
        'NOT_FOUND',
        `Grounded session not found: "${sessionId}"`,
        { session_id: sessionId },
        'krusch_grounded_intercept'
      );
    }

    const cleanToolName = String(safeParams.tool_name ?? safeParams.toolName ?? '').trim();
    if (!cleanToolName) {
      return errorEnvelope(
        'VALIDATION_ERROR',
        'tool_name is required',
        { session_id: sessionId },
        'krusch_grounded_intercept'
      );
    }

    const scaleProfile = hydrateScaleProfile(sessionRow);
    const tracker = getOrHydrateTracker(sessionRow);
    const rawArgs = safeParams.args !== undefined ? safeParams.args : {};
    const normalizedArgs = normalizeRawArgs(rawArgs);
    const isMutating = classifyToolMutability(cleanToolName, safeParams.mutating);
    const isForaging = !isMutating && isForagingTool(cleanToolName, normalizedArgs);
    const suppressTurn0Reads =
      safeParams.suppress_turn0_reads !== undefined
        ? safeParams.suppress_turn0_reads
        : safeParams.suppressTurn0Reads;

    const { canonicalArgsJson, callSignature } = canonicalizeToolCallKey(
      cleanToolName,
      normalizedArgs
    );
    const safeStep = normalizeNonNegativeInt(safeParams.step, 0);
    const event_id = crypto.randomUUID();
    const now = Date.now();

    const insertEvent = ({ decision, status, issues = [], result_preview = '' }) => {
      db.run(
        `INSERT INTO grounded_events (
          event_id, session_id, step, tool_name, is_mutating, is_foraging,
          canonical_args_json, call_signature, decision, status, issues_json,
          result_preview, created_at_ms, updated_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          event_id,
          sessionId,
          safeStep,
          cleanToolName,
          isMutating ? 1 : 0,
          isForaging ? 1 : 0,
          canonicalArgsJson,
          callSignature,
          decision,
          status,
          JSON.stringify(issues),
          String(result_preview || '').slice(0, MAX_RESULT_PREVIEW_CHARS),
          now,
          now
        ]
      );
    };

    // Check 1: Frozen Policy Floor
    const floorVerdict = policyFloor.evaluate(cleanToolName, buildPolicyFloorArgs(normalizedArgs));
    if (!floorVerdict.allowed) {
      const ruleId = floorVerdict.ruleId || 'POLICY_FLOOR_FORBIDDEN';
      db.transaction(() => {
        db.run(
          `UPDATE grounded_sessions
           SET policy_floor_blocks = policy_floor_blocks + 1, updated_at_ms = ?
           WHERE session_id = ?`,
          [now, sessionId]
        );
        insertEvent({
          decision: 'BLOCK',
          status: 'BLOCKED',
          issues: [{ code: ruleId, message: floorVerdict.reason }]
        });
      });

      return okEnvelope(
        'krusch_grounded_intercept',
        `Blocked tool call ${cleanToolName} by policy floor (${ruleId})`,
        {
          decision: 'BLOCK',
          status: 'BLOCKED',
          reason: ruleId,
          detail: floorVerdict.reason,
          isMutating,
          isForaging,
          event_id,
          call_signature: callSignature
        }
      );
    }

    // Check 2: Secret Leak Guard on mutating or outbound calls
    const isOutboundCall = OUTBOUND_TOOL_HINT_RE.test(cleanToolName);
    if (isMutating || isOutboundCall) {
      const leakedSecretRule = scanArgsForSecretLeak(canonicalArgsJson, normalizedArgs);
      if (leakedSecretRule) {
        const detail = `Blocked live credential signature (${leakedSecretRule}) in tool arguments.`;
        db.transaction(() => {
          db.run(
            `UPDATE grounded_sessions
             SET policy_floor_blocks = policy_floor_blocks + 1, updated_at_ms = ?
             WHERE session_id = ?`,
            [now, sessionId]
          );
          insertEvent({
            decision: 'BLOCK',
            status: 'BLOCKED',
            issues: [{ code: 'SECRET_LEAK_BLOCKED', rule: leakedSecretRule, message: detail }]
          });
        });

        return okEnvelope(
          'krusch_grounded_intercept',
          `Blocked tool call ${cleanToolName} due to credential leak signature`,
          {
            decision: 'BLOCK',
            status: 'BLOCKED',
            reason: 'SECRET_LEAK_BLOCKED',
            detail,
            isMutating,
            isForaging,
            event_id,
            call_signature: callSignature
          }
        );
      }
    }

    const rawBlockSpin =
      safeParams.block_spin_loop !== undefined
        ? safeParams.block_spin_loop
        : safeParams.blockSpinLoop;
    const spinLoopEnabled = rawBlockSpin !== false;
    const explicitBlockSpinLoop = rawBlockSpin === true;

    const respondWithSpinLoopBlock = (priorSpinRow) => {
      const fallbackMemoPreview = String(tracker.checkReadMemo(callSignature)?.entry?.preview ?? '');
      const cachedPreview = String(priorSpinRow.result_preview ?? '') || fallbackMemoPreview;
      const wasFailed = priorSpinRow.status === 'FAILED';
      const detail = wasFailed
        ? `Identical call to "${cleanToolName}" already failed in this session.`
        : `Identical call to "${cleanToolName}" already returned ${priorSpinRow.status} in this session.`;
      const correctivePrompt = wasFailed
        ? `Spin-loop blocked: identical call to "${cleanToolName}" already failed${cachedPreview ? ` (${cachedPreview})` : ''}. Do not re-run the same code, SQL, or command with only comment/whitespace edits; change your logic or arguments before retrying.`
        : `Spin-loop blocked: identical call to "${cleanToolName}" was already executed${cachedPreview ? ` (cached result: ${cachedPreview})` : ''}. Use the existing observation in context to advance or answer instead of repeating "${cleanToolName}".`;

      db.transaction(() => {
        db.run(
          `UPDATE grounded_sessions
           SET spin_loops_blocked = spin_loops_blocked + 1, updated_at_ms = ?
           WHERE session_id = ?`,
          [now, sessionId]
        );
        insertEvent({
          decision: 'BLOCK',
          status: 'BLOCKED',
          issues: [{ code: 'BLOCK_SPIN_LOOP', message: detail }],
          result_preview: cachedPreview
        });
      });

      return okEnvelope(
        'krusch_grounded_intercept',
        `Blocked duplicate spin-loop call for ${cleanToolName}`,
        {
          decision: 'BLOCK',
          status: 'BLOCKED',
          reason: 'BLOCK_SPIN_LOOP',
          detail,
          cachedPreview,
          correctivePrompt,
          isMutating,
          isForaging,
          event_id,
          call_signature: callSignature
        }
      );
    };

    // Explicit Spin-Loop Override (`block_spin_loop: true` / `blockSpinLoop: true`)
    if (spinLoopEnabled && explicitBlockSpinLoop) {
      const priorAnyRow = db.queryOne(
        `SELECT status, result_preview
         FROM grounded_events
         WHERE session_id = ? AND call_signature = ? AND status IN ('COMMITTED', 'FAILED', 'MEMOIZED')
         ORDER BY updated_at_ms DESC, rowid DESC
         LIMIT 1`,
        [sessionId, callSignature]
      );
      if (priorAnyRow) {
        return respondWithSpinLoopBlock(priorAnyRow);
      }
    }

    // Find latest workspace mutation rowid (if any) to scope read/spin/duplicate-write checks
    const lastMutationRow = db.queryOne(
      `SELECT MAX(rowid) AS max_rowid, call_signature
       FROM grounded_events
       WHERE session_id = ? AND is_mutating = 1 AND status = 'COMMITTED'`,
      [sessionId]
    );
    const lastMutationRowId = Number(lastMutationRow?.max_rowid ?? 0);

    // Check 3: Duplicate Mutating Write Guard (consecutive identical mutations without an intervening different mutation)
    if (isMutating) {
      const lastDiffMutationRow = db.queryOne(
        `SELECT MAX(rowid) AS max_rowid
         FROM grounded_events
         WHERE session_id = ? AND is_mutating = 1 AND status = 'COMMITTED' AND call_signature != ?`,
        [sessionId, callSignature]
      );
      const afterRowId = Number(lastDiffMutationRow?.max_rowid ?? 0);
      const countRow = db.queryOne(
        `SELECT COUNT(*) AS cnt
         FROM grounded_events
         WHERE session_id = ? AND call_signature = ? AND status = 'COMMITTED' AND rowid > ?`,
        [sessionId, callSignature, afterRowId]
      );
      const committedCount = Number(countRow?.cnt ?? 0);
      const maxDupWrites = Number(sessionRow.max_duplicate_writes ?? 1);

      if (committedCount >= maxDupWrites) {
        const detail = `Identical mutating tool call already committed ${committedCount} time(s) (max_duplicate_writes=${maxDupWrites}).`;
        db.transaction(() => {
          db.run(
            `UPDATE grounded_sessions
             SET duplicate_writes_blocked = duplicate_writes_blocked + 1, updated_at_ms = ?
             WHERE session_id = ?`,
            [now, sessionId]
          );
          insertEvent({
            decision: 'BLOCK',
            status: 'BLOCKED',
            issues: [{ code: 'BLOCK_DUPLICATE_WRITE', message: detail }]
          });
        });

        return okEnvelope(
          'krusch_grounded_intercept',
          `Blocked duplicate mutating write for ${cleanToolName}`,
          {
            decision: 'BLOCK',
            status: 'BLOCKED',
            reason: 'BLOCK_DUPLICATE_WRITE',
            detail,
            isMutating: true,
            isForaging: false,
            event_id,
            call_signature: callSignature
          }
        );
      }
    }

    // Check 3.5: Passive Spin-Loop Guard on repeated FAILED or already-MEMOIZED calls since last mutation (`INV-GH-04`)
    if (spinLoopEnabled && !explicitBlockSpinLoop) {
      const priorSpinRow = db.queryOne(
        `SELECT status, result_preview
         FROM grounded_events
         WHERE session_id = ? AND call_signature = ? AND status IN ('FAILED', 'MEMOIZED') AND rowid > ?
         ORDER BY updated_at_ms DESC, rowid DESC
         LIMIT 1`,
        [sessionId, callSignature, lastMutationRowId]
      );
      if (priorSpinRow) {
        return respondWithSpinLoopBlock(priorSpinRow);
      }
    }

    // Check 4: Read Memoization & Turn-0 Delta Short-Circuit (strictly maxReadStreak === 0, scoped since last mutation)
    if (!isMutating) {
      const memo = tracker.checkReadMemo(callSignature);
      let memoHit = Boolean(memo?.hit);
      let cachedPreview = memoHit ? String(memo?.entry?.preview ?? '') : '';

      if (!memoHit) {
        const committedReadRow = db.queryOne(
          `SELECT result_preview, step
           FROM grounded_events
           WHERE session_id = ? AND call_signature = ? AND is_mutating = 0 AND status = 'COMMITTED' AND rowid > ?
           ORDER BY updated_at_ms DESC, rowid DESC
           LIMIT 1`,
          [sessionId, callSignature, lastMutationRowId]
        );
        if (committedReadRow) {
          memoHit = true;
          cachedPreview = String(committedReadRow.result_preview ?? '');
          tracker.recordReadMemo(callSignature, {
            preview: cachedPreview,
            step: Number(committedReadRow.step ?? 0)
          });
        }
      }

      if (memoHit) {
        db.transaction(() => {
          db.run(
            `UPDATE grounded_sessions
             SET memoized_reads = memoized_reads + 1, updated_at_ms = ?
             WHERE session_id = ?`,
            [now, sessionId]
          );
          insertEvent({
            decision: 'MEMOIZED',
            status: 'MEMOIZED',
            result_preview: cachedPreview
          });
        });

        return okEnvelope(
          'krusch_grounded_intercept',
          `Memoized prior identical read for ${cleanToolName}`,
          {
            decision: 'MEMOIZED',
            status: 'MEMOIZED',
            reason: 'MEMOIZED_PRIOR_READ',
            cachedPreview,
            isMutating: false,
            isForaging,
            event_id,
            call_signature: callSignature
          }
        );
      }

      if (suppressTurn0Reads !== false && normalizedArgs && typeof normalizedArgs === 'object') {
        const relPath = normalizedArgs.relPath ?? normalizedArgs.rel_path;
        const fileDigest = normalizedArgs.fileDigest ?? normalizedArgs.file_digest;
        if (relPath && fileDigest && tracker.hasSeenFileDigest(relPath, fileDigest)) {
          const turn0Preview = `File "${String(relPath)}" unchanged since Turn-0 grounding.`;
          db.transaction(() => {
            db.run(
              `UPDATE grounded_sessions
               SET turn0_duplicates_suppressed = turn0_duplicates_suppressed + 1, updated_at_ms = ?
               WHERE session_id = ?`,
              [now, sessionId]
            );
            insertEvent({
              decision: 'MEMOIZED',
              status: 'MEMOIZED',
              result_preview: turn0Preview
            });
          });

          return okEnvelope(
            'krusch_grounded_intercept',
            `Suppressed redundant Turn-0 file read (${String(relPath)})`,
            {
              decision: 'MEMOIZED',
              status: 'MEMOIZED',
              reason: 'ALREADY_GROUNDED_TURN_ZERO',
              isMutating: false,
              isForaging,
              event_id,
              call_signature: callSignature
            }
          );
        }
      }
    }

    // Check 5: SMALL_MODEL-Only Placeholder & Invalid Calendar Date Soft-Hold
    if (scaleProfile.softHoldPlaceholdersAndDates === true && isMutating) {
      const issues = scanSmallModelArgumentIssues(normalizedArgs);
      if (issues.length > 0) {
        const anchorNote = sessionRow.anchor_date
          ? ` (session anchor_date: ${sessionRow.anchor_date})`
          : '';
        const correctivePrompt =
          `Pre-action argument check held "${cleanToolName}"${anchorNote}: `
          + `${issues.map((item) => item.message).join(' ')} `
          + `Replace placeholders and invalid calendar dates with concrete bound values and re-invoke "${cleanToolName}".`;

        db.transaction(() => {
          db.run(
            'UPDATE grounded_sessions SET updated_at_ms = ? WHERE session_id = ?',
            [now, sessionId]
          );
          insertEvent({
            decision: 'HOLD',
            status: 'HELD',
            issues
          });
        });

        return okEnvelope(
          'krusch_grounded_intercept',
          `Soft-held mutating tool call ${cleanToolName} (${issues.length} argument issue(s))`,
          {
            decision: 'HOLD',
            status: 'HELD',
            reason: 'SMALL_MODEL_ARGUMENT_HOLD',
            issues,
            correctivePrompt,
            isMutating: true,
            isForaging: false,
            event_id,
            call_signature: callSignature
          }
        );
      }
    }

    // Default: Stage PENDING tool call
    db.transaction(() => {
      db.run(
        'UPDATE grounded_sessions SET updated_at_ms = ? WHERE session_id = ?',
        [now, sessionId]
      );
      insertEvent({
        decision: 'ALLOW',
        status: 'PENDING'
      });
    });

    return okEnvelope(
      'krusch_grounded_intercept',
      `Allowed tool call ${cleanToolName}`,
      {
        decision: 'ALLOW',
        status: 'PENDING',
        reason: 'ALLOWED',
        isMutating,
        isForaging,
        event_id,
        call_signature: callSignature
      }
    );
  }

  function recordToolOutcome(params = {}) {
    const safeParams = params && typeof params === 'object' ? params : {};
    const sessionId = String(safeParams.session_id ?? safeParams.sessionId ?? '').trim();
    const sessionRow = loadSessionRow(sessionId);

    if (!sessionRow) {
      return errorEnvelope(
        'NOT_FOUND',
        `Grounded session not found: "${sessionId}"`,
        { session_id: sessionId },
        'krusch_grounded_outcome'
      );
    }

    const lookupEventId = String(safeParams.event_id ?? safeParams.eventId ?? '').trim();
    const lookupCallSignature = String(
      safeParams.call_signature ?? safeParams.callSignature ?? ''
    ).trim();
    const timedOut = Boolean(safeParams.timed_out ?? safeParams.timedOut ?? false);
    const isOk = timedOut ? false : safeParams.ok !== false;
    const rawPreview = safeParams.result_preview ?? safeParams.resultPreview ?? '';

    const rawDelta = safeParams.pending_diffs_delta ?? safeParams.pendingDiffsDelta ?? 0;
    const pendingDiffsDelta = Number.isFinite(Number(rawDelta)) ? Math.trunc(Number(rawDelta)) : 0;
    const verificationPassed =
      safeParams.verification_passed !== undefined
        ? safeParams.verification_passed
        : safeParams.verificationPassed;
    const clearPendingDiffs =
      safeParams.clear_pending_diffs !== undefined
        ? safeParams.clear_pending_diffs
        : safeParams.clearPendingDiffs;

    let eventRow = null;
    if (lookupEventId) {
      eventRow = db.queryOne(
        `SELECT * FROM grounded_events
         WHERE session_id = ? AND event_id = ? AND status = 'PENDING'
         LIMIT 1`,
        [sessionId, lookupEventId]
      );
    } else if (lookupCallSignature) {
      eventRow = db.queryOne(
        `SELECT * FROM grounded_events
         WHERE session_id = ? AND call_signature = ? AND status = 'PENDING'
         ORDER BY created_at_ms DESC, rowid DESC
         LIMIT 1`,
        [sessionId, lookupCallSignature]
      );
    } else {
      eventRow = db.queryOne(
        `SELECT * FROM grounded_events
         WHERE session_id = ? AND status = 'PENDING'
         ORDER BY created_at_ms DESC, rowid DESC
         LIMIT 1`,
        [sessionId]
      );
    }

    if (!eventRow) {
      return errorEnvelope(
        'NOT_FOUND',
        'Matching PENDING tool event not found',
        {
          session_id: sessionId,
          event_id: lookupEventId || null,
          call_signature: lookupCallSignature || null
        },
        'krusch_grounded_outcome'
      );
    }

    let formattedTimeout = null;
    let truncatedPreview;
    if (timedOut) {
      const rawPartialStdout =
        safeParams.partial_stdout
        ?? safeParams.partialStdout
        ?? safeParams.stdout
        ?? rawPreview
        ?? '';
      const rawPartialStderr = safeParams.stderr ?? '';
      formattedTimeout = formatTimeoutWithPartialStdout({
        timeoutMs: safeParams.timeout_ms ?? safeParams.timeoutMs,
        timeoutSeconds: safeParams.timeout_seconds ?? safeParams.timeoutSeconds,
        stdout:
          typeof rawPartialStdout === 'string'
            ? rawPartialStdout
            : JSON.stringify(rawPartialStdout) || '',
        stderr:
          typeof rawPartialStderr === 'string'
            ? rawPartialStderr
            : String(rawPartialStderr ?? ''),
        maxStdoutChars: safeParams.max_stdout_chars ?? safeParams.maxStdoutChars ?? 8000,
        label: eventRow.tool_name || 'Sandbox execution'
      });
      truncatedPreview = formattedTimeout.formattedObservation.slice(0, MAX_RESULT_PREVIEW_CHARS);
    } else {
      truncatedPreview = String(
        typeof rawPreview === 'string' ? rawPreview : JSON.stringify(rawPreview) || ''
      ).slice(0, MAX_RESULT_PREVIEW_CHARS);
    }

    const nextStatus = isOk ? 'COMMITTED' : 'FAILED';
    let committedMutations = Number(sessionRow.committed_mutations || 0);
    let committedReads = Number(sessionRow.committed_reads || 0);
    let exploratoryReads = Number(sessionRow.exploratory_reads || 0);
    let timeoutsWithPartialStdout = Number(sessionRow.timeouts_with_partial_stdout || 0);
    let pending_diffs_count = Number(sessionRow.pending_diffs_count || 0);
    let latest_verification_passed = Number(sessionRow.latest_verification_passed ?? 1);

    if (timedOut) {
      timeoutsWithPartialStdout += 1;
    }

    if (isOk) {
      if (Number(eventRow.is_mutating) === 1) {
        committedMutations += 1;
        pending_diffs_count = Math.max(0, pending_diffs_count + pendingDiffsDelta);
        if (pendingDiffsDelta > 0 && verificationPassed === undefined) {
          latest_verification_passed = 0;
        }
      } else {
        committedReads += 1;
        if (Number(eventRow.is_foraging) === 1) {
          exploratoryReads += 1;
        }
      }
    }

    if (typeof verificationPassed === 'boolean') {
      latest_verification_passed = verificationPassed ? 1 : 0;
      if (verificationPassed === true && clearPendingDiffs !== false) {
        pending_diffs_count = 0;
      }
    }

    const now = Date.now();
    db.transaction(() => {
      db.run(
        `UPDATE grounded_events
         SET status = ?, result_preview = ?, updated_at_ms = ?
         WHERE event_id = ? AND session_id = ?`,
        [nextStatus, truncatedPreview, now, eventRow.event_id, sessionId]
      );
      db.run(
        `UPDATE grounded_sessions
         SET committed_mutations = ?,
             committed_reads = ?,
             exploratory_reads = ?,
             timeouts_with_partial_stdout = ?,
             pending_diffs_count = ?,
             latest_verification_passed = ?,
             updated_at_ms = ?
         WHERE session_id = ?`,
        [
          committedMutations,
          committedReads,
          exploratoryReads,
          timeoutsWithPartialStdout,
          pending_diffs_count,
          latest_verification_passed,
          now,
          sessionId
        ]
      );
    });

    if (isOk) {
      const tracker = getOrHydrateTracker(sessionRow);
      if (Number(eventRow.is_mutating) === 0) {
        tracker.recordReadMemo(eventRow.call_signature, {
          preview: truncatedPreview,
          step: Number(eventRow.step || 0)
        });
      } else if (typeof tracker.clearReadMemo === 'function') {
        tracker.clearReadMemo();
      }
    }

    if (timedOut && formattedTimeout) {
      return okEnvelope(
        'krusch_grounded_outcome',
        `Recorded TIMEOUT outcome for ${eventRow.tool_name} with preserved partial stdout`,
        {
          session_id: sessionId,
          event_id: eventRow.event_id,
          status: nextStatus,
          pending_diffs_count,
          latest_verification_passed,
          timed_out: true,
          has_final_answer: false,
          preserved_stdout: formattedTimeout.stdout,
          formatted_observation: formattedTimeout.formattedObservation
        }
      );
    }

    return okEnvelope(
      'krusch_grounded_outcome',
      `Recorded ${nextStatus} outcome for ${eventRow.tool_name}`,
      {
        session_id: sessionId,
        event_id: eventRow.event_id,
        status: nextStatus,
        pending_diffs_count,
        latest_verification_passed
      }
    );
  }

  function verifyStop(params = {}) {
    const safeParams = params && typeof params === 'object' ? params : {};
    const sessionId = String(safeParams.session_id ?? safeParams.sessionId ?? '').trim();
    const sessionRow = loadSessionRow(sessionId);

    if (!sessionRow) {
      return errorEnvelope(
        'NOT_FOUND',
        `Grounded session not found: "${sessionId}"`,
        { session_id: sessionId },
        'krusch_grounded_verify_stop'
      );
    }

    const scaleProfile = hydrateScaleProfile(sessionRow);
    const assistantText = String(safeParams.assistant_text ?? safeParams.assistantText ?? '');
    const rawToolCalls = safeParams.tool_calls ?? safeParams.toolCalls;
    const toolCalls = Array.isArray(rawToolCalls) ? rawToolCalls : [];

    const rawPendingDiffs =
      safeParams.pending_diffs_count !== undefined
        ? safeParams.pending_diffs_count
        : safeParams.pendingDiffsCount;
    const pendingDiffs =
      rawPendingDiffs !== undefined
        ? Math.max(0, Math.trunc(Number(rawPendingDiffs) || 0))
        : Number(sessionRow.pending_diffs_count || 0);

    const rawLatestVerif =
      safeParams.latest_verification_passed !== undefined
        ? safeParams.latest_verification_passed
        : safeParams.latestVerificationPassed;
    const verifPassed =
      rawLatestVerif !== undefined
        ? Boolean(rawLatestVerif)
        : Boolean(sessionRow.latest_verification_passed);

    const verificationCommand =
      safeParams.verification_command
      ?? safeParams.verificationCommand
      ?? null;

    const verifyNudgesUsed = Number(sessionRow.verify_nudges_used || 0);
    const now = Date.now();

    // Gate 1: Real Unverified Staged Code/Disk Diffs ONLY when pendingDiffsCount > 0 (INV-GH-05)
    if (pendingDiffs > 0 && !verifPassed) {
      const guard = evaluateVerifyOnStopGuard({
        toolCalls,
        stopRequested: true,
        pendingDiffsCount: pendingDiffs,
        mutatedFilesCount: 0,
        latestVerificationPassed: verifPassed,
        verificationCommand,
        verifyRetries: verifyNudgesUsed,
        maxVerifyRetries: 2
      });

      if (guard.action === 'FORCE_VERIFY') {
        db.run(
          `UPDATE grounded_sessions
           SET verify_nudges_used = verify_nudges_used + 1, updated_at_ms = ?
           WHERE session_id = ?`,
          [now, sessionId]
        );
      } else if (guard.action === 'ABORT_UNVERIFIED') {
        db.run(
          `UPDATE grounded_sessions
           SET status = 'ABORTED', updated_at_ms = ?
           WHERE session_id = ?`,
          [now, sessionId]
        );
      }

      return okEnvelope(
        'krusch_grounded_verify_stop',
        guard.action === 'FORCE_VERIFY'
          ? 'Stop blocked: unverified mutations require verification'
          : `Stop blocked (${guard.action})`,
        {
          allowStop: guard.allowStop,
          shouldNudge: guard.action === 'FORCE_VERIFY',
          action: guard.action,
          reason: guard.reason,
          nudgePrompt: guard.correctivePrompt,
          scaleTier: scaleProfile.tier
        }
      );
    }

    // Gate 2: Zero-Turn Defect-Only Output Gate across ALL tiers (`INV-GH-05`)
    const isAbstention = Boolean(
      safeParams.is_policy_abstention === true
      || safeParams.isPolicyAbstention === true
      || POLICY_ABSTENTION_RE.test(assistantText)
    );
    const enableOutputDefectGate =
      safeParams.enable_output_defect_gate !== false
      && safeParams.enableOutputDefectGate !== false;
    const rawMaxDefectRetries =
      safeParams.max_defect_retries !== undefined
        ? safeParams.max_defect_retries
        : safeParams.maxDefectRetries;
    const maxDefectRetries =
      rawMaxDefectRetries !== undefined && Number.isFinite(Number(rawMaxDefectRetries))
        ? Math.max(0, Math.trunc(Number(rawMaxDefectRetries)))
        : 1;

    if (
      enableOutputDefectGate
      && toolCalls.length === 0
      && verifyNudgesUsed < maxDefectRetries
    ) {
      const hasCandidateParam =
        Object.prototype.hasOwnProperty.call(safeParams, 'candidate_answer')
        || Object.prototype.hasOwnProperty.call(safeParams, 'candidateAnswer');
      const candidateAnswerParam = Object.prototype.hasOwnProperty.call(safeParams, 'candidateAnswer')
        ? safeParams.candidateAnswer
        : safeParams.candidate_answer;
      const hasExplicitTextOrAnswer =
        hasCandidateParam
        || Object.prototype.hasOwnProperty.call(safeParams, 'assistant_text')
        || Object.prototype.hasOwnProperty.call(safeParams, 'assistantText');
      const expectNonEmptyAnswer =
        safeParams.expect_non_empty_answer !== undefined
          ? Boolean(safeParams.expect_non_empty_answer)
          : safeParams.expectNonEmptyAnswer !== undefined
            ? Boolean(safeParams.expectNonEmptyAnswer)
            : hasExplicitTextOrAnswer;

      const defectReport = inspectOutputDefects({
        ...(hasCandidateParam ? { candidateAnswer: candidateAnswerParam } : {}),
        assistantText,
        finishReason: safeParams.finish_reason ?? safeParams.finishReason ?? null,
        stopReason: safeParams.stop_reason ?? safeParams.stopReason ?? null,
        truncatedToolCalls:
          safeParams.truncated_tool_calls ?? safeParams.truncatedToolCalls ?? false,
        toolCalls,
        expectNonEmptyAnswer
      });

      const effectiveDefects = isAbstention
        ? defectReport.defects.filter((d) => d.code !== 'EMPTY_OR_NULL_BAILOUT')
        : defectReport.defects;

      if (effectiveDefects.length > 0) {
        const activeDefect = effectiveDefects[0];
        const isTruncatedDefect = activeDefect.code === 'TRUNCATED_OUTPUT';
        const isSerializedToolDefect =
          activeDefect.code === 'SERIALIZED_TOOL_CALL_IN_TEXT';

        db.run(
          `UPDATE grounded_sessions
           SET verify_nudges_used = verify_nudges_used + 1,
               output_defects_caught = output_defects_caught + 1,
               truncation_recoveries = truncation_recoveries + ?,
               updated_at_ms = ?
           WHERE session_id = ?`,
          [isTruncatedDefect ? 1 : 0, now, sessionId]
        );

        if (isSerializedToolDefect) {
          return okEnvelope(
            'krusch_grounded_verify_stop',
            'Rescued plain-text serialized tool call before premature stop',
            {
              allowStop: false,
              shouldNudge: true,
              action: 'RESCUE_SERIALIZED_TOOL',
              reason: 'SERIALIZED_TOOL_CALL_IN_TEXT',
              defects: effectiveDefects,
              nudgePrompt: defectReport.correctivePrompt,
              correctivePrompt: defectReport.correctivePrompt,
              rescuedToolCalls: defectReport.rescuedToolCalls,
              scaleTier: scaleProfile.tier
            }
          );
        }

        return okEnvelope(
          'krusch_grounded_verify_stop',
          `Stop blocked by output defect gate (${activeDefect.code})`,
          {
            allowStop: false,
            shouldNudge: true,
            action: 'REJECT_OUTPUT_DEFECT',
            reason: activeDefect.code,
            defects: effectiveDefects,
            nudgePrompt: defectReport.correctivePrompt,
            correctivePrompt: defectReport.correctivePrompt,
            rescuedToolCalls: defectReport.rescuedToolCalls,
            scaleTier: scaleProfile.tier
          }
        );
      }
    }

    // Gate 3: SMALL_MODEL-Only Uncommitted Formatted Draft Rescue (NEVER on Abstentions)
    const maxMechanicalNudges = Number(scaleProfile.maxMechanicalVerifyNudges ?? 0);
    const committedMutations = Number(sessionRow.committed_mutations || 0);

    if (
      scaleProfile.tier === SCALE_TIERS.SMALL_MODEL
      && verifyNudgesUsed < maxMechanicalNudges
      && committedMutations === 0
      && toolCalls.length === 0
      && !isAbstention
      && !DRAFT_ONLY_GOAL_EXEMPT_RE.test(sessionRow.goal)
      && OUTBOUND_ACTION_GOAL_RE.test(sessionRow.goal)
      && UNSENT_DRAFT_HEADER_RE.test(assistantText)
    ) {
      db.run(
        `UPDATE grounded_sessions
         SET verify_nudges_used = verify_nudges_used + 1, updated_at_ms = ?
         WHERE session_id = ?`,
        [now, sessionId]
      );

      return okEnvelope(
        'krusch_grounded_verify_stop',
        'Nudged SMALL_MODEL uncommitted outbound draft',
        {
          allowStop: false,
          shouldNudge: true,
          action: 'NUDGE_SMALL_MODEL_DRAFT',
          reason: 'SMALL_MODEL_UNCOMMITTED_DRAFT',
          nudgePrompt:
            'You drafted the outbound payload in text without invoking the action tool. Call the appropriate tool with your bound parameters now, or state explicitly if policy forbids it.',
          scaleTier: scaleProfile.tier
        }
      );
    }

    // Default (INV-GH-05): Zero-overhead clean stop
    db.run(
      `UPDATE grounded_sessions
       SET status = 'COMPLETED', updated_at_ms = ?
       WHERE session_id = ?`,
      [now, sessionId]
    );

    return okEnvelope(
      'krusch_grounded_verify_stop',
      'Stop approved with zero outer-loop 2PC overhead',
      {
        allowStop: true,
        shouldNudge: false,
        action: 'ALLOW_STOP',
        reason: 'CLEAN_STOP',
        nudgePrompt: null,
        scaleTier: scaleProfile.tier
      }
    );
  }

  function sessionSummary(params = {}) {
    const safeParams = params && typeof params === 'object' ? params : {};
    const sessionId = String(safeParams.session_id ?? safeParams.sessionId ?? '').trim();
    const session = loadSessionRow(sessionId);

    if (!session) {
      return errorEnvelope(
        'NOT_FOUND',
        `Grounded session not found: "${sessionId}"`,
        { session_id: sessionId },
        'krusch_grounded_summary'
      );
    }

    const events = db.query(
      `SELECT *
       FROM grounded_events
       WHERE session_id = ?
       ORDER BY step ASC, created_at_ms ASC, rowid ASC`,
      [sessionId]
    );

    const exploratoryReads = Number(session.exploratory_reads || 0);
    const committedReads = Number(session.committed_reads || 0);
    const committedMutations = Number(session.committed_mutations || 0);
    const memoizedReads = Number(session.memoized_reads || 0);
    const spinLoopsBlocked = Number(session.spin_loops_blocked || 0);
    const outputDefectsCaught = Number(session.output_defects_caught || 0);
    const timeoutsWithPartialStdout = Number(session.timeouts_with_partial_stdout || 0);
    const turn0DuplicatesSuppressed = Number(session.turn0_duplicates_suppressed || 0);
    const duplicateWritesBlocked = Number(session.duplicate_writes_blocked || 0);
    const policyFloorBlocks = Number(session.policy_floor_blocks || 0);
    const truncationRecoveries = Number(session.truncation_recoveries || 0);
    const verifyNudgesUsed = Number(session.verify_nudges_used || 0);
    const schemaTokensSaved = Number(session.schema_tokens_saved || 0);
    const schemaReductionPct = Number(session.schema_reduction_pct || 0);

    const totalCommittedCalls = committedReads + committedMutations;
    const foragingRatio =
      totalCommittedCalls > 0
        ? Number((exploratoryReads / totalCommittedCalls).toFixed(4))
        : 0;

    return okEnvelope(
      'krusch_grounded_summary',
      `Session ${sessionId} (${session.status}, ${events.length} event(s))`,
      {
        session,
        metrics: {
          exploratoryReads,
          committedReads,
          committedMutations,
          memoizedReads,
          spinLoopsBlocked,
          outputDefectsCaught,
          timeoutsWithPartialStdout,
          turn0DuplicatesSuppressed,
          duplicateWritesBlocked,
          policyFloorBlocks,
          truncationRecoveries,
          verifyNudgesUsed,
          schemaTokensSaved,
          schemaReductionPct,
          foragingRatio
        },
        events
      }
    );
  }

  return {
    startSession,
    evaluateTurn,
    interceptToolCall,
    recordToolOutcome,
    verifyStop,
    sessionSummary
  };
}
