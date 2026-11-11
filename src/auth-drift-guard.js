/**
 * @module auth-drift-guard
 * @description Early Scope & Authorization Drift Guard (`arXiv:2611.09113`, ADB + SERS)
 * and Decoupled Action Realization & Targeted Repair (`arXiv:2610.34298`, MICA + DART) (`INV-GH-12`).
 *
 * Enforces two complementary zero-LLM runtime layers inside `interceptToolCall`:
 * 1. **DART MCP-vs-CLI Boundary Realization Layer (`inspectAndRepairDartBoundaries`)**:
 *    - Applies zero-turn lossless repairs (`repairedArgs`) when semantic commitment is unambiguous
 *      (e.g., stringified boolean `"false"` -> `false` before truthy coercion bugs, stringified
 *      pagination integers `"25"` -> `25`, stringified optional cursor `"null"` -> `null`, and
 *      accidental markdown code fences around shell commands).
 *    - Soft-holds (`DART_BOUNDARY_HOLD`) when MCP-vs-CLI realization corruption is unsafe to guess
 *      (e.g., CLI flags `"--all --force"` stuffed into structured MCP identifiers/paths, `"undefined"`
 *      or `"[object Object]"` in entity IDs, negative/runaway pagination, or raw MCP JSON/XML envelopes
 *      passed directly to POSIX shell binaries).
 * 2. **Authorization Drift & SERS Data-Minimization Layer (`evaluateAuthorizationDrift`)**:
 *    - Prevents early broad data over-collection (`SELECT *` without `WHERE`/bounded `LIMIT` on
 *      sensitive tables, standalone `printenv`/`env` credential sweeps, `limit > maxBulkLimit`,
 *      wildcard entity dumps, and root/empty-pattern sweeps when Turn-0 schemas are grounded).
 *    - Tracks goal-attested scopes (`inferGoalAttestedScopes`) and multi-step sensitive taint across
 *      turns, guiding drifting calls onto narrow compliant trajectories via Staged Execution-Reflective
 *      Synthesis (`SERS`) prompts and escalating to hard `BLOCK` on credential-store escapes,
 *      tainted outbound exfiltration, or repeated cumulative drift.
 *
 * Pure Node 22 ESM with zero CSO leaks (`INV-GH-06`, `INV-GH-07`).
 */

import { okEnvelope } from '@krusch/toolkit/http';

export const SENSITIVE_SCOPE_DOMAINS = Object.freeze({
  CREDENTIALS_SECRETS: 'CREDENTIALS_SECRETS',
  PII_HR_PAYROLL: 'PII_HR_PAYROLL',
  BILLING_TREASURY: 'BILLING_TREASURY',
  IAM_PRIVILEGE: 'IAM_PRIVILEGE',
  OUTBOUND_DELIVERY: 'OUTBOUND_DELIVERY'
});

export const AUTH_DRIFT_REASON_CODES = Object.freeze({
  DART_BOUNDARY_HOLD: 'DART_BOUNDARY_HOLD',
  AUTHORIZATION_DRIFT_HOLD: 'AUTHORIZATION_DRIFT_HOLD',
  AUTHORIZATION_DRIFT_BLOCK: 'AUTHORIZATION_DRIFT_BLOCK',
  SENSITIVE_CREDENTIAL_STORE: 'SENSITIVE_CREDENTIAL_STORE',
  PATH_TRAVERSAL_ESCAPE: 'PATH_TRAVERSAL_ESCAPE',
  ENV_CREDENTIAL_SWEEP: 'ENV_CREDENTIAL_SWEEP',
  EARLY_DATA_OVERCOLLECTION: 'EARLY_DATA_OVERCOLLECTION',
  UNATTESTED_SENSITIVE_SCOPE: 'UNATTESTED_SENSITIVE_SCOPE',
  TAINTED_OUTBOUND_EXFILTRATION: 'TAINTED_OUTBOUND_EXFILTRATION',
  CUMULATIVE_AUTHORIZATION_DRIFT: 'CUMULATIVE_AUTHORIZATION_DRIFT'
});

const SHELL_TOOL_NAMES = new Set(['bash', 'sh', 'shell', 'run_command', 'exec']);

const SHELL_COMMAND_KEYS = ['command', 'cmd', 'CommandLine', 'commandLine'];

const FREE_TEXT_OR_CODE_KEYS = new Set([
  'content',
  'code',
  'script',
  'python',
  'py',
  'sql',
  'query_sql',
  'command',
  'cmd',
  'CommandLine',
  'commandLine',
  'body',
  'text',
  'message',
  'patch',
  'diff',
  'replacement',
  'assistant_text',
  'assistantText',
  'candidate_answer',
  'candidateAnswer'
]);

const BOOLEAN_FLAG_KEY_RE =
  /^(?:is_[a-z0-9_]+|has_[a-z0-9_]+|is[A-Z][A-Za-z0-9]*|has[A-Z][A-Za-z0-9]*|dry_?run|dryRun|recursive|force|overwrite|append|strict|verbose|quiet|mutating|delete_?all|deleteAll|dump_?all|dumpAll|export_?all|exportAll|include_[a-z0-9_]+|include[A-Z][A-Za-z0-9]*|exclude_[a-z0-9_]+|exclude[A-Z][A-Za-z0-9]*)$/;

const PAGINATION_INT_KEYS = new Set([
  'limit',
  'offset',
  'page',
  'page_size',
  'pageSize',
  'top_k',
  'topK',
  'max_results',
  'maxResults'
]);

const POSITIVE_LIMIT_KEYS = new Set([
  'limit',
  'page_size',
  'pageSize',
  'top_k',
  'topK',
  'max_results',
  'maxResults'
]);

const OPTIONAL_CURSOR_KEYS = new Set([
  'cursor',
  'next_cursor',
  'nextCursor',
  'page_token',
  'pageToken',
  'after',
  'before'
]);

const IDENTIFIER_OR_PATH_KEY_RE =
  /^(?:id|[a-z0-9_]+_id|[a-z][A-Za-z0-9]*Id|path|file_path|filePath|rel_path|relPath|target_path|targetPath|directory|dir|filename|table|collection|bucket|account|username|email)$/;

const PATH_LIKE_KEY_RE =
  /^(?:path|file_path|filePath|rel_path|relPath|target_path|targetPath|directory|dir|filename)$/;

const ENTITY_FILTER_WILDCARD_KEY_RE =
  /^(?:user_id|userId|customer_id|customerId|account_id|accountId|employee_id|employeeId|patient_id|patientId|email|ssn|tax_id|taxId)$/;

const STRINGIFIED_NULL_IDENTIFIER_RE = /^(?:undefined|null|NaN|\[object Object\])$/;

const STRINGIFIED_NULL_OPTIONAL_RE = /^(?:undefined|null|none)$/i;

const CLI_EMBEDDED_LONG_FLAG_RE = /(?:^|\s)--[a-zA-Z][a-zA-Z0-9-]*(?=\s|=|$)/;
const CLI_LEADING_SHORT_FLAG_RE = /^\s*-[a-zA-Z]{1,6}\s+\S+/;

const RAW_MCP_ENVELOPE_IN_SHELL_RE =
  /^\s*(?:<tool_call\b|<function=[A-Za-z0-9_.-]+>|\[\s*\{\s*"(?:tool_name|name)"\s*:|\{\s*"(?:tool_name|name)"\s*:\s*"[^"]+"\s*,\s*"(?:args|arguments|parameters)"\s*:)/i;

const GOAL_SCOPE_PATTERNS = [
  {
    domain: SENSITIVE_SCOPE_DOMAINS.PII_HR_PAYROLL,
    regex:
      /\b(?:payroll|salar(?:y|ies)|compensation|human\s+resources|\bhr\b|ssn|social\s+security|tax\s+withholding|w-?2\b|medical\s+record|patient|hipaa|clinical)\b/i
  },
  {
    domain: SENSITIVE_SCOPE_DOMAINS.BILLING_TREASURY,
    regex:
      /\b(?:billing|invoice|settlement|fee|ledger|wire\s+transfer|refund|payment|merchant|card|treasury|chargeback|bank|iban|ach|payout|transaction)\b/i
  },
  {
    domain: SENSITIVE_SCOPE_DOMAINS.IAM_PRIVILEGE,
    regex:
      /\b(?:iam\b|sudoers|rbac|role\s+binding|admin\s+role|permission\s+grant|privilege|access\s+policy|acl\b)\b/i
  },
  {
    domain: SENSITIVE_SCOPE_DOMAINS.CREDENTIALS_SECRETS,
    regex:
      /\b(?:secret\s+rotation|rotate\s+(?:key|secret|credential|token)|ssh\s+key|credential\s+audit|vault|api\s+key|keystore)\b/i
  },
  {
    domain: SENSITIVE_SCOPE_DOMAINS.OUTBOUND_DELIVERY,
    regex:
      /\b(?:send|email|reply|notify|webhook|slack|post\s+to|forward|dispatch|upload|publish|share|invite)\b/i
  }
];

const HARD_CREDENTIAL_STORE_RE =
  /(?:^|[\\/\s"'=])(?:\.(?:ssh[\\/](?:id_(?:rsa|ed25519|ecdsa|dsa)|authorized_keys)|aws[\\/]credentials|gnupg[\\/]private-keys|netrc|kube[\\/]config)|\/etc\/shadow)(?:$|[\\/\s"'])/i;

const ENV_CREDENTIAL_SHELL_RE =
  /(?:^|&&|\|\||;)\s*(?:printenv|env|export\s+-p|declare\s+-x)\s*(?:\||>|;|$)|\/proc\/(?:self|\d+)\/environ\b/;

const ENV_CREDENTIAL_CODE_DUMP_RE =
  /\b(?:dict\s*\(\s*os\.environ\s*\)|os\.environ\.copy\s*\(\s*\)|JSON\.stringify\s*\(\s*process\.env\b)/;

const ROOT_FILESYSTEM_SWEEP_RE =
  /(?:^|&&|\|\||;)\s*(?:find\s+\/(?:\s+-|(?:etc|root|var|opt|usr)\b)|grep\s+-[a-zA-Z]*r[a-zA-Z]*\s+\S+\s+\/(?:etc|root|var)?(?:\s|$))/;

const EMPTY_PATTERN_REPO_DUMP_RE =
  /(?:^|&&|\|\||;)\s*(?:grep\s+-[a-zA-Z]*r[a-zA-Z]*\s+(?:""|'')|rg\s+(?:""|''))\s*(?:\.|\S+)?\s*(?:\||;|$)/;

const SENSITIVE_BULK_TABLES = new Set([
  'users',
  'user_accounts',
  'accounts',
  'customers',
  'clients',
  'employees',
  'employee_salaries',
  'salaries',
  'payroll',
  'payroll_records',
  'credentials',
  'secrets',
  'api_keys',
  'tokens',
  'sessions',
  'ssn',
  'ssn_records',
  'patients',
  'medical_records',
  'cards',
  'credit_cards',
  'bank_accounts',
  'wire_transfers',
  'private_messages',
  'audit_logs'
]);

const SENSITIVE_DOMAIN_SIGNALS = [
  {
    domain: SENSITIVE_SCOPE_DOMAINS.PII_HR_PAYROLL,
    toolRe: /(?:^|[^a-zA-Z0-9])(?:payroll|salary|salaries|ssn|hr_records|medical_record|patient_chart|tax_return)(?:$|[^a-zA-Z0-9])/i,
    resourceRe: /(?:^|[^a-zA-Z0-9])(?:employee_salaries|payroll(?:_records)?|ssn(?:_records|_registry)?|social_security|medical_records|patient_records|hr_compensation)(?:$|[^a-zA-Z0-9])/i
  },
  {
    domain: SENSITIVE_SCOPE_DOMAINS.IAM_PRIVILEGE,
    toolRe: /(?:^|[^a-zA-Z0-9])(?:grant_admin|iam_policy|escalate_role|set_sudoers|attach_admin_policy)(?:$|[^a-zA-Z0-9])/i,
    resourceRe: /(?:\/etc\/sudoers|(?:^|[^a-zA-Z0-9])(?:iam_policies|admin_role_bindings|sudoers)(?:$|[^a-zA-Z0-9]))/i
  },
  {
    domain: SENSITIVE_SCOPE_DOMAINS.BILLING_TREASURY,
    toolRe: /(?:^|[^a-zA-Z0-9])(?:wire_transfer|ach_payout|export_card_pan|sweep_treasury)(?:$|[^a-zA-Z0-9])/i,
    resourceRe: /(?:^|[^a-zA-Z0-9])(?:credit_card_numbers|raw_cvv|ach_routing_numbers|wire_transfers_secret)(?:$|[^a-zA-Z0-9])/i
  },
  {
    domain: SENSITIVE_SCOPE_DOMAINS.CREDENTIALS_SECRETS,
    toolRe: /(?:^|[^a-zA-Z0-9])(?:dump_secrets|export_vault|list_private_keys|read_keystore)(?:$|[^a-zA-Z0-9])/i,
    resourceRe: /(?:^|[^a-zA-Z0-9])(?:password_hashes|secret_tokens|vault_secrets|private_keys)(?:$|[^a-zA-Z0-9])/i
  }
];

const SHELL_OUTBOUND_EXFIL_RE =
  /\b(?:curl|wget)\b[\s\S]*?(?:-(?:X|--request)\s*(?:POST|PUT|PATCH)|-(?:d|F|--data|--data-binary|--data-raw|--upload-file)\b)|(?:\bnc\b|\bnetcat\b)\s+\S+\s+\d+/i;

const TRIVIAL_SQL_WHERE_RE =
  /\bwhere\s+(?:1\s*=\s*1|true|'1'\s*=\s*'1'|"1"\s*=\s*"1")\s*(?:;|limit\b|order\b|$)/i;

function stripToolNamespace(toolName) {
  let base = String(toolName || '').trim();
  if (!base) return '';
  base = base.replace(/^mcp__(?:[^_]|_(?!_))+__/i, '');
  base = base.replace(/^(?:[A-Za-z0-9_-]+[.:/])+/, '');
  return base;
}

function unwrapOuterShellFence(rawCmd) {
  const trimmed = String(rawCmd ?? '').trim();
  const match = trimmed.match(/^```(?:bash|sh|zsh|shell|console)?[ \t]*\r?\n([\s\S]*?)\r?\n```$/i);
  if (!match) return null;
  const inner = match[1];
  if (inner.includes('```')) {
    return null;
  }
  return inner.trim();
}

function getSchemaPropertyType(toolSchema, key) {
  const prop = toolSchema?.properties?.[key] ?? toolSchema?.inputSchema?.properties?.[key];
  if (!prop || typeof prop !== 'object') return '';
  if (typeof prop.type === 'string') return prop.type.toLowerCase();
  if (Array.isArray(prop.type)) {
    const nonNull = prop.type.find((t) => t !== 'null');
    return typeof nonNull === 'string' ? nonNull.toLowerCase() : '';
  }
  return '';
}

function isReadOrQueryToolName(baseLower) {
  return /^(?:get|list|search|query|read|fetch|find|lookup|select)(?:$|[_-])/.test(baseLower);
}

/**
 * Deterministically infer authorized sensitive domains from the session `goal` and
 * caller-supplied `allowedScopes` (`INV-GH-12`).
 *
 * @param {string} [goal='']
 * @param {string[]} [explicitAllowedScopes=[]]
 * @returns {string[]}
 */
export function inferGoalAttestedScopes(goal = '', explicitAllowedScopes = []) {
  const scopes = new Set();
  const text = String(goal ?? '');

  if (Array.isArray(explicitAllowedScopes)) {
    for (const raw of explicitAllowedScopes) {
      const clean = String(raw ?? '').trim().toUpperCase();
      if (clean) {
        scopes.add(clean);
      }
    }
  }

  for (const entry of GOAL_SCOPE_PATTERNS) {
    if (entry.regex.test(text)) {
      scopes.add(entry.domain);
    }
  }

  return Array.from(scopes).sort();
}

/**
 * DART (`Decoupled Action Realization and Targeted Repair`, `arXiv:2610.34298`):
 * Repairs unambiguous MCP-vs-CLI serialization mismatches in `0` extra turns while
 * holding unsafe CLI-flag-in-MCP or corrupted-identifier boundary defects.
 *
 * @param {object} [options={}]
 * @param {string} [options.toolName='']
 * @param {object} [options.args={}]
 * @param {object|null} [options.toolSchema=null]
 * @returns {{
 *   action: 'ALLOW' | 'HOLD',
 *   repaired: boolean,
 *   repairedArgs: object,
 *   repairs: Array<{ field: string, code: string, from: unknown, to: unknown, message: string }>,
 *   issues: Array<{ field: string, code: string, value: unknown, message: string }>,
 *   correctivePrompt: string | null
 * }}
 */
export function inspectAndRepairDartBoundaries({
  toolName = '',
  args = {},
  toolSchema = null
} = {}) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    return {
      action: 'ALLOW',
      repaired: false,
      repairedArgs: args,
      repairs: [],
      issues: [],
      correctivePrompt: null
    };
  }

  const baseName = stripToolNamespace(toolName);
  const baseLower = baseName.toLowerCase();
  const isShellTool = SHELL_TOOL_NAMES.has(baseLower);
  const isReadQuery = isReadOrQueryToolName(baseLower);

  const repairedArgs = { ...args };
  /** @type {Array<{ field: string, code: string, from: unknown, to: unknown, message: string }>} */
  const repairs = [];
  /** @type {Array<{ field: string, code: string, value: unknown, message: string }>} */
  const issues = [];

  if (isShellTool) {
    for (const cmdKey of SHELL_COMMAND_KEYS) {
      if (typeof repairedArgs[cmdKey] !== 'string') continue;
      const unwrapped = unwrapOuterShellFence(repairedArgs[cmdKey]);
      if (unwrapped !== null && unwrapped !== repairedArgs[cmdKey]) {
        const before = repairedArgs[cmdKey];
        repairedArgs[cmdKey] = unwrapped;
        repairs.push({
          field: cmdKey,
          code: 'STRIPPED_SHELL_MARKDOWN_FENCE',
          from: before,
          to: unwrapped,
          message: `Stripped outer markdown code fence around shell "${cmdKey}".`
        });
      }

      if (RAW_MCP_ENVELOPE_IN_SHELL_RE.test(repairedArgs[cmdKey])) {
        issues.push({
          field: cmdKey,
          code: 'MCP_JSON_PAYLOAD_IN_POSIX_CLI',
          value: repairedArgs[cmdKey].slice(0, 120),
          message: `Shell parameter "${cmdKey}" contains a serialized MCP tool-call envelope instead of a valid POSIX command.`
        });
      }
    }
  }

  for (const [key, val] of Object.entries(repairedArgs)) {
    if (FREE_TEXT_OR_CODE_KEYS.has(key)) {
      continue;
    }

    const schemaType = getSchemaPropertyType(toolSchema, key);

    // 1. Boolean string coercion ("false" -> false prevents JS truthy inversion)
    if (
      typeof val === 'string'
      && (schemaType === 'boolean' || BOOLEAN_FLAG_KEY_RE.test(key))
    ) {
      const trimmedLower = val.trim().toLowerCase();
      if (trimmedLower === 'true' || trimmedLower === 'false') {
        const boolVal = trimmedLower === 'true';
        repairedArgs[key] = boolVal;
        repairs.push({
          field: key,
          code: 'COERCED_BOOLEAN_STRING',
          from: val,
          to: boolVal,
          message: `Coerced stringified boolean "${val}" on "${key}" to ${String(boolVal)}.`
        });
        continue;
      }
    }

    // 2. Pagination & integer boundary repair / hold
    if (schemaType === 'integer' || PAGINATION_INT_KEYS.has(key)) {
      if (typeof val === 'number') {
        if (!Number.isFinite(val) || val < 0 || !Number.isInteger(val)) {
          issues.push({
            field: key,
            code: 'INVALID_PAGINATION_BOUND',
            value: val,
            message: `Parameter "${key}" must be a non-negative integer (received ${String(val)}).`
          });
          continue;
        }
        if (val === 0 && POSITIVE_LIMIT_KEYS.has(key) && isReadQuery) {
          issues.push({
            field: key,
            code: 'INVALID_PAGINATION_BOUND',
            value: val,
            message: `Parameter "${key}" resolved to 0 on query tool "${baseName}"; pass a positive integer limit.`
          });
          continue;
        }
      } else if (typeof val === 'string') {
        const trimmed = val.trim();
        if (/^\d+$/.test(trimmed)) {
          const parsedInt = Number.parseInt(trimmed, 10);
          if (parsedInt === 0 && POSITIVE_LIMIT_KEYS.has(key) && isReadQuery) {
            issues.push({
              field: key,
              code: 'INVALID_PAGINATION_BOUND',
              value: val,
              message: `Parameter "${key}" resolved to 0 on query tool "${baseName}"; pass a positive integer limit.`
            });
            continue;
          }
          repairedArgs[key] = parsedInt;
          repairs.push({
            field: key,
            code: 'COERCED_INTEGER_PAGINATION',
            from: val,
            to: parsedInt,
            message: `Coerced stringified integer "${val}" on "${key}" to ${parsedInt}.`
          });
          continue;
        }
        if (PAGINATION_INT_KEYS.has(key)) {
          issues.push({
            field: key,
            code: 'INVALID_PAGINATION_BOUND',
            value: val,
            message: `Pagination parameter "${key}" expects a non-negative integer, not "${val}".`
          });
          continue;
        }
      }
    }

    // 3. Optional cursor stringified nullish repair ("null" / "undefined" / "None" -> null)
    if (typeof val === 'string' && OPTIONAL_CURSOR_KEYS.has(key)) {
      if (STRINGIFIED_NULL_OPTIONAL_RE.test(val.trim())) {
        repairedArgs[key] = null;
        repairs.push({
          field: key,
          code: 'CLEARED_STRINGIFIED_NULL_OPTIONAL',
          from: val,
          to: null,
          message: `Normalized stringified null sentinel "${val}" on optional cursor "${key}" to null.`
        });
        continue;
      }
    }

    // 4. Required / entity identifier & path corruption checks
    if (typeof val === 'string' && IDENTIFIER_OR_PATH_KEY_RE.test(key)) {
      const trimmed = val.trim();
      if (STRINGIFIED_NULL_IDENTIFIER_RE.test(trimmed)) {
        issues.push({
          field: key,
          code: 'STRINGIFIED_NULL_IDENTIFIER',
          value: val,
          message: `Identifier/path parameter "${key}" contains serialized sentinel "${val}" instead of a concrete resource identifier.`
        });
        continue;
      }

      if (
        CLI_EMBEDDED_LONG_FLAG_RE.test(trimmed)
        || CLI_LEADING_SHORT_FLAG_RE.test(trimmed)
      ) {
        issues.push({
          field: key,
          code: 'CLI_FLAGS_IN_MCP_IDENTIFIER',
          value: val,
          message: `Structured MCP parameter "${key}" contains CLI option flags ("${val}"). Pass only the clean identifier/path and set options via structured JSON fields.`
        });
      }
    }
  }

  if (issues.length > 0) {
    const correctivePrompt =
      `DART interface realization hold on "${baseName || toolName}": `
      + `${issues.map((i) => i.message).join(' ')} `
      + `Re-invoke "${baseName || toolName}" using clean schema-typed arguments while preserving your original task intent.`;

    return {
      action: 'HOLD',
      repaired: repairs.length > 0,
      repairedArgs,
      repairs,
      issues,
      correctivePrompt
    };
  }

  return {
    action: 'ALLOW',
    repaired: repairs.length > 0,
    repairedArgs,
    repairs,
    issues: [],
    correctivePrompt: null
  };
}

function normalizePriorDriftState(raw) {
  const safe = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const tainted = Array.isArray(safe.taintedDomains)
    ? Array.from(new Set(safe.taintedDomains.map((d) => String(d ?? '')).filter(Boolean)))
    : [];
  return {
    driftScore: Number.isFinite(Number(safe.driftScore)) ? Math.max(0, Number(safe.driftScore)) : 0,
    overcollectionCount: Number.isFinite(Number(safe.overcollectionCount))
      ? Math.max(0, Math.trunc(Number(safe.overcollectionCount)))
      : 0,
    scopeViolations: Number.isFinite(Number(safe.scopeViolations))
      ? Math.max(0, Math.trunc(Number(safe.scopeViolations)))
      : 0,
    taintedDomains: tainted
  };
}

function extractSqlStrings(toolName, args) {
  const sqlList = [];
  if (!args || typeof args !== 'object') return sqlList;

  for (const key of ['sql', 'query_sql', 'statement']) {
    if (typeof args[key] === 'string' && args[key].trim()) {
      sqlList.push(args[key]);
    }
  }

  const baseLower = stripToolNamespace(toolName).toLowerCase();
  if (
    typeof args.query === 'string'
    && /^\s*(?:select|with|insert|update|delete)\b/i.test(args.query)
  ) {
    sqlList.push(args.query);
  }

  for (const cmdKey of SHELL_COMMAND_KEYS) {
    if (typeof args[cmdKey] === 'string' && /\bselect\s+/i.test(args[cmdKey])) {
      sqlList.push(args[cmdKey]);
    }
  }

  if (SHELL_TOOL_NAMES.has(baseLower)) {
    for (const key of ['code', 'python', 'py']) {
      if (typeof args[key] === 'string' && /\bselect\s+/i.test(args[key])) {
        sqlList.push(args[key]);
      }
    }
  }

  return sqlList;
}

function inspectSqlOvercollection(sqlText, maxBulkLimit) {
  const issues = [];
  const touchedSensitiveTables = [];

  for (const match of sqlText.matchAll(/\blimit\s+(\d+)\b/gi)) {
    const limitVal = Number.parseInt(match[1], 10);
    if (Number.isFinite(limitVal) && limitVal > maxBulkLimit) {
      issues.push({
        code: AUTH_DRIFT_REASON_CODES.EARLY_DATA_OVERCOLLECTION,
        message: `SQL query requests LIMIT ${limitVal} exceeding session data-minimization cap (${maxBulkLimit}).`
      });
    }
  }

  for (const match of sqlText.matchAll(/\bselect\s+\*\s+from\s+["'`]?([a-zA-Z0-9_]+)["'`]?/gi)) {
    const tableName = String(match[1] || '').toLowerCase();
    if (!SENSITIVE_BULK_TABLES.has(tableName)) {
      continue;
    }
    touchedSensitiveTables.push(tableName);

    const hasWhere = /\bwhere\b/i.test(sqlText) && !TRIVIAL_SQL_WHERE_RE.test(sqlText);
    const limitMatch = sqlText.match(/\blimit\s+(\d+)\b/i);
    const hasBoundedLimit =
      limitMatch !== null && Number.parseInt(limitMatch[1], 10) <= maxBulkLimit;

    if (!hasWhere && !hasBoundedLimit) {
      issues.push({
        code: AUTH_DRIFT_REASON_CODES.EARLY_DATA_OVERCOLLECTION,
        table: tableName,
        message: `Unscoped "SELECT * FROM ${tableName}" over-collects full sensitive records without a constraining WHERE clause or bounded LIMIT <= ${maxBulkLimit}.`
      });
    }
  }

  return { issues, touchedSensitiveTables };
}

function buildGroundedPathSet(groundedFiles = {}) {
  const set = new Set();
  if (!groundedFiles || typeof groundedFiles !== 'object') return set;
  const entries = Array.isArray(groundedFiles) ? groundedFiles : Object.keys(groundedFiles);
  for (const raw of entries) {
    const clean = String(raw || '').replace(/^\.?\//, '').trim();
    if (clean) {
      set.add(clean);
    }
  }
  return set;
}

/**
 * Evaluate a tool call for multi-step Authorization Drift & Early Broad Data Over-Collection
 * (`arXiv:2611.09113`), returning `ALLOW`, `HOLD` (with a SERS data-minimization prompt), or `BLOCK`.
 *
 * @param {object} [options={}]
 * @returns {{
 *   decision: 'ALLOW' | 'HOLD' | 'BLOCK',
 *   code: string | null,
 *   issues: Array<{ code: string, message: string, domain?: string }>,
 *   attestedScopes: string[],
 *   touchedSensitiveDomains: string[],
 *   nextDriftState: {
 *     driftScore: number,
 *     overcollectionCount: number,
 *     scopeViolations: number,
 *     taintedDomains: string[]
 *   },
 *   correctivePrompt: string | null
 * }}
 */
export function evaluateAuthorizationDrift({
  toolName = '',
  args = {},
  isMutating = false,
  isOutbound = false,
  step = 0,
  goal = '',
  allowedScopes = [],
  groundedFiles = {},
  hasTurnZeroGrounding = false,
  priorDriftState = null,
  maxBulkLimit = 1000,
  blockScoreThreshold = 3
} = {}) {
  const safeArgs = args && typeof args === 'object' && !Array.isArray(args) ? args : {};
  const baseName = stripToolNamespace(toolName);
  const baseLower = baseName.toLowerCase();
  const isShellTool = SHELL_TOOL_NAMES.has(baseLower);
  const explicitScopesUpper = new Set(
    (Array.isArray(allowedScopes) ? allowedScopes : [])
      .map((s) => String(s ?? '').trim().toUpperCase())
      .filter(Boolean)
  );
  const attestedList = inferGoalAttestedScopes(goal, allowedScopes);
  const attestedSet = new Set(attestedList);
  const groundedPathSet = buildGroundedPathSet(groundedFiles);
  const state = normalizePriorDriftState(priorDriftState);
  const effectiveMaxBulk =
    Number.isFinite(Number(maxBulkLimit)) && Number(maxBulkLimit) > 0
      ? Math.trunc(Number(maxBulkLimit))
      : 1000;

  /** @type {Array<{ code: string, message: string, domain?: string }>} */
  const issues = [];
  const touchedDomains = new Set();
  let hardBlock = false;
  let scoreDelta = 0;
  let overcollectionDelta = 0;
  let scopeViolationDelta = 0;

  const commandStr = SHELL_COMMAND_KEYS.map((k) =>
    typeof safeArgs[k] === 'string' ? safeArgs[k] : ''
  ).find(Boolean) || '';

  const serializedNonContentArgs = JSON.stringify(
    Object.fromEntries(
      Object.entries(safeArgs).filter(([k]) => k !== 'content' && k !== 'replacement' && k !== 'patch' && k !== 'diff')
    )
  ) || '';

  // 1. Hard Credential Store Escape (requires explicit allowedScopes override)
  if (
    !explicitScopesUpper.has(SENSITIVE_SCOPE_DOMAINS.CREDENTIALS_SECRETS)
    && (HARD_CREDENTIAL_STORE_RE.test(serializedNonContentArgs) || HARD_CREDENTIAL_STORE_RE.test(commandStr))
  ) {
    hardBlock = true;
    scoreDelta += 3;
    scopeViolationDelta += 1;
    touchedDomains.add(SENSITIVE_SCOPE_DOMAINS.CREDENTIALS_SECRETS);
    issues.push({
      code: AUTH_DRIFT_REASON_CODES.SENSITIVE_CREDENTIAL_STORE,
      domain: SENSITIVE_SCOPE_DOMAINS.CREDENTIALS_SECRETS,
      message: `Tool "${baseName || toolName}" attempted to access a protected credential/identity store outside authorized session scope.`
    });
  }

  // 2. Path Traversal Scope Escape on structured path parameters
  for (const [key, val] of Object.entries(safeArgs)) {
    if (typeof val !== 'string' || !PATH_LIKE_KEY_RE.test(key)) continue;
    const normPath = val.trim();
    if (/^(?:\.\.[\\/]){2,}|[\\/](?:\.\.[\\/]){2,}/.test(normPath)) {
      scoreDelta += 1.5;
      scopeViolationDelta += 1;
      if (/\/etc\/|\.(?:ssh|aws|gnupg)\b/i.test(normPath)) {
        hardBlock = true;
      }
      issues.push({
        code: AUTH_DRIFT_REASON_CODES.PATH_TRAVERSAL_ESCAPE,
        message: `Path argument "${key}" ("${normPath}") traverses multiple parent directories outside the grounded workspace.`
      });
    }
  }

  // 3. Unscoped Process Environment Credential Sweep
  const codeText = String(safeArgs.code ?? safeArgs.python ?? safeArgs.py ?? safeArgs.script ?? '');
  if (
    !attestedSet.has(SENSITIVE_SCOPE_DOMAINS.CREDENTIALS_SECRETS)
    && (
      (isShellTool && ENV_CREDENTIAL_SHELL_RE.test(commandStr))
      || ENV_CREDENTIAL_CODE_DUMP_RE.test(codeText)
      || ENV_CREDENTIAL_CODE_DUMP_RE.test(commandStr)
    )
  ) {
    scoreDelta += 1.5;
    overcollectionDelta += 1;
    touchedDomains.add(SENSITIVE_SCOPE_DOMAINS.CREDENTIALS_SECRETS);
    issues.push({
      code: AUTH_DRIFT_REASON_CODES.ENV_CREDENTIAL_SWEEP,
      domain: SENSITIVE_SCOPE_DOMAINS.CREDENTIALS_SECRETS,
      message: 'Dumping the entire process environment sweeps unrelated credentials into context; read only specific required configuration keys.'
    });
  }

  // 4. Early Broad Data Over-Collection (SQL, structured bulk limits, wildcards, grounded root sweeps)
  for (const sqlText of extractSqlStrings(toolName, safeArgs)) {
    const sqlAudit = inspectSqlOvercollection(sqlText, effectiveMaxBulk);
    if (sqlAudit.issues.length > 0) {
      overcollectionDelta += 1;
      scoreDelta += 1;
      issues.push(...sqlAudit.issues);
    }
  }

  for (const [key, val] of Object.entries(safeArgs)) {
    if (POSITIVE_LIMIT_KEYS.has(key) && typeof val === 'number' && val > effectiveMaxBulk) {
      overcollectionDelta += 1;
      scoreDelta += 1;
      issues.push({
        code: AUTH_DRIFT_REASON_CODES.EARLY_DATA_OVERCOLLECTION,
        message: `Parameter "${key}=${val}" exceeds session data-minimization cap (${effectiveMaxBulk}).`
      });
    }

    if (
      val === true
      && /^(?:dump_?all|export_?all|include_all_users|includeAllUsers|all_records|allRecords)$/.test(key)
    ) {
      overcollectionDelta += 1;
      scoreDelta += 1;
      issues.push({
        code: AUTH_DRIFT_REASON_CODES.EARLY_DATA_OVERCOLLECTION,
        message: `Bulk dump flag "${key}=true" violates data minimization; request only records matching the task goal.`
      });
    }

    if (
      typeof val === 'string'
      && ENTITY_FILTER_WILDCARD_KEY_RE.test(key)
      && (val.trim() === '*' || val.trim() === '%')
    ) {
      overcollectionDelta += 1;
      scoreDelta += 1;
      issues.push({
        code: AUTH_DRIFT_REASON_CODES.EARLY_DATA_OVERCOLLECTION,
        message: `Wildcard entity selector "${key}=${val}" sweeps all records instead of targeting the authorized entity.`
      });
    }
  }

  if (isShellTool && commandStr) {
    if (ROOT_FILESYSTEM_SWEEP_RE.test(commandStr)) {
      overcollectionDelta += 1;
      scoreDelta += 1.5;
      issues.push({
        code: AUTH_DRIFT_REASON_CODES.EARLY_DATA_OVERCOLLECTION,
        message: 'Root/system-wide filesystem crawl exceeds workspace boundary; restrict search paths to the active project directory.'
      });
    } else if (hasTurnZeroGrounding && Number(step) <= 3 && EMPTY_PATTERN_REPO_DUMP_RE.test(commandStr)) {
      overcollectionDelta += 1;
      scoreDelta += 1;
      issues.push({
        code: AUTH_DRIFT_REASON_CODES.EARLY_DATA_OVERCOLLECTION,
        message: 'Workspace schemas and file digests are already grounded at Turn 0; pass a specific symbol or pattern instead of dumping every line.'
      });
    }
  }

  // 5. Unattested Sensitive Scope Creep (skip files already attested in Turn-0 workspace digests)
  const targetRelPath = String(
    safeArgs.relPath ?? safeArgs.rel_path ?? safeArgs.path ?? safeArgs.file_path ?? ''
  ).replace(/^\.?\//, '').trim();
  const isKnownGroundedWorkspaceFile =
    Boolean(targetRelPath) && groundedPathSet.has(targetRelPath);

  if (!isKnownGroundedWorkspaceFile) {
    for (const sig of SENSITIVE_DOMAIN_SIGNALS) {
      const matchedTool = sig.toolRe.test(baseName);
      const matchedResource = sig.resourceRe.test(serializedNonContentArgs);
      if (!matchedTool && !matchedResource) continue;

      touchedDomains.add(sig.domain);
      if (!attestedSet.has(sig.domain)) {
        scopeViolationDelta += 1;
        scoreDelta += 1.5;
        issues.push({
          code: AUTH_DRIFT_REASON_CODES.UNATTESTED_SENSITIVE_SCOPE,
          domain: sig.domain,
          message: `Tool "${baseName || toolName}" accesses sensitive domain ${sig.domain}, which is not attested in the task goal or allowedScopes.`
        });
      }
    }
  }

  // 6. Cross-Step Sensitive Taint -> Outbound Exfiltration Gate
  const isEffectiveOutbound =
    Boolean(isOutbound)
    || (isShellTool && SHELL_OUTBOUND_EXFIL_RE.test(commandStr));
  const priorHasSensitiveTaint =
    state.taintedDomains.length > 0 || state.scopeViolations > 0;

  if (
    isEffectiveOutbound
    && priorHasSensitiveTaint
    && !attestedSet.has(SENSITIVE_SCOPE_DOMAINS.OUTBOUND_DELIVERY)
  ) {
    hardBlock = true;
    scoreDelta += 3;
    scopeViolationDelta += 1;
    issues.push({
      code: AUTH_DRIFT_REASON_CODES.TAINTED_OUTBOUND_EXFILTRATION,
      domain: SENSITIVE_SCOPE_DOMAINS.OUTBOUND_DELIVERY,
      message: `Blocked outbound transmission via "${baseName || toolName}" after session touched sensitive scope(s) [${state.taintedDomains.join(', ') || 'RESTRICTED'}] without outbound delivery authorization.`
    });
  }

  const mergedTainted = Array.from(
    new Set([...state.taintedDomains, ...Array.from(touchedDomains)])
  ).sort();
  const nextDriftScore = Number((state.driftScore + scoreDelta).toFixed(2));
  const nextDriftState = {
    driftScore: nextDriftScore,
    overcollectionCount: state.overcollectionCount + overcollectionDelta,
    scopeViolations: state.scopeViolations + scopeViolationDelta,
    taintedDomains: mergedTainted
  };

  if (issues.length === 0) {
    return {
      decision: 'ALLOW',
      code: null,
      issues: [],
      attestedScopes: attestedList,
      touchedSensitiveDomains: Array.from(touchedDomains),
      nextDriftState,
      correctivePrompt: null
    };
  }

  const escalatedByCumulativeDrift =
    !hardBlock
    && state.driftScore > 0
    && nextDriftScore >= Number(blockScoreThreshold || 3);

  const primaryCode = escalatedByCumulativeDrift
    ? AUTH_DRIFT_REASON_CODES.CUMULATIVE_AUTHORIZATION_DRIFT
    : issues[0].code;
  const finalDecision = hardBlock || escalatedByCumulativeDrift ? 'BLOCK' : 'HOLD';

  const sersGuidance =
    finalDecision === 'BLOCK'
      ? `Hard boundary enforced (${primaryCode}): ${issues.map((i) => i.message).join(' ')} Proceed strictly within authorized workspace resources or abstain if the user goal requires elevated permission.`
      : `Authorization drift hold (SERS data minimization, score=${nextDriftScore}): ${issues.map((i) => i.message).join(' ')} Rewrite your "${baseName || toolName}" call along the minimal compliant path: project explicit columns, add a goal-specific WHERE/filter and bounded LIMIT <= ${effectiveMaxBulk}, and restrict access to goal-attested scopes${isMutating ? ' before mutating state' : ''}.`;

  return {
    decision: finalDecision,
    code: primaryCode,
    issues,
    attestedScopes: attestedList,
    touchedSensitiveDomains: Array.from(touchedDomains),
    nextDriftState,
    correctivePrompt: sersGuidance
  };
}

/**
 * Convenience envelope wrapper auditing a batch trajectory of tool calls for Authorization Drift
 * and DART MCP-vs-CLI realization issues (`INV-GH-06`, `INV-GH-12`).
 *
 * @param {object} [options={}]
 */
export function auditTrajectoryAuthorizationDrift({
  goal = '',
  allowedScopes = [],
  groundedFiles = {},
  hasTurnZeroGrounding = false,
  maxBulkLimit = 1000,
  calls = []
} = {}) {
  let driftState = {
    driftScore: 0,
    overcollectionCount: 0,
    scopeViolations: 0,
    taintedDomains: []
  };
  const stepVerdicts = [];
  let dartRepairsCount = 0;
  let dartHoldsCount = 0;
  let authDriftHoldsCount = 0;
  let authDriftBlocksCount = 0;

  const safeCalls = Array.isArray(calls) ? calls : [];
  for (let idx = 0; idx < safeCalls.length; idx += 1) {
    const item = safeCalls[idx] || {};
    const toolName = String(item.tool_name ?? item.toolName ?? item.name ?? '');
    const rawArgs = item.args ?? item.arguments ?? {};
    const stepNum = item.step ?? idx + 1;

    const dart = inspectAndRepairDartBoundaries({
      toolName,
      args: rawArgs,
      toolSchema: item.toolSchema ?? null
    });
    if (dart.repaired) {
      dartRepairsCount += dart.repairs.length;
    }
    if (dart.action === 'HOLD') {
      dartHoldsCount += 1;
      stepVerdicts.push({
        step: stepNum,
        toolName,
        decision: 'HOLD',
        reason: AUTH_DRIFT_REASON_CODES.DART_BOUNDARY_HOLD,
        dart,
        drift: null
      });
      continue;
    }

    const drift = evaluateAuthorizationDrift({
      toolName,
      args: dart.repairedArgs,
      isMutating: Boolean(item.isMutating ?? item.mutating ?? false),
      isOutbound: Boolean(item.isOutbound ?? false),
      step: stepNum,
      goal,
      allowedScopes,
      groundedFiles,
      hasTurnZeroGrounding,
      priorDriftState: driftState,
      maxBulkLimit
    });
    driftState = drift.nextDriftState;

    if (drift.decision === 'HOLD') {
      authDriftHoldsCount += 1;
    } else if (drift.decision === 'BLOCK') {
      authDriftBlocksCount += 1;
    }

    stepVerdicts.push({
      step: stepNum,
      toolName,
      decision: drift.decision,
      reason:
        drift.decision === 'ALLOW'
          ? 'ALLOWED'
          : drift.decision === 'BLOCK'
            ? AUTH_DRIFT_REASON_CODES.AUTHORIZATION_DRIFT_BLOCK
            : AUTH_DRIFT_REASON_CODES.AUTHORIZATION_DRIFT_HOLD,
      dart,
      drift
    });
  }

  return okEnvelope(
    'krusch_audit_auth_drift',
    `Audited ${safeCalls.length} tool call(s): ${dartRepairsCount} DART repair(s), ${dartHoldsCount} DART hold(s), ${authDriftHoldsCount} drift hold(s), ${authDriftBlocksCount} drift block(s)`,
    {
      attestedScopes: inferGoalAttestedScopes(goal, allowedScopes),
      finalDriftState: driftState,
      counts: {
        totalCalls: safeCalls.length,
        dartRepairsCount,
        dartHoldsCount,
        authDriftHoldsCount,
        authDriftBlocksCount
      },
      stepVerdicts
    }
  );
}
