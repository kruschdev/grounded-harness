# Krusch Grounded Harness (`krusch-grounded-harness` v0.2.0) — Specification

> **STATUS**: `FROZEN` (`2026-11-02`, `v0.2.0`)
> **Archetype**: `node-api-sqlite` + `@krusch/toolkit/mcp` + `@krusch/toolkit/grounded-harness`
> **Port**: `3782` (HTTP Control Gateway) + `stdio` MCP Server (`7` 4-boolean annotated tools)

---

## 1. Problem Statement & Empirical Motivation

Across multi-model evaluations (`DolphinBench` 600-task 19-run / 11,400-trace matrix, `DABstep` 120-episode multi-step data analytics, `BEAM` 100K–10M episodic memory, and `BFCL v3` 64-tool live hub), six empirical findings govern low-tool-call agentic harnesses:

1. **Turn-0 Schema + `Raw-RAG` Briefing Drives Lift & Cost Collapse**: Un-grounded ReAct loops spend `60%–75%` of tool calls blindly discovering file trees, CSV/JSON/SQLite schemas, and documentation rules (`6.8` vs. `2.4` steps on `DABstep`; `3.92x` lower cost and `2.54x` speedup on `gemini-4-argon`). Explicitly flagging **CSV `"NA"` string literals** (`keep_default_na=False`) and **JSON `null` vs. empty-list `[]` wildcards** at Turn 0 eliminates silent join/filter bugs before Step 1.
2. **Scale-Aware Diminishing Returns of Outer Thinking Steps**:
   - **Small Models (`< 15B` active without native reasoning)** benefit from `[PLAN -> BIND -> ACT]` variable binding, placeholder/date soft-holds, and single-retry draft rescue.
   - **Mid-Scale & Frontier/Reasoning Models (`>= 15B` dense, `31B–120B`, or native `thinking`)** achieve 1-shot competence once grounded. Unconditional 2PC stop-nudges (`TWO_PHASE_UNOBSERVED_COMMIT`, `IMPERATIVE_GOAL_ZERO_MUTATION`) add `+10%` to `+62.5%` steps and induce self-doubt regressions (`-0.83 pp` on `DolphinBench`).
3. **Zero-Turn *Defect-Only* Output Gate Replaces `2PC` Stop-Nudges**: Objective output defect checks (`""`/`None`/`null`/`NaN`/`[]`/`{}` bailout, `MAX_TOKENS`/`MALFORMED_FUNCTION_CALL` truncation, leaked `<tool_call>` tags, and raw `DataFrame`/`np.float64` reprs) cost **`0` extra turns when healthy** while preventing silent `0`-point exits across all tiers.
4. **Comment/Whitespace-Normalized Call Hashing (`BLOCK_SPIN_LOOP`) & `maxReadStreak = 0`**: Normalizing comments and whitespace before hashing blocks duplicate spin loops (`-22.3%` cost on `flash-lite`, `0` false positives) while never throttling distinct multi-step read chains (`maxReadStreak === 0`).
5. **Gemini `functionCallingConfig: { mode: "NONE" }` on Tool-Less Loops**: Automatically injecting `toolConfig: { functionCallingConfig: { mode: 'NONE' } }` when `tools` is omitted or empty eliminates `100%` of Gemini 3.5/4 `MALFORMED_FUNCTION_CALL` empty turns on markdown ```` ```py ```` code blocks.
6. **Partial `stdout` Preservation on Sandbox Timeouts**: Returning partial `stdout` emitted prior to timeout alongside `TimeoutError` (while clearing stale `finalAnswer`) lets models diagnose slow loops in 1 turn instead of flying blind.

---

## 2. Non-Negotiable Invariants (`INV-GH-01` .. `INV-GH-10`)

- **`INV-GH-01` (Zero-LLM Turn-0 Grounding & Dataset Hazard Flags)**: `compileTurnZeroGrounding` and `introspectWorkspaceSchemas` MUST introspect workspaces (CSV/TSV RFC-4180 schemas, JSON/JSONL keys, read-only SQLite DDL & row counts, source code symbol headers, and `.md`/`.txt` docs via `256/32`-token `createRawRagIndex`) with **`llmIngestionCalls === 0`** within `maxGroundingTokens` (default `3200`). Delimited introspection MUST detect literal `"NA"` / `"N/A"` tokens (`hasLiteralNaString: true`, `naHazardColumns`) without discarding `"NA"` string values as empty cells, emitting a `keep_default_na=False` hazard notice in `schemaSummaryText`. JSON/JSONL object-array introspection MUST track `hasNull` and `hasEmptyArray` (`[]`) per key (`nullFields`, `emptyArrayFields`, `wildcardCandidateFields`) and emit a `null` / `[]` wildcard notice in `schemaSummaryText`.
- **`INV-GH-02` (Bit-Perfect KV-Cache Prefix Stability)**: System prompts, standing invariants, static workspace schemas, and pinned tool definitions MUST be normalized via `normalizePromptCachePrefix` (`@krusch/toolkit/harness-engineering`), yielding an identical 64-char SHA-256 `prefixHash` across turns/tasks when workspace schemas and tools are unchanged.
- **`INV-GH-03` (Scale-Aware Thinking & Verification Curve)**: `resolveScaleProfile` MUST deterministically map `(model, activeParamsB, totalParamsB, thinkingEnabled)` into three monotonic profiles:
  1. `SMALL_MODEL` (`< 15B` active & `!thinkingEnabled`): `injectPlanBindStep: true`, `softHoldPlaceholdersAndDates: true`, `rescueSerializedToolCalls: true`, `maxMechanicalVerifyNudges: 1`.
  2. `MID_MODEL` (`15B <= params < 70B` & `!thinkingEnabled`, or `>= 15B` total MoE default): `injectPlanBindStep: false`, `softHoldPlaceholdersAndDates: false`, `rescueSerializedToolCalls: true`, `maxMechanicalVerifyNudges: 0`.
  3. `FRONTIER_REASONING` (`>= 70B` total OR `thinkingEnabled === true` OR frontier reasoning model family): `injectPlanBindStep: false`, `softHoldPlaceholdersAndDates: false`, `rescueSerializedToolCalls: false`, `maxMechanicalVerifyNudges: 0`.
  Note: `ScaleProfile.rescueSerializedToolCalls` reflects proactive scale-tier metadata (`false` on `FRONTIER_REASONING`), whereas `inspectOutputDefects` (`INV-GH-05`) acts as a universal zero-turn-when-healthy output-defect gate across all tiers unless `enableOutputDefectGate === false`.
- **`INV-GH-04` (Deferred BM25 Tool Bridge, Normalized Spin-Loop Hashing & `maxReadStreak === 0`)**: Tool sets exceeding `deferThreshold` (default `12`) MUST collapse via `createDeferredToolBridge`. `normalizeCodeSnippetForHash` MUST strip language-appropriate comments outside string literals while preserving Python `//` floor division and indentation. `canonicalizeToolCallKey` MUST normalize code/SQL/shell arguments before SHA-256 hashing. First repeats of `COMMITTED` reads return `MEMOIZED_PRIOR_READ` with cached preview; repeat identical `FAILED` calls, repeat calls after `MEMOIZED_PRIOR_READ`, or calls with `blockSpinLoop: true` return `BLOCK_SPIN_LOOP` (`spinLoopsBlocked`) with `0` tool re-executions. `maxReadStreak` MUST equal `0` (distinct reads are never throttled).
- **`INV-GH-05` (Passive Safety Floor, Staged-Diff-Only `FORCE_VERIFY` & Zero-Turn Defect-Only Output Gate)**: Every tool call MUST pass `createFrozenPolicyFloor`, secret-leak scanning (`SECRET_LEAK_BLOCKED`), `evaluateTruncationPoisoningGuard`, and duplicate-write prevention (`BLOCK_DUPLICATE_WRITE`). `FORCE_VERIFY` MUST trigger **strictly when `pendingDiffsCount > 0 && !latestVerificationPassed`**. `inspectOutputDefects` (`enableOutputDefectGate !== false`, `maxDefectRetries = 1`) MUST pass healthy outputs in `0` extra turns and block stop ONLY on objective defects: (a) `EMPTY_OR_NULL_BAILOUT` (`""`, `None`, `null`, `NaN`, `[]`, `{}` when an answer is expected, never blocking `"0"`, `0`, `false`, `"Not Applicable"`, or `"N/A"`), (b) `TRUNCATED_OUTPUT` (`MAX_TOKENS`, `length`, `MALFORMED_FUNCTION_CALL`, or `truncatedToolCalls`), (c) `SERIALIZED_TOOL_CALL_IN_TEXT` when `toolCalls.length === 0`, and (d) `RAW_DATAFRAME_OR_NUMPY_REPR` outside markdown code spans/fences or in `candidateAnswer`. Policy abstentions MUST NEVER be nudged (`enforceZeroMutationImperativeNudge === false`, `enforceTwoPhaseAnalyticalNudge === false`).
- **`INV-GH-06` (Lego & Universal Envelope Contract)**: Every public method, HTTP endpoint, and MCP tool MUST use `@krusch/toolkit` bricks returning `{ ok: boolean, tool: string, summary: string, data: object }`. `krusch-lego audit` MUST report `0` findings.
- **`INV-GH-07` (CSO Zero-Leak Sanitization)**: Zero hardcoded private LAN/10GbE/Tailscale IPs, zero host `/home/<user>` or `/mnt/<volume>` paths, zero internal node hostnames, and Git attribution strictly `kruschdev <kruschdev@users.noreply.github.com>`.
- **`INV-GH-08` (Legacy 2PC Nudge Deprecation)**: `action-harness-engine.js` and `DABstep` runners phase out forced `IMPERATIVE_GOAL_ZERO_MUTATION`, default `max_read_streak` cutoffs, and `TWO_PHASE_UNOBSERVED_COMMIT` stop-nudges.
- **`INV-GH-09` (Gemini Tool-Less `functionCallingConfig: { mode: 'NONE' }` Guard)**: `buildGeminiPayload` (`@krusch/toolkit/llm`) and `buildSafeGeminiToolConfig` MUST automatically set `toolConfig: { functionCallingConfig: { mode: 'NONE' } }` whenever `tools` is omitted or empty `[]` (unless caller passes an explicit `toolConfig` or `disableAutoToolConfigNone === true`).
- **`INV-GH-10` (Partial `stdout` Preservation on Sandbox/Subprocess Timeouts)**: `execCommandWithPartialStdout` (`krusch-grounded-harness`), `runAsyncWithPartialStdout` & `formatTimeoutWithPartialStdout` (`@krusch/toolkit/grounded-harness`), and `recordToolOutcome` (`timedOut: true`) MUST preserve partial `stdout` emitted prior to timeout while clearing `finalAnswer: null` and `hasFinalAnswer: false`.
- **`INV-GH-11` (Meta-Harness Failure-Trace Rule Synthesis & Holdout Replay Gate)**: `evolveRulesFromTraces` and `verifyCandidateRulesOnTraces` (`src/trace-rule-synthesizer.js`) MUST mine failure trajectories (`PSEUDO_COMPLETION_ECHO_LOOP`, `IDEMPOTENT_ROLLBACK_BLOCKED`, `TEMP_CLEANUP_FALSE_DIFF`, `INLINE_VERIFICATION_UNRECOGNIZED`), quarantine unsafe or ReDoS regexes, reject any candidate rule conflicting with `createFrozenPolicyFloor` or producing `falsePositiveHits > 0` on clean passing commands/tracked source paths, and enforce verified rules (`GH-EVO-01..05`) inside `createGroundedSessionEngine`.
- **`INV-GH-12` (Early Scope & Authorization Drift + DART MCP-vs-CLI Realization Guard)**: `inspectAndRepairDartBoundaries` and `evaluateAuthorizationDrift` (`src/auth-drift-guard.js`) MUST run inside `interceptToolCall` (`0` LLM calls):
  1. **DART Zero-Turn Lossless Repair & Boundary Hold (`arXiv:2610.34298`)**: Unambiguous stringified booleans (`"false"` -> `false`), stringified non-negative pagination integers (`"25"` -> `25`), optional `"null"`/`"undefined"` cursors, and outer markdown fences on shell commands MUST be repaired in `0` extra turns (`repairedArgs`) without mutating markdown/code file `content` or literal `"NA"` values (`INV-GH-01`), whereas CLI flags stuffed into structured MCP identifiers/paths, broken identifier sentinels, invalid pagination bounds, and raw MCP XML/JSON envelopes in POSIX shells MUST return `HOLD` (`DART_BOUNDARY_HOLD`).
  2. **Authorization Drift & SERS Data Minimization (`arXiv:2611.09113`)**: Unscoped bulk data sweeps (`SELECT *` without constraining `WHERE` or bounded `LIMIT <= maxBulkLimit` on sensitive tables, standalone `printenv`/`env` dumps, runaway `limit > maxBulkLimit`, wildcard entity selectors, and early empty-pattern/root sweeps on Turn-0 grounded sessions) and unattested sensitive scope access (`inferGoalAttestedScopes`) MUST return `HOLD` (`AUTHORIZATION_DRIFT_HOLD`) with a Staged Execution-Reflective Synthesis (`SERS`) data-minimization prompt, while hard credential-store escapes, unattested outbound transmissions after sensitive taint (`TAINTED_OUTBOUND_EXFILTRATION`), and repeated cumulative drift (`driftScore >= blockScoreThreshold`) MUST escalate to `BLOCK` (`AUTHORIZATION_DRIFT_BLOCK`). Distinct targeted reads MUST remain unthrottled (`maxReadStreak === 0`).

---

## 3. Exact Module Signatures & JSON Contracts

### 3.1 `lib/llm.js` (`@krusch/toolkit/llm`)
- `export function resolveGeminiToolConfig(config = {}, options = {})`
  - Returns explicit `toolConfig` if provided, `{ functionCallingConfig: { mode: 'NONE' } }` when `tools` is absent/empty (and `disableAutoToolConfigNone !== true`), or `undefined` when non-empty `tools` are declared.
- `export function buildGeminiPayload(systemPrompt, userMessage, config, options = {}, continuationToken = undefined)`
  - Includes `tools` only when non-empty and injects `toolConfig` from `resolveGeminiToolConfig(config, options)`.

### 3.2 `src/grounding-compiler.js`
- `export function introspectWorkspaceSchemas(workspaceDir, options = {})`
  - Tabular files include `hasLiteralNaHazard: boolean`, `naHazardColumns: string[]`, and per-column `hasLiteralNaString: boolean`, `literalNaTokens: string[]`.
  - JSON/JSONL object-array files include `nullFields: string[]`, `emptyArrayFields: string[]`, and `wildcardCandidateFields: string[]`.
- `export async function compileTurnZeroGrounding(options = {})`
  - Returns `okEnvelope('krusch_ground_turn_zero', summary, { scaleProfile, prefixHash, geminiToolConfig, workspace, retrievedChunks, seenChunkIds, fileDigests, compiledSystemPrompt, compiledContextBlock, messages, exposedTools, toolSavings, tokenStats, llmIngestionCalls: 0 })`.

### 3.3 `src/grounded-session-engine.js` & `lib/grounded-harness.js`
- `export function buildSafeGeminiToolConfig({ tools, toolConfig, disableAutoToolConfigNone = false } = {})`
  - Returns explicit `toolConfig` if provided, `{ functionCallingConfig: { mode: 'NONE' } }` when `tools` is absent/empty (and `disableAutoToolConfigNone !== true`), or `null` when non-empty `tools` are declared (or `disableAutoToolConfigNone === true`).
- `export function normalizeCodeSnippetForHash(source = '', keyHint = '')`
- `export function inspectOutputDefects({ candidateAnswer, assistantText = '', finishReason = null, truncatedToolCalls = false, toolCalls = [], expectNonEmptyAnswer = false } = {})`
  - Returns `{ hasDefect: boolean, defects: Array<{ code: string, message: string }>, primaryDefect: { code: string, message: string } | null, correctivePrompt: string | null, rescuedToolCalls: Array<object> }`.
- `export function formatTimeoutWithPartialStdout({ timeoutMs, timeoutSeconds, stdout = '', stderr = '', maxStdoutChars = 8000, label = 'Sandbox execution' } = {})`
  - Returns `{ ok: false, timedOut: true, stdout: string, stderr: string, hasFinalAnswer: false, finalAnswer: null, error: string, formattedObservation: string }`.
- `export function runAsyncWithPartialStdout(runnerFn, options = {})` (in `lib/grounded-harness.js`)
- `export function execCommandWithPartialStdout(command, args = [], options = {})` (in `projects/krusch-grounded-harness`)
- `export function detectDatasetSchemaHazards({ csvRows, headers, jsonRecords } = {})` (in `lib/grounded-harness.js`)

### 3.4 SQLite Schema (`GROUNDED_HARNESS_SCHEMA_SQL`)
```sql
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
  allowed_scopes_json TEXT NOT NULL DEFAULT '[]',
  drift_state_json TEXT NOT NULL DEFAULT '{}',
  auth_drift_holds INTEGER NOT NULL DEFAULT 0,
  dart_repairs_applied INTEGER NOT NULL DEFAULT 0,
  dart_holds INTEGER NOT NULL DEFAULT 0,
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
```

### 3.5 `src/trace-rule-synthesizer.js` (`INV-GH-11`)
- `export function verifyCandidateRulesOnTraces(candidateRules = [], options = {})`
- `export async function evolveRulesFromTraces(options = {})`
  - Returns `okEnvelope('krusch_evolve_harness_rules', summary, { mining, teacher, acceptedRules, rejectedRules, outputPath })`.

### 3.6 `src/auth-drift-guard.js` (`INV-GH-12`)
- `export function inferGoalAttestedScopes(goal = '', explicitAllowedScopes = [])`
- `export function inspectAndRepairDartBoundaries({ toolName = '', args = {}, toolSchema = null } = {})`
- `export function evaluateAuthorizationDrift(options = {})`
- `export function auditTrajectoryAuthorizationDrift(options = {})`
  - Returns `okEnvelope('krusch_audit_auth_drift', summary, { attestedScopes, finalDriftState, counts, stepVerdicts })`.
