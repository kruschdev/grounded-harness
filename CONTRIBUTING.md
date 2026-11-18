# Contributing to `krusch-grounded-harness`

Thank you for contributing to `krusch-grounded-harness`. I keep this repository focused on fast, deterministic, zero-cloud agent grounding and runtime guardrails, so every pull request must preserve the `v0.2.0` architectural boundaries and invariants below.

---

## 🎯 Repository Scope

`krusch-grounded-harness` does three focused jobs in `0` LLM calls:
1. **Turn-0 Workspace & Dataset Hazard Grounding**: Introspect RFC-4180 CSV/TSV schemas (`"NA"` string hazards), JSON/JSONL wildcard fields (`null` vs. `[]`), read-only SQLite DDL, code symbol headers, `256/32`-token `Raw-RAG` chunks, and BM25-deferred tool catalogs.
2. **Session Interception & Spin-Loop Prevention**: Enforce scale-aware policies (`SMALL_MODEL`, `MID_MODEL`, `FRONTIER_REASONING`), frozen safety-floor checks, DART boundary repair/holds, SERS authorization-drift guards, and comment-normalized `MEMOIZED_PRIOR_READ` / `BLOCK_SPIN_LOOP` deduplication (`maxReadStreak === 0`).
3. **Zero-Turn Defect-Only Stop Verification**: Pass healthy completions in `0` extra turns while catching objective output defects (`inspectOutputDefects`) and preserving partial `stdout` across subprocess timeouts.

Capabilities outside that boundary belong in sibling repositories:
- **Persistent cross-session memory & decision lineage**: [`krusch-context-mcp`](https://github.com/kruschdev/krusch-context-mcp)
- **PostgreSQL 2PC staged file diffs & Bubblewrap test sandboxes**: [`krusch-coding-harness`](https://github.com/kruschdev/krusch-coding-harness)
- **Unified multi-pillar CLI & IDE installer**: [`krusch-stack`](https://github.com/kruschdev/krusch-stack)

---

## 🛠️ Prerequisites

- **Node.js `>= 22.0.0`** (required for built-in `node:sqlite` `DatabaseSync` in WAL mode; zero Docker containers, zero native C++ build toolchains, and zero cloud API keys needed).
- **Non-root shell**: Run `npm` and `node` under a standard developer user account (`id -u != 0`), never via `sudo`.

---

## ⚡ Local Verification Commands

Run the full check sequence before opening a pull request:

```bash
# 1. Clean dependency install
npm ci

# 2. Run all unit, invariant, auth-drift, trace-synthesizer, and HTTP/MCP smoke tests
npm test

# 3. Verify SQLite WAL health, 7-tool 4-boolean MCP annotations, and v0.2.0 invariants
npm run doctor
# Equivalent CLI invocation:
node bin/krusch-grounded-harness.js doctor

# 4. Run deterministic 3-tier Grounded vs. Un-Grounded vs. Legacy-2PC benchmark
npm run bench
# Equivalent CLI invocation:
node bin/krusch-grounded-harness.js bench

# 5. Optional CLI spot-checks for Turn-0 grounding and scale profiles
node bin/krusch-grounded-harness.js ground --dir . --goal "Verify Turn-0 grounding" --max-tokens 3200
node bin/krusch-grounded-harness.js scale --model qwen2.5-coder:7b
```

---

## 🛡️ Non-Negotiable Invariants

1. **Core Empirical Laws (`INV-GH-01..10`)**:
   - **`INV-GH-01` & `INV-GH-02` (Zero-LLM Grounding & Prefix Stability)**: `compileTurnZeroGrounding` and `introspectWorkspaceSchemas` must execute with `llmIngestionCalls === 0`, flag CSV/TSV literal `"NA"` / `"N/A"` tokens (`keep_default_na=False`) and JSON `null` vs. `[]` wildcards, skip `.env` and secret files automatically, and emit a deterministic 64-character SHA-256 `prefixHash`.
   - **`INV-GH-03` (Monotonic Scale Policy)**: `resolveScaleProfile` must keep `SMALL_MODEL` (`< 15B` non-thinking), `MID_MODEL` (`15B–70B`), and `FRONTIER_REASONING` (`>= 70B` or native thinking) monotonic, injecting `[PLAN -> BIND -> ACT]` only for `SMALL_MODEL` and adding `0` outer thinking steps on `MID_MODEL` and `FRONTIER_REASONING`.
   - **`INV-GH-04` (Normalized Spin Hashing & `maxReadStreak === 0`)**: `normalizeCodeSnippetForHash` must strip comments outside string literals while preserving Python `//` floor division and indentation. First repeats of committed reads return `MEMOIZED_PRIOR_READ`; repeat failures or repeats after memoization return `BLOCK_SPIN_LOOP` (`0` re-executions). Distinct multi-step reads must never be throttled (`maxReadStreak === 0`).
   - **`INV-GH-05` & `INV-GH-08` (Staged-Diff-Only `FORCE_VERIFY` & Defect-Only Stop Gate)**: `FORCE_VERIFY` triggers strictly when `pendingDiffsCount > 0 && !latestVerificationPassed`. `inspectOutputDefects` must pass clean answers (including `"0"`, `0`, `false`, `"Not Applicable"`, and `"N/A"`) in `0` extra turns and block stop only on objective defects (`EMPTY_OR_NULL_BAILOUT`, `TRUNCATED_OUTPUT`, `SERIALIZED_TOOL_CALL_IN_TEXT`, `RAW_DATAFRAME_OR_NUMPY_REPR`). Never reintroduce unconditional analytical 2PC stop-nudges.
   - **`INV-GH-09` & `INV-GH-10` (Gemini Tool-Less Guard & Timeout Partial `stdout`)**: `buildSafeGeminiToolConfig` must return `{ functionCallingConfig: { mode: 'NONE' } }` when `tools` is omitted or empty `[]`. `execCommandWithPartialStdout` and `formatTimeoutWithPartialStdout` must preserve partial `stdout` emitted prior to timeout while resetting `finalAnswer: null` and `hasFinalAnswer: false`.
   - **`INV-GH-11` & `INV-GH-12` (Holdout-Verified Rule Synthesis & Drift/Boundary Guards)**: Candidate rules in `src/trace-rule-synthesizer.js` must reject ReDoS-unsafe regexes and require `falsePositiveHits === 0` against clean commands. DART boundary repairs in `src/auth-drift-guard.js` must never mutate file body content or literal `"NA"` strings.
2. **Universal Envelope Contract (`INV-GH-06`)**: Every public library method, HTTP endpoint on `:3782`, and MCP handler must return `{ ok: boolean, tool: string, summary: string, data: object }` (or `{ ok: false, error: { code, message } }`).
3. **4-Boolean MCP Tool Annotations (`INV-STACK-03`)**: Every tool exposed by `src/mcp.js` must define explicit boolean `annotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`), verified by `node bin/krusch-grounded-harness.js doctor`.
4. **Zero Private IPs, Hostnames, or Personal Paths (`INV-GH-07` / `INV-STACK-04`)**: Never include private LAN, 10GbE, or VPN IP addresses, internal machine hostnames, `/home/<user>` or `/mnt/<volume>` paths, or live secrets in code, tests, fixtures, or documentation. Use `127.0.0.1` / `localhost` and `/absolute/path/to/...` placeholders.

---

## 📬 Pull Request Guidelines

- **Reuse `@krusch/toolkit` Bricks**: Prefer `@krusch/toolkit` subpaths (`./http`, `./mcp`, `./sqlite`, `./grounded-harness`, `./harness-engineering`, `./raw-rag`, `./cli`) over hand-rolled server or database wrappers.
- **Deterministic Offline Tests**: Add or update tests in `tests/*.test.js` using `:memory:` SQLite databases or `fs.mkdtempSync(path.join(os.tmpdir(), ...))` scratch directories with `finally` cleanup. Tests must never require network access or external LLM APIs.
- **Documentation Style (`INV-SOLO-VOICE-01`)**: Write documentation in singular first-person (`"I"`, `"my"`, `"me"`) or second-person (`"you"`, `"your"`), with zero plural first-person pronouns and zero em-dash characters.
- **Pre-PR Checklist**: Confirm `npm test`, `npm run doctor`, and `npm run bench` exit `0` cleanly before submitting your pull request.
