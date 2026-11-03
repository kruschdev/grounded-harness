# Krusch Grounded Harness (`krusch-grounded-harness` v0.2.0)

Turn-0 Grounded, Scale-Aware, Low-Tool-Call Agent Harness (`HTTP :3782` Control Gateway + `7`-tool `stdio` MCP Server + Node 22 ESM library) built on `@krusch/toolkit` (`v1.7.0`).

---

## ⚡ Overview & Six Empirical Design Laws (`INV-GH-01..10`)

Distilled from `13,200+` `DolphinBench` traces (`22` official `600`-task multi-session tool runs), `120` `DABstep` multi-step analytics episodes, `BEAM` (`100K`–`10M` tokens), and `BFCL v3` (`64` live tools), `krusch-grounded-harness` replaces unconditional outer-loop 2PC stop-nudging with six zero-overhead-when-healthy structural laws:

1. **Turn-0 Schema + `Raw-RAG` Briefing with Dataset Hazard Flags (`INV-GH-01`, `INV-GH-02`)**
   - `compileTurnZeroGrounding` introspects RFC-4180 CSV/TSV columns, JSON/JSONL object arrays, read-only SQLite DDL & row counts, code symbols, and `256/32`-token `Raw-RAG` documentation chunks with **`0` LLM ingestion calls**, paired with Okapi BM25 tool deferral (`-70%` to `-80%` schema tokens) and SHA-256 `prefixHash` KV-cache normalization.
   - Explicitly flags **CSV `"NA"` string literals** (`keep_default_na=False` in `pandas.read_csv`) and **JSON `null` vs. empty-list `[]` wildcards** before Step 1 (skipping `.env` / secret files automatically).
2. **Gemini Tool-Less `functionCallingConfig: { mode: "NONE" }` Guard (`INV-GH-09`)**
   - `buildSafeGeminiToolConfig` (and `buildGeminiPayload` in `@krusch/toolkit/llm`) automatically injects `toolConfig: { functionCallingConfig: { mode: 'NONE' } }` whenever `tools` is omitted or empty `[]`, eliminating `MALFORMED_FUNCTION_CALL` empty turns on markdown ```` ```py ```` code blocks.
3. **Zero-Turn *Defect-Only* Output Gate (`inspectOutputDefects`, `INV-GH-05`)**
   - Approves clean completions in **`0` extra turns** while blocking objective output defects (`maxDefectRetries = 1`):
     - `EMPTY_OR_NULL_BAILOUT`: literal `""`, `None`, `null`, `NaN`, `[]`, `{}` when an answer is expected (never blocking `"0"`, `0`, `false`, `"Not Applicable"`, or `"N/A"`).
     - `TRUNCATED_OUTPUT`: `finishReason` in `MAX_TOKENS` / `length` / `MALFORMED_FUNCTION_CALL` or truncated tool JSON.
     - `SERIALIZED_TOOL_CALL_IN_TEXT`: raw `<tool_call>{...}</tool_call>` or `call:fn{...}` emitted in prose when `toolCalls.length === 0`.
     - `RAW_DATAFRAME_OR_NUMPY_REPR`: unformatted `np.float64(...)` or pandas `dtype:` repr leaks in final answers.
4. **Quote-Safe Comment-Normalized Call Hashing (`BLOCK_SPIN_LOOP`) & `maxReadStreak = 0` (`INV-GH-04`)**
   - `normalizeCodeSnippetForHash` strips comments outside string literals (preserving Python `//` floor division and indentation) prior to SHA-256 hashing. First repeats of `COMMITTED` reads return `MEMOIZED_PRIOR_READ` with cached preview; repeat identical `FAILED` calls or repeats after `MEMOIZED_PRIOR_READ` return `BLOCK_SPIN_LOOP` with `0` tool re-executions. Distinct multi-step reads (`1..N`) are never throttled (`maxReadStreak === 0`).
5. **Scale-Aware Thinking Curve & Staged-Diff-Only `FORCE_VERIFY` (`INV-GH-03`, `INV-GH-05`)**
   - `SMALL_MODEL` (`< 15B` non-thinking) receives compact `[PLAN -> BIND -> ACT]` guidance plus placeholder (`{{var}}`) and invalid-calendar-date soft-holds (`HOLD`); `MID_MODEL` (`15B–70B`) and `FRONTIER_REASONING` (`>= 70B` or native thinking) execute with `0` outer thinking overhead. `FORCE_VERIFY` fires **strictly when `pendingDiffsCount > 0 && !latestVerificationPassed`**, never on read-only analytics or policy abstentions.
6. **Partial `stdout` Preservation on Sandbox Timeouts (`INV-GH-10`)**
   - `execCommandWithPartialStdout` and `formatTimeoutWithPartialStdout` preserve partial `stdout` emitted prior to timeout alongside `TimeoutError` while clearing stale `finalAnswer: null` (`hasFinalAnswer: false`).

---

## 📊 Empirical Benchmark Results (`1,800` Official `DolphinBench` Traces & `120` Adyen `DABstep` Episodes)

### 1. Official `DolphinBench` Multi-App Suite (`3 × 600 = 1,800` Traces, `openai/gpt-5.6-sol` Judge, `0o444` Frozen SQLite, `5/5` Clean-Room Gates)

| Model & Scale Tier (`N = 600` Tasks/Run) | Standard Harness | `+ Grounded Harness` (`v0.2.0`) | Key Latency, Persona & Telemetry Outcomes | Archive SHA-256 |
|---|---|---|---|---|
| **`Google Gemma 4 31B Dense` (`MID_MODEL`, Thinking ON, `$0.00`)** | `54.17%` (`325/600`) | **`56.67%` (`340/600`, NEW `#1 Open-Weights`)** | **`+2.50 pp` (`+15` net tasks)** · Lifts every persona (`Morgan 73.0%`, `Alex 48.5%`, **`Riley 48.5%` [`+5.50 pp`]**) · **`15` spin loops blocked**, `4` policy-floor blocks, `1` output defect healed, `1,228` Turn-0 duplicates suppressed (`Oracle@2 = 61.33%` [`368/600`], `Oracle@3 = 66.17%` [`397/600`]) | `eab600888c276d58490135544e1ecd4ed2c68b63a4504baf1556437f9e62f296` |
| **`OpenAI GPT 5.6 Luna` (`FRONTIER_REASONING`, High, `$1.35`)** | `81.33%` (`488/600`) | **`81.50%` (`489/600`, `#1` Luna Pareto)** | **`30.03s` median latency (`1.57x` faster than `47.02s` Standard)** · **`+4.50 pp` on `Riley` (`149 -> 158`)** over unconditional 2PC stop-nudging · `5,318` Turn-0 duplicates suppressed, `0` self-doubt nudges (`Oracle@2 = 89.33%` [`536/600`]) | `477047fc4852137f3432eaf9a82aa40c659ba2ae4a6269d28ea2b419df17e408` |
| **`Google Gemini 4 Argon` (`FRONTIER_REASONING`, Low, `$23.92`)** | `91.17%` (`547/600`) | **`89.17%` (`535/600`)** | `-2.5%` lower cost (`$23.92` vs. `$24.54`, exact McNemar $p = 0.104$ NS) · **`+17` new tail-recall wins (`Argon Low Oracle@2 = 94.00%` [`564/600`])** · `8,092` Turn-0 duplicates suppressed, `0` self-doubt nudges | `5ce8a7f8ac513d706e874f58014fee1e5e7b18bbd520df8a0d7445c1565a798d` |

### 2. Adyen `DABstep` Multi-Step Data Analytics (`120` Episodes Across `4` Models, `0` LLM Judges, `42/42` Upstream `scorer.py` Parity)

- **`gemini-4-argon` (`medium`)**: Reaches **`90.0%` (`9/10`: `100%` Easy, `85.7%` Hard) @ `$0.81`** (`5.1` turns) and delivers **`-74.5%` lower cost with a `2.54x` wall-clock speedup** (`75.5s` vs. `191.5s` ungrounded) by flagging CSV `"NA"` string literals (`keep_default_na=False`) and JSON `null`/`[]` wildcards at Turn 0.
- **Open-Weights (`$0.00` Inference)**: Lifts **`gemma4:31b` from `20.0%` $\rightarrow$ `40.0%` (`+20.0 pp`)** and **`qwen3-coder-30b-moe` from `20.0%` $\rightarrow$ `30.0%` (`+10.0 pp`, `6.8 -> 2.4` steps, `-44.4%` prompt tokens)** with `0` LLM ingestion calls.

---

## 🛠️ Tech Stack & Package Exports

- **Runtime**: Node.js `>= 22.0.0` (ESM, native `node:sqlite` WAL via `@krusch/toolkit/sqlite`, zero native C++ build steps required).
- **Bricks Used**: `@krusch/toolkit/http`, `@krusch/toolkit/mcp`, `@krusch/toolkit/sqlite`, `@krusch/toolkit/harness-engineering`, `@krusch/toolkit/raw-rag`, `@krusch/toolkit/cli`, `@krusch/toolkit/config`, `@krusch/toolkit/log`.

| Subpath Import | Core Exports |
|---|---|
| `krusch-grounded-harness` | `createGroundedHarness`, `compileTurnZeroGrounding`, `introspectWorkspaceSchemas`, `resolveScaleProfile`, `createGroundedSessionEngine`, `inspectOutputDefects`, `buildSafeGeminiToolConfig`, `normalizeCodeSnippetForHash`, `canonicalizeToolCallKey`, `execCommandWithPartialStdout` |
| `krusch-grounded-harness/scale-policy` | `SCALE_TIERS`, `inferModelScaleMetadata`, `resolveScaleProfile`, `buildScaleAwareDirective` |
| `krusch-grounded-harness/delta-tool-gate` | `measureToolSchemaSavings`, `createToolBudgetGate`, `createDeltaContextTracker` |
| `krusch-grounded-harness/grounding-compiler` | `introspectWorkspaceSchemas`, `compileTurnZeroGrounding` |
| `krusch-grounded-harness/session-engine` | `GROUNDED_HARNESS_SCHEMA_SQL`, `createGroundedSessionEngine`, `inspectOutputDefects`, `buildSafeGeminiToolConfig`, `normalizeCodeSnippetForHash`, `formatTimeoutWithPartialStdout`, `execCommandWithPartialStdout`, `classifyToolMutability`, `canonicalizeToolCallKey` |
| `krusch-grounded-harness/mcp` | `GROUNDED_MCP_TOOLS`, `startGroundedMcpServer` |
| `krusch-grounded-harness/server` | `buildServer` |

---

## 🚀 Setup & CLI Commands

```bash
# Install dependencies and run full invariant + smoke test suites
npm install
npm test

# Verify SQLite WAL engine, 7-tool 4-boolean MCP annotations, and v0.2.0 invariants
node bin/krusch-grounded-harness.js doctor

# Inspect monotonic scale profile for any model
node bin/krusch-grounded-harness.js scale --model qwen2.5-coder:7b
node bin/krusch-grounded-harness.js scale --model gemma4:31b
node bin/krusch-grounded-harness.js scale --model gemini-4-argon

# Compile Turn-0 workspace schemas & zero-LLM Raw-RAG chunks (--json supported)
node bin/krusch-grounded-harness.js ground --dir . --goal "Inspect session engine invariants" --max-tokens 3200

# Run deterministic 3-tier Grounded vs. Un-Grounded vs. Legacy-2PC benchmark
node bin/krusch-grounded-harness.js bench

# Start 7-tool stdio MCP server or HTTP :3782 Control Gateway
node bin/krusch-grounded-harness.js mcp
node bin/krusch-grounded-harness.js serve --port 3782
```

### Docker Compose Deployment

```bash
cp .env.example .env
# Set DATA_DIR in .env to a dedicated non-OS storage volume
docker compose up -d --build
curl -s http://127.0.0.1:3782/health
```

---

## 🔌 Stdio MCP Server (`7` Tools — `INV-STACK-03` Annotated)

| Tool Name | `readOnly` | `destructive` | `idempotent` | `openWorld` | Purpose |
|---|---:|---:|---:|---:|---|
| `krusch_ground_workspace` | `true` | `false` | `true` | `false` | Introspect CSV/TSV, JSON/JSONL, read-only SQLite DDL, code symbols, and `256/32` `Raw-RAG` docs (`0` LLM calls), defer `>12` tools via BM25, and emit `prefixHash`. |
| `krusch_resolve_scale_profile` | `true` | `false` | `true` | `false` | Resolve `SMALL_MODEL`, `MID_MODEL`, or `FRONTIER_REASONING` policy from model & thinking hints. |
| `krusch_grounded_session_start` | `false` | `false` | `true` | `false` | Start or reset a SQLite-tracked session seeded with `seen_chunk_ids`, `file_digests`, and schema token savings. |
| `krusch_grounded_intercept` | `false` | `false` | `false` | `false` | Check proposed tool calls against frozen policy floor, secret-leak guard, duplicate-write guard, Turn-0 digest cache, read memoization, and `BLOCK_SPIN_LOOP`. |
| `krusch_grounded_outcome` | `false` | `false` | `true` | `false` | Record tool outcome (`COMMITTED`/`FAILED`), cache read previews, preserve timeout `partial_stdout`, and update `pending_diffs_count`. |
| `krusch_grounded_verify_stop` | `false` | `false` | `false` | `false` | Zero-turn-when-healthy stop gate enforcing staged-diff `FORCE_VERIFY` and `inspectOutputDefects`. |
| `krusch_grounded_summary` | `true` | `false` | `true` | `false` | Return session metrics (`exploratoryReads`, `memoizedReads`, `spinLoopsBlocked`, `outputDefectsCaught`, `timeoutsWithPartialStdout`, `turn0DuplicatesSuppressed`) & event log. |

---

## 🌐 HTTP Control Gateway (`:3782`)

All routes return deterministic JSON envelopes `{ ok: boolean, tool: string, summary: string, data: object }` (or `{ ok: false, error: { code, message } }`; no auth required on loopback `127.0.0.1:3782`):

| Method & Path | Status | Request Body / Query | Response `data` Summary |
|---|---|---|---|
| `GET /health` & `GET /doctor` | `200` | — | Service status, version `0.2.0`, SQLite health (`db: "ok"`), and tracked `sessions` count. |
| `GET /api/scale-tiers` | `200` | — | `{ tiers: { SMALL_MODEL, MID_MODEL, FRONTIER_REASONING } }`. |
| `POST /api/scale-profile` | `200` | `{ model, activeParamsB?, totalParamsB?, thinkingEnabled?, reasoningEffort? }` | `{ profile, directive }`. |
| `POST /api/ground` | `200` | `{ workspaceDir, goal, model?, tools?, pinnedToolNames?, deferThreshold?, maxGroundingTokens? }` | `{ scaleProfile, prefixHash, geminiToolConfig, workspace, retrievedChunks, seenChunkIds, fileDigests, exposedTools, toolSavings, tokenStats, llmIngestionCalls: 0 }`. |
| `POST /api/ground-and-start` | `201` | Same as `/api/ground` + optional `session_id`, `anchor_date`, `max_duplicate_writes` | `{ session, grounding }`. |
| `POST /api/session/start` | `201` | `{ goal, session_id?, model?, seen_chunk_ids?, file_digests?, anchor_date? }` | Created `grounded_sessions` state record. |
| `POST /api/session/evaluate-turn` | `200` | `{ session_id, turn_response }` | Truncation poisoning check (`{ poisoned, safeToExecuteTools }`). |
| `POST /api/session/intercept` | `200` | `{ session_id, step?, tool_name, args?, mutating?, suppress_turn0_reads?, block_spin_loop? }` | `{ event_id, decision: "ALLOW" \| "MEMOIZED" \| "HOLD" \| "BLOCK", reason, cachedPreview?, issues }`. |
| `POST /api/session/outcome` | `200` | `{ session_id, event_id, ok?, result_preview?, timed_out?, partial_stdout?, pending_diffs_delta?, verification_passed? }` | Updated event status and preserved timeout stdout metadata. |
| `POST /api/session/verify-stop` | `200` | `{ session_id, assistant_text?, candidate_answer?, finish_reason?, expect_non_empty_answer?, pending_diffs_count?, latest_verification_passed? }` | `{ allowStop, shouldNudge, action, reason?, correctivePrompt?, rescuedToolCalls? }`. |
| `POST /api/session/summary` / `GET /api/session/summary?session_id=...` | `200` | `{ session_id }` or `?session_id=<id>` | `{ session, metrics, events }`. |

---

## ⚙️ Environment Variables (`.env.example`)

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | Optional | `3782` | TCP port for the HTTP Control Gateway. |
| `SERVICE_NAME` | Optional | `krusch-grounded-harness` | Service identifier emitted in `/health`, `/doctor`, and JSON logs. |
| `DATA_DIR` | Optional | `./data` | Host/Docker volume directory for persistent runtime state (point to a non-OS disk in production). |
| `DB_PATH` | Optional | `./data/app.db` | SQLite WAL database file path (`:memory:` supported for ephemeral/benchmark runs). |
| `LOG_DIR` | Optional | `./logs` | Directory for rotating structured JSON logs. |
