# krusch-grounded-harness (`AGENTS.md`)

Turn-0 Grounded, Scale-Aware, Low-Tool-Call Agent Harness (`v0.2.0`) providing an HTTP Control Gateway (`:3782`), a 7-tool `stdio` MCP server, and programmatic ESM subpath exports built on `@krusch/toolkit`.

---

## ⚠️ Hazards & Non-Negotiable Protection Policies

1. **OS Drive Protection (`INV-LEGO-04`)**: Never store persistent SQLite databases (`DB_PATH`), Docker volumes (`DATA_DIR`), or large log archives on OS boot drives in production. Mount a dedicated non-OS storage volume via `DATA_DIR`.
2. **CSO Zero-Leak Sanitization (`INV-GH-07`)**: Never commit private LAN/10GbE/Tailscale IPs, host user paths, internal fleet hostnames, or raw credentials. Author all Git commits and tags as `kruschdev <kruschdev@users.noreply.github.com>`.
3. **Lego & Universal Envelope Contract (`INV-GH-06`)**: Never hand-roll HTTP servers, MCP stdio transports, or raw SQLite wrappers. Every public method, HTTP route, and MCP tool must return `{ ok, tool, summary, data }` (or `{ ok: false, error }`) and pass `krusch-lego audit` with `0` findings.
4. **Zero-Overhead Healthy Path (`INV-GH-04`, `INV-GH-05`)**: Keep `maxReadStreak === 0` (never throttle distinct multi-step reads), fire `FORCE_VERIFY` strictly when `pendingDiffsCount > 0 && !latestVerificationPassed`, and never nudge policy abstentions or clean read-only completions.

---

## 🖥️ Runtime Target & Quick Start

- **Target Host & Surface**: Local orchestrator (`127.0.0.1:3782` HTTP Control Gateway + `stdio` MCP Server, Node.js `>= 22.0.0` ESM).

```bash
npm install && npm test
node bin/krusch-grounded-harness.js doctor
node bin/krusch-grounded-harness.js bench
node bin/krusch-grounded-harness.js mcp
node bin/krusch-grounded-harness.js serve --port 3782
```

---

## 🏛️ 3-Layer Architecture

1. **Transport Layer (`src/server.js`, `src/mcp.js`, `bin/krusch-grounded-harness.js`)**
   - HTTP Control Gateway (`createApiServer`, `/health`, `/doctor`, `/api/scale-tiers`, `/api/scale-profile`, `/api/ground`, `/api/ground-and-start`, `/api/session/*`).
   - Stdio MCP Server (`createMcpServer`, `strictTools: true`) exposing `7` tools with mandatory `INV-STACK-03` 4-boolean annotations.
   - Deterministic CLI (`defineCli`) supporting `--json` across `scale`, `ground`, `doctor`, `bench`, `mcp`, and `serve`.
2. **Domain Layer (`src/scale-policy.js`, `src/delta-tool-gate.js`, `src/grounding-compiler.js`, `src/grounded-session-engine.js`)**
   - **Scale-Aware Policy (`INV-GH-03`)**: Maps `(model, activeParamsB, totalParamsB, thinkingEnabled)` into `SMALL_MODEL` (`< 15B` non-thinking: `[PLAN -> BIND -> ACT]` + placeholder/date holds), `MID_MODEL`, or `FRONTIER_REASONING` (`0` outer thinking overhead).
   - **Turn-0 Grounding (`INV-GH-01`, `INV-GH-02`, `INV-GH-09`)**: Zero-LLM workspace schema introspection (RFC-4180 CSV/TSV with literal `"NA"` `keep_default_na=False` flags, JSON/JSONL with `null`/`[]` wildcard flags, read-only SQLite DDL/counts, code symbols, and `256/32`-token `Raw-RAG` chunks), KV-cache-stable `prefixHash` normalization, and automatic Gemini tool-less `functionCallingConfig: { mode: 'NONE' }`.
   - **Session & Output Gates (`INV-GH-04`, `INV-GH-05`, `INV-GH-10`)**: Okapi BM25 tool deferral (`>12` tools), quote-safe/Python-`//`-safe comment-stripped call hashing (`MEMOIZED_PRIOR_READ` -> `BLOCK_SPIN_LOOP`, `maxReadStreak = 0`), frozen policy floor + secret-leak + duplicate-write guards, zero-turn defect-only `inspectOutputDefects`, and partial `stdout` preservation on subprocess timeouts.
3. **Persistence Layer (`@krusch/toolkit/sqlite` — `openSqliteDb`)**
   - WAL-mode `node:sqlite` store (`GROUNDED_HARNESS_SCHEMA_SQL`) persisting `grounded_sessions` and `grounded_events` (`seen_chunks_json`, `file_digests_json`, memoized `result_preview`, and per-session telemetry counters).

---

## 🗺️ Key File Map

- `package.json` — Package manifest, subpath exports (`./scale-policy`, `./delta-tool-gate`, `./grounding-compiler`, `./session-engine`, `./mcp`, `./server`), and scripts.
- `config.json` & `.env.example` — Default port (`3782`), service name, `DB_PATH`, `DATA_DIR`, and `LOG_DIR`.
- `spec.md` — Frozen `v0.2.0` architectural specification and `INV-GH-01..10` contracts.
- `bin/krusch-grounded-harness.js` — CLI entrypoint (`scale`, `ground`, `doctor`, `bench`, `mcp`, `serve`).
- `src/index.js` — Public module barrel and `createGroundedHarness` (`groundAndStartSession`) factory.
- `src/config.js` — Layered configuration loader (`@krusch/toolkit/config`).
- `src/scale-policy.js` — Model parameter parser and `SMALL_MODEL` / `MID_MODEL` / `FRONTIER_REASONING` resolver.
- `src/delta-tool-gate.js` — BM25 deferred tool budget gate (`createToolBudgetGate`) and `createDeltaContextTracker`.
- `src/grounding-compiler.js` — Zero-LLM `introspectWorkspaceSchemas` and `compileTurnZeroGrounding`.
- `src/grounded-session-engine.js` — SQLite session engine, `inspectOutputDefects`, `normalizeCodeSnippetForHash`, `buildSafeGeminiToolConfig`, and `execCommandWithPartialStdout`.
- `src/mcp.js` — 7-tool `stdio` MCP server (`GROUNDED_MCP_TOOLS`, `startGroundedMcpServer`).
- `src/server.js` — HTTP `:3782` Control Gateway (`buildServer`).
- `tests/grounded-harness.test.js` & `tests/smoke.test.js` — Unit, HTTP, MCP, and `INV-GH-07` zero-leak verification suites.
