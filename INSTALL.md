# Install `krusch-grounded-harness` (`grounded-harness`)

These are instructions for a coding agent (Claude Code, Codex, Cursor, Windsurf, or Antigravity) that a person asked to install and configure `grounded-harness` (`krusch-grounded-harness` v0.2.0) on their machine or inside their repository.

`krusch-grounded-harness` is a Turn-0 Grounded, Scale-Aware, Low-Tool-Call Agent Harness built on `@krusch/toolkit`. It compiles zero-LLM workspace schemas (CSV/TSV `"NA"` hazards, JSON `null`/`[]` wildcards, read-only SQLite DDL, code symbols, and `256/32`-token `Raw-RAG` chunks), enforces monotonic `SMALL_MODEL` / `MID_MODEL` / `FRONTIER_REASONING` policies, memoizes duplicate reads (`BLOCK_SPIN_LOOP`), gates objective output defects in zero extra turns when healthy, and exposes both a 7-tool stdio MCP server and an HTTP `:3782` Control Gateway backed by Node 22 native `node:sqlite` WAL.

## 1. Check Prerequisites First (All at Once)

Run one read-only check before making any changes:

```bash
id -u
node -v 2>/dev/null || echo "MISSING: node"
npm -v 2>/dev/null || echo "MISSING: npm"
git --version 2>/dev/null || echo "MISSING: git"
docker compose version 2>/dev/null || echo "OPTIONAL_MISSING: docker-compose"
```

Evaluate the results:
1. **User check**: If `id -u` prints `0` (root), stop and ask the person to run you under a standard non-root developer account.
2. **Node.js `>= 22.0.0` (Required)**: `krusch-grounded-harness` uses Node 22's built-in `node:sqlite` (`DatabaseSync` in WAL mode), so zero native C++ build toolchains or database containers are needed. If `node -v` is missing or older than `v22.0.0`, ask the person before installing or switching to Node 22 (`nvm install 22` or `fnm use 22`).
3. **Docker Compose (Strictly Optional)**: Not needed for Mode A's local CLI or 7-tool stdio MCP server. Only use Docker if the person explicitly asks for a containerized `:3782` HTTP Control Gateway.

## 2. Choose the Right Setup Mode

- **Mode A: Local Zero-Docker CLI + 7-Tool Stdio MCP Server (Recommended Default)**: Clones `https://github.com/kruschdev/grounded-harness.git`, installs dependencies, creates `.env` from `.env.example` if missing, runs `npm test`, `node bin/krusch-grounded-harness.js doctor`, and `node bin/krusch-grounded-harness.js bench`, and registers the 7-tool stdio MCP server.
- **Mode B: HTTP Control Gateway (`127.0.0.1:3782`) or Docker Compose**: Runs `node bin/krusch-grounded-harness.js serve --port 3782` directly under Node 22 or builds the container via `docker compose up -d --build`, then verifies `http://127.0.0.1:3782/health`.

## 3. Install & Verify

### Mode A: Local Zero-Docker CLI + SQLite WAL Setup (Default)

Check `pwd` first. Clone into the current directory (or into `~/src/grounded-harness` if the current directory is `$HOME` or another unrelated repository):

```bash
git clone https://github.com/kruschdev/grounded-harness.git
cd grounded-harness
npm install
[ -f .env ] || cp .env.example .env

# 1. Run full invariant and smoke test suites
npm test

# 2. Verify SQLite WAL engine, 7-tool 4-boolean MCP annotations, and v0.2.0 invariants
node bin/krusch-grounded-harness.js doctor

# 3. Run deterministic 3-tier Grounded vs. Un-Grounded vs. Legacy-2PC benchmark
node bin/krusch-grounded-harness.js bench
```

Optional read-only CLI checks to inspect scale profiles or Turn-0 grounding on any directory:

```bash
node bin/krusch-grounded-harness.js scale --model qwen2.5-coder:7b
node bin/krusch-grounded-harness.js ground --dir . --goal "Inspect session engine invariants" --max-tokens 3200
```

### Mode B: HTTP Control Gateway (`:3782`) or Docker Compose (When Requested)

Check whether port `3782` is already bound first (`ss -ltnp | grep -E ':3782\b' || true`).

To run the HTTP Control Gateway directly with Node 22 (zero Docker):

```bash
[ -f .env ] || cp .env.example .env
node bin/krusch-grounded-harness.js serve --port 3782
```

Or, if the person specifically requested Docker Compose deployment (set `DATA_DIR` in `.env` to a dedicated persistent storage path in production):

```bash
[ -f .env ] || cp .env.example .env
docker compose up -d --build
curl -fsS http://127.0.0.1:3782/health
```

## 4. Connect to the Person's Coding Agent / IDE

`krusch-grounded-harness` provides 7 `INV-STACK-03` annotated MCP tools over stdio (`krusch_ground_workspace`, `krusch_resolve_scale_profile`, `krusch_grounded_session_start`, `krusch_grounded_intercept`, `krusch_grounded_outcome`, `krusch_grounded_verify_stop`, `krusch_grounded_summary`).

Replace `/absolute/path/to/grounded-harness` below with the real checkout path from `pwd`, and merge the `krusch-grounded-harness` server entry into the person's existing MCP config file without overwriting their other MCP servers:

- **Claude Code CLI**:
  ```bash
  claude mcp add krusch-grounded-harness -- node /absolute/path/to/grounded-harness/bin/krusch-grounded-harness.js mcp
  ```
- **Cursor (`~/.cursor/mcp.json`), Windsurf (`~/.codeium/windsurf/mcp_config.json`), or Antigravity (`~/.gemini/antigravity/mcp_config.json`)**:
  ```json
  {
    "mcpServers": {
      "krusch-grounded-harness": {
        "command": "node",
        "args": ["/absolute/path/to/grounded-harness/bin/krusch-grounded-harness.js", "mcp"]
      }
    }
  }
  ```
- **Codex (`~/.codex/config.toml`)**:
  ```toml
  [mcp_servers.krusch-grounded-harness]
  command = "node"
  args = ["/absolute/path/to/grounded-harness/bin/krusch-grounded-harness.js", "mcp"]
  ```

## Never

- **Never run `npm`, `node`, or `krusch-grounded-harness` with `sudo` or as `root`**.
- **Never overwrite an existing `.env` or global MCP config file** (`~/.cursor/mcp.json`, `~/.codeium/windsurf/mcp_config.json`, `~/.gemini/antigravity/mcp_config.json`, `~/.codex/config.toml`); read and parse the existing file first, merge only the `krusch-grounded-harness` key, and write it back cleanly.
- **Never invent API keys**; Turn-0 workspace grounding, `Raw-RAG` chunking, scale profiling, and SQLite session tracking execute locally with `0` LLM ingestion calls and `$0.00` API cost.
- **Never start Docker containers** unless the person requested containerized gateway mode and port `3782` is free.

## Tell the Person After

Share a concise status report:
1. **Install location & mode**: Confirm the directory path, SQLite database location (`./data/app.db` by default), and whether `:3782` HTTP gateway mode was also started.
2. **Verification status**: Report exact results from `npm test`, `node bin/krusch-grounded-harness.js doctor`, and `node bin/krusch-grounded-harness.js bench` (plus `curl -fsS http://127.0.0.1:3782/health` if Mode B ran).
3. **Configured IDEs**: List the exact MCP configuration files updated and remind the person to reload MCP servers or open a new session so all 7 tools appear.
4. **First-turn test prompt**: Suggest running in their next session: `"Call krusch_ground_workspace and krusch_resolve_scale_profile on this repository to verify krusch-grounded-harness is active."`
