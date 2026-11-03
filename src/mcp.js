/**
 * @module mcp
 * @description Stdio MCP Server for `krusch-grounded-harness` built on `@krusch/toolkit/mcp`
 * with mandatory 4-boolean annotations (`INV-STACK-03` & `INV-GH-06`).
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  defineMcpTool,
  createMcpServer,
  okMcpResult,
  errorMcpResult
} from '@krusch/toolkit/mcp';
import { config } from './config.js';
import { createGroundedHarness } from './index.js';

export const GROUNDED_MCP_TOOLS = [
  defineMcpTool({
    name: 'krusch_ground_workspace',
    title: 'Compile Turn-0 Workspace Grounding',
    description:
      'Introspect local workspace schemas (CSV/TSV, JSON/JSONL, read-only SQLite DDL, source symbols, and 256/32 Raw-RAG docs) with 0 LLM calls, apply BM25 tool deferral, and emit a KV-cache-stable prompt bundle.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        goal: { type: 'string', description: 'Task goal used to retrieve relevant doc chunks.' },
        workspaceDir: { type: 'string', description: 'Directory path to introspect.' },
        model: { type: 'string', description: 'Target model identifier for scale-aware directive.' },
        activeParamsB: { type: 'number', description: 'Optional active parameter count in billions.' },
        totalParamsB: { type: 'number', description: 'Optional total parameter count in billions.' },
        thinkingEnabled: { type: 'boolean', description: 'Whether native reasoning/thinking is enabled.' },
        standingInvariants: {
          type: 'array',
          items: { type: 'string' },
          description: 'Standing rules/invariants included in the static cache prefix.'
        },
        tools: {
          type: 'array',
          items: { type: 'object' },
          description: 'Full tool registry definitions to gate via BM25 deferral.'
        },
        pinnedToolNames: {
          type: 'array',
          items: { type: 'string' },
          description: 'Core tools kept eagerly exposed.'
        },
        deferThreshold: { type: 'integer', description: 'Tool count threshold triggering BM25 deferral.' },
        maxGroundingTokens: { type: 'integer', description: 'Maximum Turn-0 grounding token budget.' }
      }
    }
  }),
  defineMcpTool({
    name: 'krusch_resolve_scale_profile',
    title: 'Resolve Scale-Aware Harness Profile',
    description:
      'Deterministically map a model identifier and parameter/thinking hints into SMALL_MODEL, MID_MODEL, or FRONTIER_REASONING harness policy.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: 'Model identifier (e.g., qwen2.5-coder:7b, gemma4:31b, gemini-4-argon).' },
        activeParamsB: { type: 'number', description: 'Optional active parameter count in billions.' },
        totalParamsB: { type: 'number', description: 'Optional total parameter count in billions.' },
        thinkingEnabled: { type: 'boolean', description: 'Whether native thinking mode is active.' },
        thinkingLevel: { type: 'string', description: 'Optional thinking level hint.' },
        reasoningEffort: { type: 'string', description: 'Optional reasoning effort hint.' },
        explicitTier: { type: 'string', description: 'Optional explicit tier override.' },
        preferThinkingStepForSmallActive: {
          type: 'boolean',
          description: 'Opt small-active MoE models into the compact PLAN->BIND->ACT directive.'
        }
      }
    }
  }),
  defineMcpTool({
    name: 'krusch_grounded_session_start',
    title: 'Start Grounded Harness Session',
    description:
      'Create or reset a SQLite-tracked grounded session seeded with Turn-0 chunk IDs, file digests, scale profile, and schema token savings.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      required: ['goal'],
      properties: {
        session_id: { type: 'string', description: 'Optional explicit session identifier.' },
        goal: { type: 'string', description: 'User or task goal.' },
        model: { type: 'string', description: 'Target model identifier.' },
        activeParamsB: { type: 'number' },
        totalParamsB: { type: 'number' },
        thinkingEnabled: { type: 'boolean' },
        anchor_date: { type: 'string', description: 'Optional ISO anchor date (YYYY-MM-DD).' },
        prefix_hash: { type: 'string', description: 'Optional 64-char Turn-0 prompt cache prefix hash.' },
        seen_chunk_ids: { type: 'array', items: { type: 'string' } },
        file_digests: { type: 'object' },
        all_tools: { type: 'array', items: { type: 'object' } },
        exposed_tools: { type: 'array', items: { type: 'object' } },
        turn0_tokens: { type: 'integer' },
        max_duplicate_writes: { type: 'integer' }
      }
    }
  }),
  defineMcpTool({
    name: 'krusch_grounded_intercept',
    title: 'Intercept Tool Call With Passive Safety & Read Memoization',
    description:
      'Check a proposed tool call against the frozen policy floor, secret-leak guard, duplicate-write guard, read memoization cache (maxReadStreak=0), and small-model placeholder soft-holds.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      required: ['session_id', 'tool_name'],
      properties: {
        session_id: { type: 'string', description: 'Active grounded session ID.' },
        step: { type: 'integer', description: '0-based or 1-based agent turn index.' },
        tool_name: { type: 'string', description: 'Invoked tool name.' },
        args: { type: 'object', description: 'Tool call arguments.' },
        mutating: { type: 'boolean', description: 'Optional explicit mutability override.' },
        suppress_turn0_reads: { type: 'boolean', description: 'Short-circuit unchanged Turn-0 file reads.' },
        block_spin_loop: { type: 'boolean', description: 'Passively block identical repeat calls via BLOCK_SPIN_LOOP.' }
      }
    }
  }),
  defineMcpTool({
    name: 'krusch_grounded_outcome',
    title: 'Record Tool Call Execution Outcome',
    description:
      'Commit or fail a pending intercepted tool call, memoizing read previews, preserving partial stdout on timeouts, and updating staged diff verification counters.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      required: ['session_id'],
      properties: {
        session_id: { type: 'string', description: 'Active grounded session ID.' },
        event_id: { type: 'string', description: 'Event ID returned by krusch_grounded_intercept.' },
        call_signature: { type: 'string', description: 'Fallback 64-char call signature.' },
        ok: { type: 'boolean', description: 'Whether the underlying tool succeeded.' },
        result_preview: { type: 'string', description: 'Bounded preview cached for read memoization.' },
        timed_out: { type: 'boolean', description: 'Whether sandbox/subprocess execution timed out.' },
        partial_stdout: { type: 'string', description: 'Partial stdout captured prior to timeout.' },
        pending_diffs_delta: { type: 'integer', description: 'Change in unverified staged code/disk diffs.' },
        verification_passed: { type: 'boolean', description: 'Whether automated verification passed.' }
      }
    }
  }),
  defineMcpTool({
    name: 'krusch_grounded_verify_stop',
    title: 'Verify Outer Loop Stop With Zero-Turn Defect-Only Gate',
    description:
      'Approve zero-overhead completion when pendingDiffsCount=0 and output has 0 objective defects while blocking unverified code diffs, empty/null/NaN bailouts, truncations, raw DataFrame/numpy reprs, and leaked <tool_call> tags.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      required: ['session_id'],
      properties: {
        session_id: { type: 'string', description: 'Active grounded session ID.' },
        assistant_text: { type: 'string', description: 'Final assistant response text.' },
        candidate_answer: { description: 'Optional structured or scalar final answer value.' },
        finish_reason: { type: 'string', description: 'Optional provider finish reason (e.g., STOP, MAX_TOKENS).' },
        expect_non_empty_answer: { type: 'boolean', description: 'Flag empty/null/NaN/[]/{} bailouts as output defects.' },
        tool_calls: { type: 'array', items: { type: 'object' } },
        pending_diffs_count: { type: 'integer' },
        mutated_files_count: { type: 'integer' },
        latest_verification_passed: { type: 'boolean' },
        verification_command: { type: 'string' }
      }
    }
  }),
  defineMcpTool({
    name: 'krusch_grounded_summary',
    title: 'Get Grounded Session Telemetry Summary',
    description:
      'Retrieve session metrics including exploratory foraging ratio, memoized reads, spin loops blocked, output defects caught, partial-stdout timeouts, Turn-0 suppressed duplicates, schema token savings, and ordered events.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      required: ['session_id'],
      properties: {
        session_id: { type: 'string', description: 'Grounded session ID.' }
      }
    }
  })
];

/**
 * Create (and optionally connect over stdio) the `krusch-grounded-harness` MCP server.
 *
 * @param {object} [options={}]
 * @param {string} [options.dbPath]
 * @param {boolean} [options.connect=true]
 */
export async function startGroundedMcpServer({
  dbPath = config.dbPath,
  connect = true
} = {}) {
  const harness = createGroundedHarness({ dbPath });

  const handler = async (name, args = {}) => {
    switch (name) {
      case 'krusch_ground_workspace':
        return harness.compileTurnZeroGrounding(args);
      case 'krusch_resolve_scale_profile': {
        const profile = harness.resolveScaleProfile(args);
        return okMcpResult(
          'krusch_resolve_scale_profile',
          `Resolved ${profile.tier} scale profile for "${profile.model || 'default'}"`,
          { profile }
        );
      }
      case 'krusch_grounded_session_start':
        return harness.engine.startSession(args);
      case 'krusch_grounded_intercept':
        return harness.engine.interceptToolCall(args);
      case 'krusch_grounded_outcome':
        return harness.engine.recordToolOutcome(args);
      case 'krusch_grounded_verify_stop':
        return harness.engine.verifyStop(args);
      case 'krusch_grounded_summary':
        return harness.engine.sessionSummary(args);
      default:
        return errorMcpResult(name, 'UNKNOWN_TOOL', `Unknown MCP tool: ${name}`);
    }
  };

  const mcp = await createMcpServer(
    'krusch-grounded-harness',
    '0.2.0',
    GROUNDED_MCP_TOOLS,
    handler,
    { connect, strictTools: true }
  );

  return {
    ...mcp,
    harness,
    close: () => harness.close()
  };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  await startGroundedMcpServer({ connect: true });
}
