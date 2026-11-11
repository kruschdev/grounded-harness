/**
 * @module krusch-grounded-harness
 * @description Turn-0 Grounded, Scale-Aware, Low-Tool-Call Harness (`INV-GH-01` .. `INV-GH-08`).
 *
 * Replaces intrusive unconditional 2-phase outer-loop stop-nudging with:
 * 1. Deterministic zero-LLM Turn-0 workspace schema & Raw-RAG grounding (`compileTurnZeroGrounding`)
 * 2. Monotonic scale-aware thinking/verification curves (`SMALL_MODEL` vs `MID_MODEL` vs `FRONTIER_REASONING`)
 * 3. Deferred BM25 tool gating, delta-chunk deduplication, and read memoization (`maxReadStreak === 0`)
 * 4. Passive safety rails (`createFrozenPolicyFloor`, secret-leak & duplicate-write blocks, staged-diff-only `FORCE_VERIFY`)
 */

import fs from 'node:fs';
import path from 'node:path';
import { openSqliteDb } from '@krusch/toolkit/sqlite';
import { okEnvelope } from '@krusch/toolkit/http';
import {
  SCALE_TIERS,
  inferModelScaleMetadata,
  resolveScaleProfile,
  buildScaleAwareDirective
} from './scale-policy.js';
import {
  measureToolSchemaSavings,
  createToolBudgetGate,
  createDeltaContextTracker
} from './delta-tool-gate.js';
import {
  introspectWorkspaceSchemas,
  compileTurnZeroGrounding
} from './grounding-compiler.js';
import {
  GROUNDED_HARNESS_SCHEMA_SQL,
  buildSafeGeminiToolConfig,
  normalizeCodeSnippetForHash,
  inspectOutputDefects,
  formatTimeoutWithPartialStdout,
  execCommandWithPartialStdout,
  classifyToolMutability,
  canonicalizeToolCallKey,
  createGroundedSessionEngine
} from './grounded-session-engine.js';
import {
  SYNTHESIZED_RULE_ACTIONS,
  DEFAULT_EVOLVED_HARNESS_RULES,
  compileSafeRuleRegex,
  compileExecutableRules,
  extractShellCommandsFromTrajectory,
  mineFailureTrajectories,
  verifyCandidateRulesOnTraces,
  synthesizeRulesWithTeacher,
  evolveRulesFromTraces
} from './trace-rule-synthesizer.js';
import {
  SENSITIVE_SCOPE_DOMAINS,
  AUTH_DRIFT_REASON_CODES,
  inferGoalAttestedScopes,
  inspectAndRepairDartBoundaries,
  evaluateAuthorizationDrift,
  auditTrajectoryAuthorizationDrift
} from './auth-drift-guard.js';

export {
  SCALE_TIERS,
  inferModelScaleMetadata,
  resolveScaleProfile,
  buildScaleAwareDirective,
  measureToolSchemaSavings,
  createToolBudgetGate,
  createDeltaContextTracker,
  introspectWorkspaceSchemas,
  compileTurnZeroGrounding,
  GROUNDED_HARNESS_SCHEMA_SQL,
  buildSafeGeminiToolConfig,
  normalizeCodeSnippetForHash,
  inspectOutputDefects,
  formatTimeoutWithPartialStdout,
  execCommandWithPartialStdout,
  classifyToolMutability,
  canonicalizeToolCallKey,
  createGroundedSessionEngine,
  SYNTHESIZED_RULE_ACTIONS,
  DEFAULT_EVOLVED_HARNESS_RULES,
  compileSafeRuleRegex,
  compileExecutableRules,
  extractShellCommandsFromTrajectory,
  mineFailureTrajectories,
  verifyCandidateRulesOnTraces,
  synthesizeRulesWithTeacher,
  evolveRulesFromTraces,
  SENSITIVE_SCOPE_DOMAINS,
  AUTH_DRIFT_REASON_CODES,
  inferGoalAttestedScopes,
  inspectAndRepairDartBoundaries,
  evaluateAuthorizationDrift,
  auditTrajectoryAuthorizationDrift
};

/**
 * Convenience factory creating a complete Grounded Harness backed by `openSqliteDb` (`@krusch/toolkit/sqlite`)
 * with one-call `groundAndStartSession` Turn-0 compilation + session seeding.
 *
 * @param {object} [options={}]
 * @param {string} [options.dbPath=':memory:']
 * @param {object|null} [options.db=null]
 * @param {string[]} [options.protectedPaths=[]]
 * @param {Array<object>} [options.extraFloorRules=[]]
 */
export function createGroundedHarness({
  dbPath = ':memory:',
  db = null,
  protectedPaths = [],
  extraFloorRules = [],
  evolvedRules = DEFAULT_EVOLVED_HARNESS_RULES
} = {}) {
  const ownsDb = !db;
  if (ownsDb && dbPath !== ':memory:') {
    const resolvedDir = path.dirname(path.resolve(dbPath));
    fs.mkdirSync(resolvedDir, { recursive: true });
  }
  const activeDb = db || openSqliteDb(dbPath);
  const engine = createGroundedSessionEngine({
    db: activeDb,
    protectedPaths,
    extraFloorRules,
    evolvedRules
  });

  /**
   * Compiles Turn-0 workspace grounding and immediately starts a tracked SQLite session
   * pre-seeded with `seenChunkIds`, `fileDigests`, `prefixHash`, and schema token savings.
   *
   * @param {object} [params={}]
   */
  async function groundAndStartSession(params = {}) {
    const groundingEnv = await compileTurnZeroGrounding(params);
    const gData = groundingEnv.data;

    const sessionEnv = await engine.startSession({
      session_id: params.session_id ?? params.sessionId,
      goal: params.goal,
      model: params.model,
      activeParamsB: params.activeParamsB,
      totalParamsB: params.totalParamsB,
      thinkingEnabled: params.thinkingEnabled,
      thinkingLevel: params.thinkingLevel,
      reasoningEffort: params.reasoningEffort,
      explicitTier: params.explicitTier,
      preferThinkingStepForSmallActive: params.preferThinkingStepForSmallActive,
      anchor_date: params.anchor_date ?? params.anchorDate ?? '',
      prefix_hash: gData.prefixHash,
      seen_chunk_ids: gData.seenChunkIds,
      file_digests: gData.fileDigests,
      all_tools: params.tools || [],
      exposed_tools: gData.exposedTools || [],
      turn0_tokens: gData.tokenStats?.totalGroundingTokens ?? 0,
      max_duplicate_writes: params.max_duplicate_writes ?? params.maxDuplicateWrites ?? 1,
      allowed_scopes: params.allowed_scopes ?? params.allowedScopes,
      max_bulk_limit: params.max_bulk_limit ?? params.maxBulkLimit,
      enable_auth_drift_guard: params.enable_auth_drift_guard ?? params.enableAuthDriftGuard,
      enable_dart_boundary_guard: params.enable_dart_boundary_guard ?? params.enableDartBoundaryGuard
    });

    if (!sessionEnv.ok) {
      return sessionEnv;
    }

    return okEnvelope(
      'krusch_ground_and_start',
      `Grounded workspace and started session ${sessionEnv.data.session_id} (${gData.scaleProfile.tier})`,
      {
        session: sessionEnv.data,
        grounding: gData
      }
    );
  }

  function close() {
    if (ownsDb && activeDb.isOpen()) {
      activeDb.close();
    }
  }

  return {
    db: activeDb,
    engine,
    groundAndStartSession,
    compileTurnZeroGrounding,
    resolveScaleProfile,
    close
  };
}
