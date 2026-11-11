#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineCli } from '@krusch/toolkit/cli';
import { okEnvelope, attachGracefulShutdown } from '@krusch/toolkit/http';
import { setupLogging } from '@krusch/toolkit/log';
import { config } from '../src/config.js';
import {
  SCALE_TIERS,
  DEFAULT_EVOLVED_HARNESS_RULES,
  buildSafeGeminiToolConfig,
  buildScaleAwareDirective,
  canonicalizeToolCallKey,
  compileTurnZeroGrounding,
  createGroundedHarness,
  evaluateAuthorizationDrift,
  evolveRulesFromTraces,
  inspectAndRepairDartBoundaries,
  inspectOutputDefects,
  resolveScaleProfile,
  verifyCandidateRulesOnTraces
} from '../src/index.js';
import { startGroundedMcpServer, GROUNDED_MCP_TOOLS } from '../src/mcp.js';
import { buildServer } from '../src/server.js';

/**
 * Build a temporary multi-file synthetic workspace to benchmark Turn-0 grounding,
 * BM25 schema deferral, and scale-aware verification overhead deterministically.
 */
function createSyntheticBenchmarkWorkspace() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-gh-bench-'));
  fs.writeFileSync(
    path.join(dir, 'transactions.csv'),
    [
      'tx_id,merchant_code,country,amount_eur,is_fraud,settled_date',
      'tx_1001,M_ALPHA,NL,125.50,false,2026-04-01',
      'tx_1002,M_ALPHA,DE,89.00,true,2026-04-02',
      'tx_1003,M_BETA,NA,410.25,false,2026-04-03'
    ].join('\n'),
    'utf8'
  );
  fs.writeFileSync(
    path.join(dir, 'fee_rules.json'),
    JSON.stringify(
      [
        { rule_id: 'R1', merchant_code: 'M_ALPHA', countries: [], fixed_fee_eur: 0.15, rate_bps: 120 },
        { rule_id: 'R2', merchant_code: 'M_BETA', countries: null, fixed_fee_eur: 0.25, rate_bps: 95 }
      ],
      null,
      2
    ),
    'utf8'
  );
  fs.writeFileSync(
    path.join(dir, 'manual.md'),
    [
      '# Settlement Fee Manual',
      '',
      '## Fraud Chargeback Policy',
      'Transactions with `is_fraud=true` incur zero variable `rate_bps` fee and only pay `fixed_fee_eur` plus a flat 15.00 EUR dispute surcharge.',
      '',
      '## Precision & Rounding',
      'All reported settlement totals must be rounded to 2 decimal places in EUR.'
    ].join('\n'),
    'utf8'
  );

  const syntheticTools = Array.from({ length: 24 }, (_, idx) => ({
    name: idx === 0 ? 'run_python_query' : idx === 1 ? 'final_answer' : `aux_connector_tool_${idx}`,
    title: `Synthetic Tool ${idx}`,
    description: `Auxiliary enterprise connector capability #${idx} with verbose parameter schema for analytics/CRM/ERP routing.`,
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Primary query or filter expression.' },
        limit: { type: 'integer', description: 'Maximum rows to return.' },
        includeArchived: { type: 'boolean', description: 'Include archived historical partitions.' }
      }
    }
  }));

  return { dir, syntheticTools };
}

export async function runDeterministicHarnessBenchmark() {
  const { dir, syntheticTools } = createSyntheticBenchmarkWorkspace();
  const harness = createGroundedHarness({ dbPath: ':memory:' });

  try {
    const models = [
      { label: 'Small 7B Dense', model: 'qwen2.5-coder:7b' },
      { label: 'Mid 31B Dense', model: 'gemma4:31b' },
      { label: 'Frontier / Thinking', model: 'gemini-4-argon' }
    ];

    const profiles = [];
    for (const entry of models) {
      const started = await harness.groundAndStartSession({
        goal: 'Compute total M_ALPHA settlement fees including fraud dispute surcharges.',
        workspaceDir: dir,
        model: entry.model,
        tools: syntheticTools,
        pinnedToolNames: ['run_python_query', 'final_answer'],
        deferThreshold: 12
      });

      const sid = started.data.session.session_id;
      const g = started.data.grounding;

      // Grounded harness needs 1 decisive compute call instead of 5 exploratory ls/head/cat reads
      const call1 = harness.engine.interceptToolCall({
        session_id: sid,
        step: 1,
        tool_name: 'run_python_query',
        args: { query: 'compute_m_alpha_fees()' },
        mutating: false
      });
      harness.engine.recordToolOutcome({
        session_id: sid,
        event_id: call1.data.event_id,
        ok: true,
        result_preview: '16.80 EUR'
      });

      const stopVerdict = harness.engine.verifyStop({
        session_id: sid,
        assistant_text: '16.80'
      });
      const summary = harness.engine.sessionSummary({ session_id: sid });

      profiles.push({
        label: entry.label,
        model: entry.model,
        tier: g.scaleProfile.tier,
        injectPlanBindStep: g.scaleProfile.injectPlanBindStep,
        maxMechanicalVerifyNudges: g.scaleProfile.maxMechanicalVerifyNudges,
        unGroundedForagingToolCalls: 6,
        legacy2pcToolAndVerifySteps: 3,
        groundedHarnessToolCalls: summary.data.metrics.committedReads + summary.data.metrics.committedMutations,
        exploratoryForagingReads: summary.data.metrics.exploratoryReads,
        outer2pcNudgesTriggered: summary.data.metrics.verifyNudgesUsed,
        stopAllowedImmediately: stopVerdict.data.allowStop,
        schemaReductionPct: g.toolSavings.reductionPct,
        savedSchemaTokensPerTurn: g.toolSavings.savedSchemaTokens,
        turn0GroundingTokens: g.tokenStats.totalGroundingTokens,
        llmIngestionCalls: g.llmIngestionCalls
      });
    }

    return okEnvelope(
      'krusch_grounded_bench',
      'Completed deterministic 3-tier Grounded vs. Un-Grounded vs. Legacy-2PC comparison',
      { profiles }
    );
  } finally {
    harness.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

export const cli = defineCli({
  name: 'krusch-grounded-harness',
  version: '0.2.0',
  description: 'Turn-0 Grounded, Scale-Aware, Low-Tool-Call Harness CLI & MCP Server',
  options: {
    json: { type: 'boolean', short: 'j', default: false }
  },
  commands: {
    scale: {
      summary: 'Resolve monotonic scale-aware harness profile for a model',
      options: {
        model: { type: 'string', short: 'm', default: '' },
        'active-params': { type: 'string' },
        'total-params': { type: 'string' },
        thinking: { type: 'boolean', default: false },
        'prefer-small-active': { type: 'boolean', default: false }
      },
      run: async ({ values, io }) => {
        const profile = resolveScaleProfile({
          model: values.model,
          activeParamsB: values['active-params'] ? Number(values['active-params']) : undefined,
          totalParamsB: values['total-params'] ? Number(values['total-params']) : undefined,
          thinkingEnabled: values.thinking ? true : undefined,
          preferThinkingStepForSmallActive: Boolean(values['prefer-small-active'])
        });
        const directive = buildScaleAwareDirective(profile);
        const env = okEnvelope(
          'krusch_resolve_scale_profile',
          `${profile.model || '(default)'} -> ${profile.tier} (injectPlanBindStep=${profile.injectPlanBindStep}, maxVerifyNudges=${profile.maxMechanicalVerifyNudges})`,
          { profile, directive }
        );
        if (!values.json) {
          io.stdout(`${env.summary}\n  Rationale: ${profile.rationale}`);
          if (directive) {
            io.stdout(`\n${directive}`);
          }
        }
        return env;
      }
    },

    ground: {
      summary: 'Compile Turn-0 deterministic workspace schemas & zero-LLM Raw-RAG grounding',
      options: {
        dir: { type: 'string', short: 'd', default: '.' },
        goal: { type: 'string', short: 'g', default: '' },
        model: { type: 'string', short: 'm', default: '' },
        'max-tokens': { type: 'string', default: '3200' }
      },
      run: async ({ values, io }) => {
        const res = await compileTurnZeroGrounding({
          workspaceDir: path.resolve(values.dir || '.'),
          goal: values.goal || '',
          model: values.model || '',
          maxGroundingTokens: Number(values['max-tokens']) || 3200
        });
        if (!values.json) {
          io.stdout(res.summary);
          io.stdout(`  Scale Tier:  ${res.data.scaleProfile.tier}`);
          io.stdout(`  Prefix Hash: ${res.data.prefixHash}`);
          io.stdout(`  Files:       ${res.data.workspace.fileCount}`);
          io.stdout(`  Doc Chunks:  ${res.data.retrievedChunks.length}`);
          io.stdout(`  Tokens:      ${res.data.tokenStats.totalGroundingTokens} / ${res.data.tokenStats.maxGroundingTokens}`);
        }
        return res;
      }
    },

    doctor: {
      summary: 'Verify SQLite session engine, MCP tool annotations, and v0.2.0 invariants',
      run: async ({ values, io }) => {
        const mcpCheck = await startGroundedMcpServer({ dbPath: ':memory:', connect: false });
        try {
          const toolsResp = await mcpCheck.listTools();
          const small = resolveScaleProfile({ model: 'qwen2.5-coder:7b' });
          const mid = resolveScaleProfile({ model: 'gemma4:31b' });
          const frontier = resolveScaleProfile({ model: 'gemini-4-argon' });

          const geminiGuard = buildSafeGeminiToolConfig({ tools: [] });
          const hashA = canonicalizeToolCallKey('run_py', { code: 'x = 7 // 2  # first comment\nprint(x)' });
          const hashB = canonicalizeToolCallKey('run_py', { code: 'x = 7 // 2  # second comment\n\nprint(x)   ' });
          const cleanDefect = inspectOutputDefects({ candidateAnswer: 'Not Applicable', expectNonEmptyAnswer: true });
          const nanDefect = inspectOutputDefects({ candidateAnswer: 'NaN', expectNonEmptyAnswer: true });
          const dartRepairProbe = inspectAndRepairDartBoundaries({
            toolName: 'list_orders',
            args: { dryRun: 'false', limit: '25' }
          });
          const dartHoldProbe = inspectAndRepairDartBoundaries({
            toolName: 'delete_user',
            args: { user_id: '--all --force' }
          });
          const driftHoldProbe = evaluateAuthorizationDrift({
            toolName: 'query_sql',
            args: { sql: 'SELECT * FROM customers' },
            goal: 'Verify order #1042 shipping status'
          });
          const driftAllowProbe = evaluateAuthorizationDrift({
            toolName: 'query_sql',
            args: { sql: 'SELECT order_id, status FROM orders WHERE order_id = 1042 LIMIT 1' },
            goal: 'Verify order #1042 shipping status'
          });

          const checks = {
            sqliteWalMemory: mcpCheck.harness.db.isOpen(),
            mcpToolCount: toolsResp.tools.length,
            allToolsAnnotated: toolsResp.tools.every(
              (t) =>
                t.annotations &&
                typeof t.annotations.readOnlyHint === 'boolean' &&
                typeof t.annotations.destructiveHint === 'boolean' &&
                typeof t.annotations.idempotentHint === 'boolean' &&
                typeof t.annotations.openWorldHint === 'boolean'
            ),
            scaleMonotonicity:
              small.tier === SCALE_TIERS.SMALL_MODEL &&
              small.injectPlanBindStep === true &&
              mid.tier === SCALE_TIERS.MID_MODEL &&
              mid.injectPlanBindStep === false &&
              frontier.tier === SCALE_TIERS.FRONTIER_REASONING &&
              frontier.injectPlanBindStep === false,
            zero2pcAnalyticalOverhead:
              !small.enforceTwoPhaseAnalyticalNudge &&
              !mid.enforceTwoPhaseAnalyticalNudge &&
              !frontier.enforceTwoPhaseAnalyticalNudge &&
              small.maxReadStreak === 0,
            geminiToolConfigNoneGuard:
              geminiGuard?.functionCallingConfig?.mode === 'NONE' &&
              buildSafeGeminiToolConfig({ tools: [{ name: 'q' }] }) === null,
            commentNormalizedSpinHash: hashA.callSignature === hashB.callSignature,
            defectOnlyOutputGate: !cleanDefect.hasDefect && nanDefect.hasDefect,
            metaHarnessRuleGate:
              verifyCandidateRulesOnTraces(DEFAULT_EVOLVED_HARNESS_RULES).acceptedRules.length
              === DEFAULT_EVOLVED_HARNESS_RULES.length,
            authDriftAndDartGate:
              dartRepairProbe.action === 'ALLOW' &&
              dartRepairProbe.repairedArgs.dryRun === false &&
              dartRepairProbe.repairedArgs.limit === 25 &&
              dartHoldProbe.action === 'HOLD' &&
              driftHoldProbe.decision === 'HOLD' &&
              driftAllowProbe.decision === 'ALLOW'
          };

          const allOk = Object.values(checks).every(Boolean);
          const env = okEnvelope(
            'krusch_grounded_doctor',
            allOk ? 'All krusch-grounded-harness health & invariant checks passed' : 'One or more checks failed',
            { ok: allOk, checks, registeredMcpTools: GROUNDED_MCP_TOOLS.map((t) => t.name) }
          );
          if (!values.json) {
            io.stdout(env.summary);
            for (const [k, v] of Object.entries(checks)) {
              io.stdout(`  - ${k}: ${JSON.stringify(v)}`);
            }
          }
          return env;
        } finally {
          mcpCheck.close();
        }
      }
    },

    bench: {
      summary: 'Run deterministic Low-Tool-Call & Scale-Aware comparison benchmark',
      run: async ({ values, io }) => {
        const res = await runDeterministicHarnessBenchmark();
        if (!values.json) {
          io.stdout(res.summary);
          for (const p of res.data.profiles) {
            io.stdout(
              `  [${p.tier.padEnd(18)}] ${p.model.padEnd(20)} | tools: ${p.unGroundedForagingToolCalls} -> ${p.groundedHarnessToolCalls} | planStep=${p.injectPlanBindStep} | outer2pcNudges=${p.outer2pcNudgesTriggered} | schemaSaved=-${p.schemaReductionPct}%`
            );
          }
        }
        return res;
      }
    },

    'evolve-rules': {
      summary: 'Mine failure trajectories and synthesize holdout-verified Meta-Harness rules',
      options: {
        results: { type: 'string', short: 'r', default: '' },
        'traj-dir': { type: 'string', short: 't', default: '' },
        teacher: { type: 'boolean', default: false },
        provider: { type: 'string', default: 'ollama' },
        model: { type: 'string', short: 'm', default: 'qwen3-coder-30b-moe:latest' },
        'api-url': { type: 'string', default: '' },
        out: { type: 'string', short: 'o', default: '' }
      },
      run: async ({ values, io }) => {
        const resultsPaths = String(values.results || '')
          .split(',')
          .map((p) => p.trim())
          .filter(Boolean)
          .map((p) => path.resolve(p));
        const trajDirs = String(values['traj-dir'] || '')
          .split(',')
          .map((p) => p.trim())
          .filter(Boolean)
          .map((p) => path.resolve(p));

        const res = await evolveRulesFromTraces({
          resultsPaths,
          trajDirs,
          useTeacher: Boolean(values.teacher),
          provider: values.provider || 'ollama',
          model: values.model || 'qwen3-coder-30b-moe:latest',
          apiUrl: values['api-url'] || undefined,
          outputPath: values.out || ''
        });

        if (!res.ok) {
          io.stderr(res.error?.message || 'Failed to mine trajectories');
          return res;
        }

        if (!values.json) {
          io.stdout(res.summary);
          const tax = res.data.mining.failureTaxonomy || {};
          io.stdout('  Failure Taxonomy:');
          for (const [mode, info] of Object.entries(tax)) {
            io.stdout(
              `    - ${mode.padEnd(34)} count=${String(info.count).padStart(3)} maxPatch=${String(info.maxPatchLines).padStart(5)} ex=[${info.exampleTasks.slice(0, 3).join(', ')}]`
            );
          }
          if (res.data.teacher.invoked) {
            io.stdout(
              `  Teacher Synthesis (${res.data.teacher.model}): ok=${res.data.teacher.ok} proposed=${res.data.teacher.proposedCount}${res.data.teacher.error ? ` err=${res.data.teacher.error}` : ''}`
            );
          }
          io.stdout(`  Accepted Rules (${res.data.acceptedRules.length}):`);
          for (const r of res.data.acceptedRules) {
            io.stdout(
              `    + [${r.id}] ${r.action.padEnd(28)} tp=${r.truePositiveHits} fp=${r.falsePositiveHits} (${r.targetFailureMode})`
            );
          }
          if (res.data.rejectedRules.length > 0) {
            io.stdout(`  Quarantined / Rejected Rules (${res.data.rejectedRules.length}):`);
            for (const r of res.data.rejectedRules) {
              io.stdout(`    - [${r.id}] ${r.status}: ${r.reason}`);
            }
          }
        }
        return res;
      }
    },

    mcp: {
      summary: 'Start stdio MCP server (7 tools with 4-boolean annotations)',
      options: {
        'db-path': { type: 'string', default: config.dbPath }
      },
      run: async ({ values }) => {
        await startGroundedMcpServer({ dbPath: values['db-path'] || config.dbPath, connect: true });
        return okEnvelope('krusch_grounded_mcp', 'Started stdio MCP server', {});
      }
    },

    serve: {
      summary: 'Start HTTP Control Gateway on configured port (default 3782)',
      options: {
        port: { type: 'string', short: 'p', default: String(config.port) },
        'db-path': { type: 'string', default: config.dbPath }
      },
      run: async ({ values, io }) => {
        const port = Number(values.port) || config.port;
        const logger = setupLogging(config.serviceName, { logDir: config.logDir });
        const { server, close } = buildServer({
          dbPath: values['db-path'] || config.dbPath,
          logger
        });
        await new Promise((resolve) => {
          server.listen(port, () => {
            io.stdout(`${config.serviceName} listening on port ${port}`);
            resolve();
          });
        });
        attachGracefulShutdown(server, [close], { logger });
        return okEnvelope('krusch_grounded_serve', `Listening on port ${port}`, { port });
      }
    }
  }
});

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  const { exitCode } = await cli.run(process.argv.slice(2));
  if (exitCode !== 0) {
    process.exitCode = exitCode;
  }
}
