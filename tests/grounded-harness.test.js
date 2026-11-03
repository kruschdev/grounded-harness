import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { openSqliteDb } from '@krusch/toolkit/sqlite';
import {
  SCALE_TIERS,
  inferModelScaleMetadata,
  resolveScaleProfile,
  buildScaleAwareDirective,
  measureToolSchemaSavings,
  createToolBudgetGate,
  createDeltaContextTracker,
  introspectWorkspaceSchemas,
  compileTurnZeroGrounding,
  buildSafeGeminiToolConfig,
  normalizeCodeSnippetForHash,
  inspectOutputDefects,
  execCommandWithPartialStdout,
  canonicalizeToolCallKey,
  createGroundedSessionEngine,
  createGroundedHarness
} from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, '..');

function makeTempWorkspace() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-gh-test-'));

  fs.writeFileSync(
    path.join(dir, 'orders.csv'),
    [
      'order_id,customer_note,region_code,amount_usd,is_priority,order_date',
      '101,"Fast, fragile delivery",EU,249.95,true,2026-06-10',
      '102,"Standard shipping",NA,80.00,false,2026-06-11',
      '103,,US,19.50,false,2026-06-12'
    ].join('\n'),
    'utf8'
  );

  fs.writeFileSync(
    path.join(dir, 'tiers.json'),
    JSON.stringify([
      { tier: 'GOLD', regions: [], override_cap: null, discount_pct: 15, min_spend: 200 },
      { tier: 'STANDARD', regions: ['EU', 'NA'], override_cap: 50, discount_pct: 0, min_spend: 0 }
    ]),
    'utf8'
  );

  const sqDb = openSqliteDb(path.join(dir, 'ledger.sqlite'));
  sqDb.exec(`
    CREATE TABLE invoices (
      invoice_id TEXT PRIMARY KEY,
      total_cents INTEGER NOT NULL,
      paid INTEGER NOT NULL DEFAULT 0
    );
    INSERT INTO invoices (invoice_id, total_cents, paid) VALUES ('inv_1', 24995, 1), ('inv_2', 8000, 0);
  `);
  sqDb.close();

  fs.writeFileSync(
    path.join(dir, 'pricing.js'),
    'export function computeOrderTotal(subtotal, discountPct) { return subtotal * (1 - discountPct / 100); }\n',
    'utf8'
  );

  fs.writeFileSync(
    path.join(dir, 'policy.md'),
    [
      '# Fulfillment & Pricing Manual',
      '',
      '## Priority Handling Rule',
      'Orders with `is_priority=true` receive same-day dispatch and an automatic 15% GOLD tier discount when `amount_usd >= 200`.',
      '',
      '## Refund Abstention Policy',
      'Agents must never issue refunds above 500 USD without explicit VP Finance sign-off.'
    ].join('\n'),
    'utf8'
  );

  // Secret .env file must be ignored by workspace grounder
  fs.writeFileSync(path.join(dir, '.env'), 'SECRET_API_KEY=should_never_be_indexed\n', 'utf8');

  return dir;
}

describe('krusch-grounded-harness v0.2.0 — Invariants INV-GH-01 .. INV-GH-10', () => {
  test('INV-GH-01, INV-GH-02 & INV-GH-09: Zero-LLM Turn-0 Grounding, CSV "NA" & JSON null/[] Hazard Flags, Gemini NONE Guard & Prefix Hash', async () => {
    const dir = makeTempWorkspace();
    try {
      const schema = introspectWorkspaceSchemas(dir);
      assert.equal(schema.fileCount, 5); // orders.csv, tiers.json, ledger.sqlite, pricing.js, policy.md (.env skipped!)
      assert.ok(!Object.keys(schema.fileDigests).some((f) => f.includes('.env')));
      assert.match(schema.schemaSummaryText, /orders\.csv/);
      assert.match(schema.schemaSummaryText, /invoices/);
      assert.match(schema.schemaSummaryText, /computeOrderTotal/);

      // Pattern 4: CSV "NA" string literal preserved & keep_default_na=False hazard flagged
      const csvFile = schema.files.find((f) => f.relPath === 'orders.csv');
      assert.equal(csvFile.hasLiteralNaHazard, true);
      assert.deepEqual(csvFile.naHazardColumns, ['region_code']);
      const regionCol = csvFile.columns.find((c) => c.name === 'region_code');
      assert.equal(regionCol.inferredType, 'string');
      assert.equal(regionCol.hasLiteralNaString, true);
      assert.ok(regionCol.sampleValues.includes('NA'));
      assert.match(schema.schemaSummaryText, /keep_default_na=False/);

      // Pattern 4: JSON null vs empty-list [] wildcard fields flagged
      const jsonFile = schema.files.find((f) => f.relPath === 'tiers.json');
      assert.ok(jsonFile.emptyArrayFields.includes('regions'));
      assert.ok(jsonFile.nullFields.includes('override_cap'));
      assert.ok(jsonFile.wildcardCandidateFields.includes('regions'));
      assert.match(schema.schemaSummaryText, /JSON NULL \/ EMPTY-LIST \[\] WILDCARD HAZARD/);

      // Pattern 1: Tool-less Turn-0 grounding emits geminiToolConfig mode NONE
      const gNoTools = await compileTurnZeroGrounding({
        goal: 'Compute North America priority order discounts.',
        workspaceDir: dir,
        model: 'gemini-4-argon',
        tools: []
      });
      assert.deepEqual(gNoTools.data.geminiToolConfig, { functionCallingConfig: { mode: 'NONE' } });

      const tools = Array.from({ length: 18 }, (_, i) => ({
        name: i === 0 ? 'query_sql' : `connector_tool_${i}`,
        description: `Connector tool #${i} for enterprise data retrieval and sync.`,
        inputSchema: { type: 'object', properties: { id: { type: 'string' }, filter: { type: 'string' } } }
      }));

      const g1 = await compileTurnZeroGrounding({
        goal: 'How are priority orders discounted when amount_usd >= 200?',
        workspaceDir: dir,
        model: 'gemma4:31b',
        standingInvariants: ['Never mutate production ledgers without verification.'],
        tools,
        pinnedToolNames: ['query_sql'],
        deferThreshold: 12,
        maxGroundingTokens: 2800
      });

      const g2 = await compileTurnZeroGrounding({
        goal: 'What is the VP Finance refund threshold rule?',
        workspaceDir: dir,
        model: 'gemma4:31b',
        standingInvariants: ['Never mutate production ledgers without verification.'],
        tools,
        pinnedToolNames: ['query_sql'],
        deferThreshold: 12,
        maxGroundingTokens: 2800
      });

      assert.equal(g1.ok, true);
      assert.equal(g1.data.llmIngestionCalls, 0);
      assert.equal(g1.data.geminiToolConfig, null);
      assert.ok(g1.data.retrievedChunks.length >= 1);
      assert.ok(g1.data.tokenStats.totalGroundingTokens <= 2800);
      assert.equal(g1.data.prefixHash.length, 64);
      assert.equal(g1.data.prefixHash, g2.data.prefixHash);
      assert.notEqual(g1.data.compiledContextBlock, g2.data.compiledContextBlock);
      assert.ok(g1.data.toolSavings.reductionPct > 50);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('INV-GH-03: Monotonic Scale-Aware Thinking & Verification Curve across Small, Mid, MoE & Frontier models', () => {
    const small7b = resolveScaleProfile({ model: 'qwen2.5-coder:7b' });
    assert.equal(small7b.tier, SCALE_TIERS.SMALL_MODEL);
    assert.equal(small7b.injectPlanBindStep, true);
    assert.equal(small7b.softHoldPlaceholdersAndDates, true);
    assert.equal(small7b.rescueSerializedToolCalls, true);
    assert.equal(small7b.maxMechanicalVerifyNudges, 1);
    assert.equal(small7b.enforceZeroMutationImperativeNudge, false);
    assert.equal(small7b.enforceTwoPhaseAnalyticalNudge, false);
    assert.equal(small7b.maxReadStreak, 0);
    assert.match(buildScaleAwareDirective(small7b), /PLAN -> BIND -> ACT/);

    const edge4b = resolveScaleProfile({ model: 'gemma4:e4b' });
    assert.equal(edge4b.tier, SCALE_TIERS.SMALL_MODEL);
    assert.equal(edge4b.inferredActiveParamsB, 4);

    const mid31b = resolveScaleProfile({ model: 'gemma4:31b' });
    assert.equal(mid31b.tier, SCALE_TIERS.MID_MODEL);
    assert.equal(mid31b.injectPlanBindStep, false);
    assert.equal(mid31b.softHoldPlaceholdersAndDates, false);
    assert.equal(mid31b.rescueSerializedToolCalls, true);
    assert.equal(mid31b.maxMechanicalVerifyNudges, 0);
    assert.equal(buildScaleAwareDirective(mid31b), '');

    const moeDefault = resolveScaleProfile({ model: 'qwen3-coder-30b-moe:latest' });
    assert.equal(moeDefault.tier, SCALE_TIERS.MID_MODEL);
    assert.equal(moeDefault.isMoe, true);
    assert.equal(moeDefault.inferredActiveParamsB, 3);
    assert.equal(moeDefault.inferredTotalParamsB, 30);

    const moeOptInSmall = resolveScaleProfile({
      model: 'qwen3-coder-30b-moe:latest',
      preferThinkingStepForSmallActive: true
    });
    assert.equal(moeOptInSmall.tier, SCALE_TIERS.SMALL_MODEL);
    assert.equal(moeOptInSmall.injectPlanBindStep, true);

    const frontier120b = resolveScaleProfile({ model: 'gpt-oss:120b' });
    assert.equal(frontier120b.tier, SCALE_TIERS.FRONTIER_REASONING);
    assert.equal(frontier120b.injectPlanBindStep, false);
    assert.equal(frontier120b.rescueSerializedToolCalls, false);
    assert.equal(frontier120b.maxMechanicalVerifyNudges, 0);

    const argon = resolveScaleProfile({ model: 'gemini-4-argon' });
    assert.equal(argon.tier, SCALE_TIERS.FRONTIER_REASONING);
    assert.equal(argon.thinkingEnabled, true);

    const smallWithNativeThinking = resolveScaleProfile({
      model: 'qwen3:8b',
      thinkingEnabled: true
    });
    assert.equal(smallWithNativeThinking.tier, SCALE_TIERS.FRONTIER_REASONING);
    assert.equal(smallWithNativeThinking.injectPlanBindStep, false);

    const metaMixtral = inferModelScaleMetadata('mixtral-8x7b-instruct');
    assert.equal(metaMixtral.isMoe, true);
    assert.equal(metaMixtral.totalParamsB, 47);
  });

  test('INV-GH-04: Deferred BM25 Tool Gate, Comment-Normalized Call Hashing, BLOCK_SPIN_LOOP & Unlimited Read Streak', async () => {
    const tools = Array.from({ length: 20 }, (_, idx) => ({
      name: idx === 0 ? 'core_execute' : `crm_billing_sync_${idx}`,
      title: `CRM Billing Sync ${idx}`,
      description: `Synchronize billing invoice records and subscription ledgers (#${idx}).`,
      inputSchema: {
        type: 'object',
        properties: { accountId: { type: 'string' }, dryRun: { type: 'boolean' } },
        required: ['accountId']
      },
      handler: async (args) => ({ synced: args.accountId, toolIdx: idx })
    }));

    const gate = createToolBudgetGate({
      tools,
      pinnedToolNames: ['core_execute'],
      deferThreshold: 12
    });
    assert.equal(gate.deferred, true);
    assert.equal(gate.exposedTools.length, 4);
    assert.ok(gate.savings.reductionPct > 65);
    assert.equal(measureToolSchemaSavings([], []).reductionPct, 0);

    const searchHits = await gate.invokeMetaTool('tool_search', { query: 'billing invoice', limit: 3 });
    assert.equal(searchHits.ok, true);
    assert.equal(searchHits.data.matches.length, 3);

    const callHit = await gate.invokeMetaTool('tool_call', {
      toolName: 'crm_billing_sync_2',
      args: { accountId: 'acct_42' }
    });
    assert.equal(callHit.ok, true);
    assert.equal(callHit.data.result.synced, 'acct_42');

    // Quote-safe & Python floor-division-safe normalization
    const k1 = canonicalizeToolCallKey('run_py', {
      code: 'ratio = 19 // 4  # initial attempt\nlabel = "item#1"\nprint(ratio)'
    });
    const k2 = canonicalizeToolCallKey('run_py', {
      code: 'ratio = 19 // 4  # retry with different comment\n\nlabel = "item#1"   \nprint(ratio)'
    });
    const kDiv = canonicalizeToolCallKey('run_py', {
      code: 'ratio = 19 / 4\nlabel = "item#1"\nprint(ratio)'
    });
    assert.equal(k1.callSignature, k2.callSignature);
    assert.notEqual(k1.callSignature, kDiv.callSignature);
    assert.match(normalizeCodeSnippetForHash('x = 7 // 2 # c', 'code'), /7 \/\/ 2/);

    // Tracker delta deduplication
    const tracker = createDeltaContextTracker({
      initialChunkIds: ['win_0', 'win_1'],
      initialFileDigests: { 'orders.csv': 'sha_orders_v1' }
    });
    const filtered = tracker.filterDeltaChunks([
      { chunkId: 'win_0', text: 'already at turn 0' },
      { chunkId: 'win_2', text: 'fresh evidence' }
    ]);
    assert.equal(filtered.suppressedCount, 1);
    assert.equal(filtered.novelChunks.length, 1);
    assert.equal(filtered.novelChunks[0].chunkId, 'win_2');
    assert.equal(tracker.hasSeenFileDigest('orders.csv', 'sha_orders_v1'), true);

    // Unlimited read streak (12 distinct reads succeed with 0 BLOCK_READ_STREAK) + MEMOIZED_PRIOR_READ -> BLOCK_SPIN_LOOP
    const harness = createGroundedHarness({ dbPath: ':memory:' });
    try {
      await harness.engine.startSession({
        session_id: 'sess_reads',
        goal: 'Correlate 12 monthly ledger partitions',
        model: 'gemma4:31b',
        seen_chunk_ids: ['win_0'],
        file_digests: { 'orders.csv': 'sha_orders_v1' }
      });

      for (let i = 1; i <= 12; i += 1) {
        const res = harness.engine.interceptToolCall({
          session_id: 'sess_reads',
          step: i,
          tool_name: 'query_partition',
          args: { month: i }
        });
        assert.equal(res.data.decision, 'ALLOW');
        harness.engine.recordToolOutcome({
          session_id: 'sess_reads',
          event_id: res.data.event_id,
          ok: true,
          result_preview: `Month ${i}: 1200 rows`
        });
      }

      // First repeat returns MEMOIZED_PRIOR_READ
      const memoRes = harness.engine.interceptToolCall({
        session_id: 'sess_reads',
        step: 13,
        tool_name: 'query_partition',
        args: { month: 3 }
      });
      assert.equal(memoRes.data.decision, 'MEMOIZED');
      assert.equal(memoRes.data.reason, 'MEMOIZED_PRIOR_READ');
      assert.equal(memoRes.data.cachedPreview, 'Month 3: 1200 rows');

      // Stubborn repeat after MEMOIZED_PRIOR_READ triggers passive BLOCK_SPIN_LOOP
      const spinAfterMemo = harness.engine.interceptToolCall({
        session_id: 'sess_reads',
        step: 14,
        tool_name: 'query_partition',
        args: { month: 3 }
      });
      assert.equal(spinAfterMemo.data.decision, 'BLOCK');
      assert.equal(spinAfterMemo.data.reason, 'BLOCK_SPIN_LOOP');

      // Re-commented identical failing Python snippet triggers passive BLOCK_SPIN_LOOP
      const pyFail1 = harness.engine.interceptToolCall({
        session_id: 'sess_reads',
        step: 15,
        tool_name: 'query_py',
        args: { code: 'df = load_missing()  # attempt 1' },
        mutating: false
      });
      assert.equal(pyFail1.data.decision, 'ALLOW');
      harness.engine.recordToolOutcome({
        session_id: 'sess_reads',
        event_id: pyFail1.data.event_id,
        ok: false,
        result_preview: 'NameError: load_missing is not defined'
      });

      const pyFail2 = harness.engine.interceptToolCall({
        session_id: 'sess_reads',
        step: 16,
        tool_name: 'query_py',
        args: { code: 'df = load_missing()  # attempt 2 same code' },
        mutating: false
      });
      assert.equal(pyFail2.data.decision, 'BLOCK');
      assert.equal(pyFail2.data.reason, 'BLOCK_SPIN_LOOP');
      assert.match(pyFail2.data.cachedPreview, /NameError/);

      // Re-reading unchanged Turn-0 file digest returns ALREADY_GROUNDED_TURN_ZERO
      const turn0FileRes = harness.engine.interceptToolCall({
        session_id: 'sess_reads',
        step: 17,
        tool_name: 'read_file',
        args: { relPath: 'orders.csv', fileDigest: 'sha_orders_v1' }
      });
      assert.equal(turn0FileRes.data.decision, 'MEMOIZED');
      assert.equal(turn0FileRes.data.reason, 'ALREADY_GROUNDED_TURN_ZERO');

      const summary = harness.engine.sessionSummary({ session_id: 'sess_reads' });
      assert.equal(summary.data.metrics.committedReads, 12);
      assert.equal(summary.data.metrics.memoizedReads, 1);
      assert.equal(summary.data.metrics.spinLoopsBlocked, 2);
      assert.equal(summary.data.metrics.turn0DuplicatesSuppressed, 1);
    } finally {
      harness.close();
    }
  });

  test('INV-GH-05 & INV-GH-10: Zero-Turn Defect-Only Output Gate, Staged-Diff FORCE_VERIFY, Zero Abstention Nagging & Timeout Partial Stdout', async () => {
    const db = openSqliteDb(':memory:');
    const engine = createGroundedSessionEngine({ db });
    try {
      assert.deepEqual(buildSafeGeminiToolConfig({ tools: [] }), { functionCallingConfig: { mode: 'NONE' } });
      assert.equal(inspectOutputDefects({ candidateAnswer: 'Not Applicable', expectNonEmptyAnswer: true }).hasDefect, false);
      assert.equal(inspectOutputDefects({ candidateAnswer: 0, expectNonEmptyAnswer: true }).hasDefect, false);
      assert.equal(inspectOutputDefects({ candidateAnswer: 'N/A', expectNonEmptyAnswer: true }).hasDefect, false);

      // 1. SMALL_MODEL session
      await engine.startSession({
        session_id: 'sess_small',
        goal: 'Send vendor onboarding email and schedule kickoff',
        model: 'qwen2.5-coder:7b',
        anchor_date: '2026-02-20'
      });

      const floorBlock = engine.interceptToolCall({
        session_id: 'sess_small',
        step: 1,
        tool_name: 'bash',
        args: { command: 'rm -rf /' }
      });
      assert.equal(floorBlock.data.decision, 'BLOCK');

      const fakeOpenAiKey = ['sk', '-', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4'].join('');
      const secretBlock = engine.interceptToolCall({
        session_id: 'sess_small',
        step: 2,
        tool_name: 'send_email',
        args: { to: 'vendor@example.org', body: `Token: ${fakeOpenAiKey}` }
      });
      assert.equal(secretBlock.data.decision, 'BLOCK');
      assert.equal(secretBlock.data.reason, 'SECRET_LEAK_BLOCKED');

      const badArgsHold = engine.interceptToolCall({
        session_id: 'sess_small',
        step: 3,
        tool_name: 'schedule_event',
        args: { title: 'Kickoff {{vendor_name}}', date: '2026-02-30' }
      });
      assert.equal(badArgsHold.data.decision, 'HOLD');
      assert.equal(badArgsHold.data.reason, 'SMALL_MODEL_ARGUMENT_HOLD');
      assert.equal(badArgsHold.data.issues.length, 2);

      const trunc = engine.evaluateTurn({
        session_id: 'sess_small',
        turn_response: {
          finishReason: 'length',
          toolCalls: [{ id: 'tc_1', name: 'send_email', rawArguments: '{"to":"cut' }]
        }
      });
      assert.equal(trunc.data.poisoned, true);
      assert.equal(trunc.data.safeToExecuteTools, false);

      const draftNudge = engine.verifyStop({
        session_id: 'sess_small',
        assistant_text: 'Subject: Vendor Onboarding\nTo: ops@vendor.example\n\nWelcome aboard!'
      });
      assert.equal(draftNudge.data.allowStop, false);
      assert.equal(draftNudge.data.action, 'NUDGE_SMALL_MODEL_DRAFT');

      // Policy abstention on SMALL_MODEL is NEVER nudged!
      await engine.startSession({
        session_id: 'sess_small_abstain',
        goal: 'Send wire transfer refund of 900 USD to Acme',
        model: 'qwen2.5-coder:7b'
      });
      const abstainStop = engine.verifyStop({
        session_id: 'sess_small_abstain',
        assistant_text: 'I cannot send a 900 USD refund because policy requires VP Finance approval above 500 USD.'
      });
      assert.equal(abstainStop.data.allowStop, true);
      assert.equal(abstainStop.data.shouldNudge, false);

      // 2. FRONTIER_REASONING: Defect-Only Output Gate catches NaN / repr / <tool_call> while passing clean answers in 0 turns
      await engine.startSession({
        session_id: 'sess_defect_gate',
        goal: 'Compute merchant fee delta',
        model: 'gemini-4-argon'
      });
      const reprBlock = engine.verifyStop({
        session_id: 'sess_defect_gate',
        assistant_text: 'np.float64(0.0912)',
        candidate_answer: 'np.float64(0.0912)',
        expect_non_empty_answer: true
      });
      assert.equal(reprBlock.data.allowStop, false);
      assert.equal(reprBlock.data.action, 'REJECT_OUTPUT_DEFECT');
      assert.equal(reprBlock.data.reason, 'RAW_DATAFRAME_OR_NUMPY_REPR');

      // Clean scalar passes with 0 nudges on fresh frontier session
      await engine.startSession({
        session_id: 'sess_frontier',
        goal: 'Update settlement config and verify test suite',
        model: 'gemini-4-argon'
      });

      const mut1 = engine.interceptToolCall({
        session_id: 'sess_frontier',
        step: 1,
        tool_name: 'write_file',
        args: { path: 'src/settlement.js', content: 'export const FEE = 0.15;\n' }
      });
      assert.equal(mut1.data.decision, 'ALLOW');
      engine.recordToolOutcome({
        session_id: 'sess_frontier',
        event_id: mut1.data.event_id,
        ok: true,
        pending_diffs_delta: 1
      });

      const dupMut = engine.interceptToolCall({
        session_id: 'sess_frontier',
        step: 2,
        tool_name: 'write_file',
        args: { content: 'export const FEE = 0.15;\n', path: 'src/settlement.js' }
      });
      assert.equal(dupMut.data.decision, 'BLOCK');
      assert.equal(dupMut.data.reason, 'BLOCK_DUPLICATE_WRITE');

      const diffBlock = engine.verifyStop({
        session_id: 'sess_frontier',
        assistant_text: 'Updated settlement.js.',
        verification_command: 'npm test'
      });
      assert.equal(diffBlock.data.allowStop, false);
      assert.equal(diffBlock.data.action, 'FORCE_VERIFY');

      const testCall = engine.interceptToolCall({
        session_id: 'sess_frontier',
        step: 3,
        tool_name: 'check_tests',
        args: { command: 'npm test' },
        mutating: false
      });
      engine.recordToolOutcome({
        session_id: 'sess_frontier',
        event_id: testCall.data.event_id,
        ok: true,
        verification_passed: true
      });

      const cleanStop = engine.verifyStop({
        session_id: 'sess_frontier',
        assistant_text: 'Updated settlement.js and verified npm test passes.',
        pending_diffs_count: 0,
        mutated_files_count: 3,
        latest_verification_passed: false
      });
      assert.equal(cleanStop.data.allowStop, true);
      assert.equal(cleanStop.data.shouldNudge, false);

      // 3. Pattern 6 (INV-GH-10): Subprocess timeout preserves partial stdout and clears finalAnswer
      const timeoutExec = await execCommandWithPartialStdout(
        process.execPath,
        ['-e', 'process.stdout.write("rows_scanned=9420\\n"); setInterval(() => {}, 1000);'],
        { timeoutMs: 120, label: 'python_sandbox_step' }
      );
      assert.equal(timeoutExec.timedOut, true);
      assert.equal(timeoutExec.ok, false);
      assert.equal(timeoutExec.hasFinalAnswer, false);
      assert.equal(timeoutExec.finalAnswer, null);
      assert.match(timeoutExec.stdout, /rows_scanned=9420/);
      assert.match(timeoutExec.formattedObservation, /PARTIAL STDOUT BEFORE TIMEOUT/);

      const sbCall = engine.interceptToolCall({
        session_id: 'sess_frontier',
        step: 4,
        tool_name: 'query_sandbox',
        args: { code: 'scan_heavy_rows()' },
        mutating: false
      });
      const sbOut = engine.recordToolOutcome({
        session_id: 'sess_frontier',
        event_id: sbCall.data.event_id,
        timed_out: true,
        partial_stdout: timeoutExec.stdout
      });
      assert.equal(sbOut.data.status, 'FAILED');
      assert.equal(sbOut.data.timed_out, true);
      assert.equal(sbOut.data.has_final_answer, false);
      assert.match(sbOut.data.preserved_stdout, /rows_scanned=9420/);

      const fSummary = engine.sessionSummary({ session_id: 'sess_frontier' });
      assert.equal(fSummary.data.metrics.timeoutsWithPartialStdout, 1);
    } finally {
      db.close();
    }
  });

  test('INV-GH-07: CSO Zero-Leak Verification across all project files', () => {
    const scanDirs = ['src', 'bin', 'tests'];
    const hostParts = [
      ['krusch', 'serv'].join(''),
      ['krusch', 'game'].join(''),
      ['krusch', 'media'].join(''),
      ['krusch', 'sandbox'].join(''),
      ['crush', '0'].join(''),
      ['kr1', 'yoga'].join(''),
      ['kd', 'code'].join('')
    ];
    const forbidden = [
      new RegExp('\\b192' + '\\.168\\.\\d+\\.\\d+\\b'),
      new RegExp('\\b10' + '\\.10\\.\\d+\\.\\d+\\b'),
      new RegExp('\\b100' + '\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7])\\.\\d+\\.\\d+\\b'),
      new RegExp('/home/' + '[a-z0-9_-]+', 'i'),
      new RegExp('/mnt/' + '[a-z0-9_-]+', 'i'),
      new RegExp('\\b(?:' + hostParts.join('|') + ')\\b', 'i')
    ];

    for (const sub of scanDirs) {
      const fullDir = path.join(PROJECT_ROOT, sub);
      for (const entry of fs.readdirSync(fullDir)) {
        const filePath = path.join(fullDir, entry);
        if (!fs.statSync(filePath).isFile()) continue;
        const text = fs.readFileSync(filePath, 'utf8');
        for (const re of forbidden) {
          assert.equal(re.test(text), false, `Forbidden CSO pattern ${re} matched in ${sub}/${entry}`);
        }
      }
    }
  });
});
