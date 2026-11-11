import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SYNTHESIZED_RULE_ACTIONS,
  DEFAULT_EVOLVED_HARNESS_RULES,
  compileSafeRuleRegex,
  extractShellCommandsFromTrajectory,
  mineFailureTrajectories,
  verifyCandidateRulesOnTraces,
  evolveRulesFromTraces,
  createGroundedHarness
} from '../src/index.js';

describe('Meta-Harness Failure-Trace Rule Synthesizer & Runtime Gate (INV-GH-11)', () => {
  test('compileSafeRuleRegex blocks trivial catch-alls, ReDoS nested quantifiers, and broken syntax', () => {
    assert.equal(compileSafeRuleRegex('.*').ok, false);
    assert.equal(compileSafeRuleRegex('^.*$').ok, false);
    assert.equal(compileSafeRuleRegex('ab').ok, false);
    assert.equal(compileSafeRuleRegex('(a+)+$').ok, false);
    assert.equal(compileSafeRuleRegex('([unclosed').ok, false);

    const safe = compileSafeRuleRegex('^\\s*git\\s+restore\\s+\\S+$');
    assert.equal(safe.ok, true);
    assert.equal(safe.regex.test('git restore calculator.js'), true);
  });

  test('mineFailureTrajectories classifies echo-spin, scratch pollution, rollback block, and inline verify gaps', async () => {
    const sampleTrajClean = {
      messages: [
        { role: 'assistant', content: 'Run tests', extra: { actions: [{ command: 'node --test tests/core.test.js' }] } },
        { role: 'tool', content: '<returncode>0</returncode><output>pass 3</output>' },
        { role: 'assistant', content: 'Submit', extra: { actions: [{ command: 'echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT' }] } },
        { role: 'tool', content: '<returncode>0</returncode><output>submitted</output>' }
      ]
    };

    const extracted = extractShellCommandsFromTrajectory(sampleTrajClean);
    assert.equal(extracted.length, 2);
    assert.equal(extracted[0].returncode, 0);

    const syntheticRows = [
      {
        task_id: 'T01-clean',
        config: 'C',
        resolved: true,
        submitted: true,
        exit_status: 'Submitted',
        turns: 8,
        patch_lines: 24,
        blocked_reason: null,
        steps: extracted
      },
      {
        task_id: 'T02-echo-loop',
        config: 'C',
        resolved: false,
        submitted: false,
        exit_status: 'LimitsExceeded',
        turns: 40,
        patch_lines: 9727,
        blocked_reason: null,
        steps: [
          { step: 38, command: 'echo "Task completed successfully - json-parse.js fixed"', returncode: 0, outputPreview: 'Task completed successfully' },
          { step: 39, command: 'echo "Final verification: fix confirmed working"', returncode: 0, outputPreview: 'Final verification' }
        ]
      },
      {
        task_id: 'T03-rollback-and-cleanup',
        config: 'C',
        resolved: true,
        submitted: true,
        exit_status: 'Submitted',
        turns: 31,
        patch_lines: 45,
        blocked_reason: 'BLOCK:BLOCK_DUPLICATE_WRITE;STOP_BLOCKED:FORCE_VERIFY',
        steps: [
          { step: 10, command: 'perl -pi -e "s/foo/bar/" config.js', returncode: 1, outputPreview: "SyntaxError: Unexpected token '}'" },
          { step: 11, command: 'git checkout -- config.js', returncode: 0, outputPreview: '' },
          { step: 20, command: 'rm -f test_envbool.mjs', returncode: 0, outputPreview: '' }
        ]
      }
    ];

    const mined = mineFailureTrajectories({ rows: syntheticRows });
    assert.equal(mined.ok, true);
    assert.equal(mined.data.cleanPassEpisodes, 1);
    assert.equal(mined.data.failedEpisodes, 2);
    assert.equal(mined.data.failureTaxonomy.PSEUDO_COMPLETION_ECHO_LOOP.count, 1);
    assert.equal(mined.data.failureTaxonomy.UNTRACKED_SCRATCH_POLLUTION.count, 1);
    assert.equal(mined.data.failureTaxonomy.IDEMPOTENT_ROLLBACK_BLOCKED.count, 1);
    assert.equal(mined.data.failureTaxonomy.INLINE_VERIFICATION_UNRECOGNIZED.count, 1);
    assert.equal(mined.data.failureTaxonomy.TEMP_CLEANUP_FALSE_DIFF.count, 1);
    assert.equal(mined.data.failureTaxonomy.SHELL_EDIT_CORRUPTION_SPIRAL.count, 1);

    // Holdout replay gate accepts all 4 default rules and quarantines unsafe candidate rules
    const evolved = await evolveRulesFromTraces({
      rows: syntheticRows,
      includeDefaultRules: true,
      useTeacher: false,
      extraCandidateRules: [
        {
          id: 'BAD-OVERBROAD-ECHO',
          action: SYNTHESIZED_RULE_ACTIONS.HOLD_TOOL_PATTERN,
          commandRegex: '^\\s*echo\\b'
        },
        {
          id: 'BAD-TRACKED-RM',
          action: SYNTHESIZED_RULE_ACTIONS.EXEMPT_CLEANUP_DIFF,
          commandRegex: '^\\s*rm\\s+.*$'
        },
        {
          id: 'BAD-FLOOR-SUBVERT',
          action: SYNTHESIZED_RULE_ACTIONS.EXEMPT_DUPLICATE_WRITE,
          commandRegex: '^\\s*git\\s+reset\\s+--hard'
        }
      ]
    });

    assert.equal(evolved.ok, true);
    assert.equal(evolved.data.acceptedRules.length, DEFAULT_EVOLVED_HARNESS_RULES.length);
    assert.equal(evolved.data.rejectedRules.length, 3);

    const statuses = new Map(evolved.data.rejectedRules.map((r) => [r.id, r.status]));
    assert.equal(statuses.get('BAD-OVERBROAD-ECHO'), 'REJECTED_FALSE_POSITIVE');
    assert.equal(statuses.get('BAD-FLOOR-SUBVERT'), 'REJECTED_POLICY_FLOOR_CONFLICT');
    // `rm -rf /` hits frozen policy floor first or tracked source delete false-positive
    assert.ok(
      statuses.get('BAD-TRACKED-RM') === 'REJECTED_POLICY_FLOOR_CONFLICT'
        || statuses.get('BAD-TRACKED-RM') === 'REJECTED_FALSE_POSITIVE'
    );

    const standaloneVerify = verifyCandidateRulesOnTraces([
      {
        id: 'BAD-RM-SRC',
        action: SYNTHESIZED_RULE_ACTIONS.EXEMPT_CLEANUP_DIFF,
        commandRegex: '^\\s*rm\\s+(?:-f\\s+)?src/[\\w.-]+$'
      }
    ]);
    assert.equal(standaloneVerify.acceptedRules.length, 0);
    assert.equal(standaloneVerify.rejectedRules[0].status, 'REJECTED_FALSE_POSITIVE');
  });

  test('Live runtime enforcement of GH-EVO-01..04 inside createGroundedHarness', async () => {
    const harness = createGroundedHarness({ dbPath: ':memory:' });
    try {
      await harness.engine.startSession({
        session_id: 'sess_meta_evo',
        goal: 'Fix envBool falsy handling in config.js and verify tests',
        model: 'qwen3-coder-30b-moe:latest'
      });

      // 1. GH-EVO-01: Repeated `git checkout -- config.js` is NOT blocked by BLOCK_DUPLICATE_WRITE
      for (const step of [1, 2]) {
        const res = harness.engine.interceptToolCall({
          session_id: 'sess_meta_evo',
          step,
          tool_name: 'bash',
          args: { command: 'git checkout -- config.js' },
          mutating: true
        });
        assert.equal(res.data.decision, 'ALLOW');
        harness.engine.recordToolOutcome({
          session_id: 'sess_meta_evo',
          event_id: res.data.event_id,
          ok: true,
          pending_diffs_delta: 0
        });
      }

      // Real duplicate edit (`sed -i`) IS still blocked by BLOCK_DUPLICATE_WRITE
      const edit1 = harness.engine.interceptToolCall({
        session_id: 'sess_meta_evo',
        step: 3,
        tool_name: 'bash',
        args: { command: 'sed -i "s/oldVal/newVal/" config.js' },
        mutating: true
      });
      assert.equal(edit1.data.decision, 'ALLOW');
      harness.engine.recordToolOutcome({
        session_id: 'sess_meta_evo',
        event_id: edit1.data.event_id,
        ok: true,
        pending_diffs_delta: 1
      });

      const editDup = harness.engine.interceptToolCall({
        session_id: 'sess_meta_evo',
        step: 4,
        tool_name: 'bash',
        args: { command: 'sed -i "s/oldVal/newVal/" config.js' },
        mutating: true
      });
      assert.equal(editDup.data.decision, 'BLOCK');
      assert.equal(editDup.data.reason, 'BLOCK_DUPLICATE_WRITE');

      // Mutating `node -e` with writeFileSync is NOT mis-credited as verification
      const mutNode = harness.engine.interceptToolCall({
        session_id: 'sess_meta_evo',
        step: 5,
        tool_name: 'bash',
        args: { command: 'node -e "fs.writeFileSync(\'config.js\', \'updated\')"' },
        mutating: true
      });
      const mutOut = harness.engine.recordToolOutcome({
        session_id: 'sess_meta_evo',
        event_id: mutNode.data.event_id,
        ok: true,
        pending_diffs_delta: 1
      });
      assert.equal(mutOut.data.latest_verification_passed, 0);
      assert.ok(mutOut.data.pending_diffs_count > 0);

      // 2. GH-EVO-03: Non-mutating exit-0 inline `node -e` assertion credits verification_passed
      const verifyNode = harness.engine.interceptToolCall({
        session_id: 'sess_meta_evo',
        step: 6,
        tool_name: 'bash',
        args: { command: 'node -e "import(\'./config.js\').then(m => console.log(m.envBool))"' },
        mutating: false
      });
      const verifyOut = harness.engine.recordToolOutcome({
        session_id: 'sess_meta_evo',
        event_id: verifyNode.data.event_id,
        ok: true,
        result_preview: '[Function: envBool]'
      });
      assert.equal(verifyOut.data.latest_verification_passed, 1);
      assert.equal(verifyOut.data.pending_diffs_count, 0);

      // 3. GH-EVO-02: Deleting scratch test file `rm -f test_envbool.mjs` after passing verify keeps pending_diffs_count = 0
      const cleanupCall = harness.engine.interceptToolCall({
        session_id: 'sess_meta_evo',
        step: 7,
        tool_name: 'bash',
        args: { command: 'rm -f test_envbool.mjs verify_fix.mjs' },
        mutating: true
      });
      assert.equal(cleanupCall.data.decision, 'ALLOW');
      const cleanupOut = harness.engine.recordToolOutcome({
        session_id: 'sess_meta_evo',
        event_id: cleanupCall.data.event_id,
        ok: true,
        pending_diffs_delta: 1
      });
      assert.equal(cleanupOut.data.pending_diffs_count, 0);
      assert.equal(cleanupOut.data.latest_verification_passed, 1);

      // 3b. GH-EVO-05: Exporting `git diff config.js > patch.txt` right before submit keeps pending_diffs_count = 0
      const patchExportCall = harness.engine.interceptToolCall({
        session_id: 'sess_meta_evo',
        step: 8,
        tool_name: 'bash',
        args: { command: 'cd /testbed && git diff config.js > patch.txt' },
        mutating: true
      });
      assert.equal(patchExportCall.data.decision, 'ALLOW');
      const patchExportOut = harness.engine.recordToolOutcome({
        session_id: 'sess_meta_evo',
        event_id: patchExportCall.data.event_id,
        ok: true,
        pending_diffs_delta: 1
      });
      assert.equal(patchExportOut.data.pending_diffs_count, 0);
      assert.equal(patchExportOut.data.latest_verification_passed, 1);

      // Stop check succeeds with 0 FORCE_VERIFY nudges!
      const stopCheck = harness.engine.verifyStop({
        session_id: 'sess_meta_evo',
        assistant_text: 'Fixed envBool and verified.'
      });
      assert.equal(stopCheck.data.allowStop, true);
      assert.equal(stopCheck.data.action, 'ALLOW_STOP');

      // 4. GH-EVO-04: Consecutive celebratory echo banners trigger PSEUDO_COMPLETION_ECHO_LOOP on 2nd repeat, while submit marker is allowed
      await harness.engine.startSession({
        session_id: 'sess_echo_loop',
        goal: 'Fix parseAIJson trailing prose',
        model: 'qwen3-coder-30b-moe:latest'
      });

      const echo1 = harness.engine.interceptToolCall({
        session_id: 'sess_echo_loop',
        step: 1,
        tool_name: 'bash',
        args: { command: 'echo "Task completed successfully - parseAIJson fixed"' },
        mutating: false
      });
      assert.equal(echo1.data.decision, 'ALLOW');
      harness.engine.recordToolOutcome({
        session_id: 'sess_echo_loop',
        event_id: echo1.data.event_id,
        ok: true,
        result_preview: 'Task completed successfully'
      });

      const echo2 = harness.engine.interceptToolCall({
        session_id: 'sess_echo_loop',
        step: 2,
        tool_name: 'bash',
        args: { command: 'echo "Final verification: fix confirmed working"' },
        mutating: false
      });
      assert.equal(echo2.data.decision, 'HOLD');
      assert.equal(echo2.data.reason, 'PSEUDO_COMPLETION_ECHO_LOOP');
      assert.match(echo2.data.correctivePrompt, /submit/i);

      const realSubmit = harness.engine.interceptToolCall({
        session_id: 'sess_echo_loop',
        step: 3,
        tool_name: 'bash',
        args: { command: 'echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT' },
        mutating: false
      });
      assert.equal(realSubmit.data.decision, 'ALLOW');
    } finally {
      harness.close();
    }
  });
});
