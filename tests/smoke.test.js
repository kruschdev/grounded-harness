import test from 'node:test';
import assert from 'node:assert/strict';
import { buildServer } from '../src/server.js';
import { startGroundedMcpServer } from '../src/mcp.js';
import { cli } from '../bin/krusch-grounded-harness.js';

test('krusch-grounded-harness HTTP API (/health, /doctor, scale-profile, session lifecycle)', async (t) => {
  const { server, close } = buildServer({ dbPath: ':memory:' });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    close();
  });

  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  const healthRes = await fetch(`${baseUrl}/health`);
  assert.equal(healthRes.status, 200);
  const healthBody = await healthRes.json();
  assert.equal(healthBody.ok, true);
  assert.equal(healthBody.data.db, 'ok');

  const scaleRes = await fetch(`${baseUrl}/api/scale-profile`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'qwen2.5-coder:7b' })
  });
  assert.equal(scaleRes.status, 200);
  const scaleBody = await scaleRes.json();
  assert.equal(scaleBody.ok, true);
  assert.equal(scaleBody.data.profile.tier, 'SMALL_MODEL');
  assert.equal(scaleBody.data.profile.injectPlanBindStep, true);

  const startRes = await fetch(`${baseUrl}/api/session/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      session_id: 'smoke_sess_1',
      goal: 'Query customer retention metrics',
      model: 'gemini-4-argon'
    })
  });
  assert.equal(startRes.status, 201);
  const startBody = await startRes.json();
  assert.equal(startBody.ok, true);
  assert.equal(startBody.data.scaleProfile.tier, 'FRONTIER_REASONING');

  const stopRes = await fetch(`${baseUrl}/api/session/verify-stop`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      session_id: 'smoke_sess_1',
      assistant_text: 'Net retention is 114.2%.'
    })
  });
  assert.equal(stopRes.status, 200);
  const stopBody = await stopRes.json();
  assert.equal(stopBody.ok, true);
  assert.equal(stopBody.data.allowStop, true);
  assert.equal(stopBody.data.shouldNudge, false);

  const summaryRes = await fetch(`${baseUrl}/api/session/summary?session_id=smoke_sess_1`);
  assert.equal(summaryRes.status, 200);
  const summaryBody = await summaryRes.json();
  assert.equal(summaryBody.ok, true);
  assert.equal(summaryBody.data.session.status, 'COMPLETED');
});

test('krusch-grounded-harness MCP server exposes 7 4-boolean-annotated tools and CLI doctor/bench succeed', async () => {
  const mcp = await startGroundedMcpServer({ dbPath: ':memory:', connect: false });
  try {
    const listed = await mcp.listTools();
    assert.equal(listed.tools.length, 7);
    for (const tool of listed.tools) {
      assert.equal(typeof tool.annotations.readOnlyHint, 'boolean');
      assert.equal(typeof tool.annotations.destructiveHint, 'boolean');
      assert.equal(typeof tool.annotations.idempotentHint, 'boolean');
      assert.equal(typeof tool.annotations.openWorldHint, 'boolean');
    }

    const callRes = await mcp.callTool({
      params: {
        name: 'krusch_resolve_scale_profile',
        arguments: { model: 'gemma4:31b' }
      }
    });
    const parsed = JSON.parse(callRes.content[0].text);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.data.profile.tier, 'MID_MODEL');
  } finally {
    mcp.close();
  }

  const lines = [];
  const docRun = await cli.run(['doctor', '--json'], { stdout: (l) => lines.push(l), stderr: () => {} });
  assert.equal(docRun.exitCode, 0);
  assert.equal(docRun.result.ok, true);
  assert.equal(docRun.result.data.ok, true);

  const benchRun = await cli.run(['bench', '--json'], { stdout: () => {}, stderr: () => {} });
  assert.equal(benchRun.exitCode, 0);
  assert.equal(benchRun.result.ok, true);
  assert.equal(benchRun.result.data.profiles.length, 3);
});
