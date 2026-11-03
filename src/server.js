import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createApiServer,
  attachGracefulShutdown,
  okEnvelope,
  errorEnvelope
} from '@krusch/toolkit/http';
import { setupLogging } from '@krusch/toolkit/log';
import { config } from './config.js';
import {
  SCALE_TIERS,
  buildScaleAwareDirective,
  createGroundedHarness
} from './index.js';

function statusForErrorEnvelope(envelope) {
  const code = envelope?.error?.code || '';
  if (code === 'NOT_FOUND') return 404;
  if (code === 'VALIDATION_ERROR' || code === 'INVALID_ARGS') return 400;
  return 500;
}

function respondEnvelope(ctx, envelope, successStatus = 200) {
  if (!envelope || typeof envelope !== 'object') {
    ctx.sendJson(500, errorEnvelope('INTERNAL_ERROR', 'Empty engine response', null, 'krusch-grounded-harness'));
    return;
  }
  const status = envelope.ok === false ? statusForErrorEnvelope(envelope) : successStatus;
  ctx.sendJson(status, envelope);
}

export function buildServer({
  dbPath = config.dbPath,
  serviceName = config.serviceName,
  logger = null,
  protectedPaths = [],
  extraFloorRules = []
} = {}) {
  const activeLogger = logger || setupLogging(serviceName, { logDir: config.logDir, console: false });
  const harness = createGroundedHarness({ dbPath, protectedPaths, extraFloorRules });

  const server = createApiServer({
    serviceName,
    version: '0.2.0',
    logger: activeLogger,
    healthCheck: () => {
      const row = harness.db.queryOne('SELECT COUNT(*) AS count FROM grounded_sessions');
      return {
        db: 'ok',
        sessions: Number(row?.count ?? 0)
      };
    },
    routes: {
      'GET /api/scale-tiers': () =>
        okEnvelope('krusch_scale_tiers', 'Returned monotonic scale-aware harness tiers', {
          tiers: SCALE_TIERS
        }),

      'POST /api/scale-profile': (ctx) => {
        const profile = harness.resolveScaleProfile(ctx.body || {});
        const directive = buildScaleAwareDirective(profile);
        return okEnvelope(
          'krusch_resolve_scale_profile',
          `Resolved ${profile.tier} profile for "${profile.model || 'default'}"`,
          { profile, directive }
        );
      },

      'POST /api/ground': async (ctx) => {
        const res = await harness.compileTurnZeroGrounding(ctx.body || {});
        respondEnvelope(ctx, res, 200);
      },

      'POST /api/ground-and-start': async (ctx) => {
        const res = await harness.groundAndStartSession(ctx.body || {});
        respondEnvelope(ctx, res, res.ok ? 201 : 400);
      },

      'POST /api/session/start': async (ctx) => {
        const res = await harness.engine.startSession(ctx.body || {});
        respondEnvelope(ctx, res, res.ok ? 201 : 400);
      },

      'POST /api/session/evaluate-turn': (ctx) => {
        const res = harness.engine.evaluateTurn(ctx.body || {});
        respondEnvelope(ctx, res, 200);
      },

      'POST /api/session/intercept': (ctx) => {
        const res = harness.engine.interceptToolCall(ctx.body || {});
        respondEnvelope(ctx, res, 200);
      },

      'POST /api/session/outcome': (ctx) => {
        const res = harness.engine.recordToolOutcome(ctx.body || {});
        respondEnvelope(ctx, res, 200);
      },

      'POST /api/session/verify-stop': (ctx) => {
        const res = harness.engine.verifyStop(ctx.body || {});
        respondEnvelope(ctx, res, 200);
      },

      'POST /api/session/summary': (ctx) => {
        const res = harness.engine.sessionSummary(ctx.body || {});
        respondEnvelope(ctx, res, 200);
      },

      'GET /api/session/summary': (ctx) => {
        const res = harness.engine.sessionSummary({
          session_id: ctx.query?.session_id ?? ctx.query?.sessionId ?? ''
        });
        respondEnvelope(ctx, res, 200);
      }
    }
  });

  return {
    server,
    harness,
    close: () => harness.close()
  };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  const logger = setupLogging(config.serviceName, { logDir: config.logDir });
  const { server, close } = buildServer({ logger });
  server.listen(config.port, () => {
    logger.info(`${config.serviceName} listening on port ${config.port}`);
  });
  attachGracefulShutdown(server, [close], { logger });
}
