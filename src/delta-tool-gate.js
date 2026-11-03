/**
 * @module delta-tool-gate
 * @description Deferred BM25 tool-schema budget gate and session delta-context / read-memo
 * tracker enforcing `INV-GH-04` (`createDeferredToolBridge`, Turn-0 duplicate suppression,
 * and `MEMOIZED_PRIOR_READ` caching).
 */

import { createDeferredToolBridge } from '@krusch/toolkit/harness-engineering';
import { estimateTokenCount } from '@krusch/toolkit/raw-rag';

/**
 * Computes token-level schema overhead and savings between raw and exposed tool definitions.
 *
 * @param {Array<object>} [allTools=[]] - Complete registered tool schemas.
 * @param {Array<object>} [exposedTools=[]] - Eagerly exposed tool schemas (+ meta-tools when deferred).
 * @returns {{
 *   rawToolCount: number,
 *   exposedToolCount: number,
 *   rawSchemaTokens: number,
 *   exposedSchemaTokens: number,
 *   savedSchemaTokens: number,
 *   reductionPct: number
 * }}
 */
export function measureToolSchemaSavings(allTools = [], exposedTools = []) {
  const safeAll = Array.isArray(allTools) ? allTools : [];
  const safeExposed = Array.isArray(exposedTools) ? exposedTools : [];

  const rawSchemaTokens = safeAll.length === 0 ? 0 : estimateTokenCount(JSON.stringify(safeAll));
  const exposedSchemaTokens = safeExposed.length === 0 ? 0 : estimateTokenCount(JSON.stringify(safeExposed));
  const savedSchemaTokens = Math.max(0, rawSchemaTokens - exposedSchemaTokens);
  const reductionPct = rawSchemaTokens > 0
    ? Number(((savedSchemaTokens / rawSchemaTokens) * 100).toFixed(2))
    : 0;

  return {
    rawToolCount: safeAll.length,
    exposedToolCount: safeExposed.length,
    rawSchemaTokens,
    exposedSchemaTokens,
    savedSchemaTokens,
    reductionPct
  };
}

async function dispatchWithOverride(bridge, overrideDispatcher, rawToolName, rawArgs) {
  const targetName = String(rawToolName ?? '').trim();
  const described = bridge.describe(targetName);
  if (!described.ok) {
    return {
      ok: false,
      tool: 'tool_call',
      summary: `Unknown or unexposed tool "${targetName}".`,
      data: { toolName: targetName || null, error: 'TOOL_NOT_FOUND' }
    };
  }
  if (rawArgs !== undefined && rawArgs !== null && (typeof rawArgs !== 'object' || Array.isArray(rawArgs))) {
    return {
      ok: false,
      tool: 'tool_call',
      summary: `Arguments for "${targetName}" must be a plain JSON object.`,
      data: { toolName: targetName, error: 'INVALID_ARGUMENTS' }
    };
  }
  try {
    const result = await overrideDispatcher(targetName, rawArgs || {});
    const underlyingFailed = Boolean(result && typeof result === 'object' && result.ok === false);
    return {
      ok: !underlyingFailed,
      tool: 'tool_call',
      summary: underlyingFailed
        ? `Tool "${targetName}" reported failure: ${result.summary || result.error || 'execution failed'}.`
        : `Executed "${targetName}" successfully.`,
      data: { toolName: targetName, result }
    };
  } catch (err) {
    return {
      ok: false,
      tool: 'tool_call',
      summary: `Execution of "${targetName}" threw an error: ${err.message}`,
      data: { toolName: targetName, error: err.message }
    };
  }
}

/**
 * Wraps `createDeferredToolBridge` (`@krusch/toolkit/harness-engineering`) with token-level
 * schema savings accounting and meta-tool dispatch (`tool_search`, `tool_describe`, `tool_call`).
 *
 * @param {object} [options={}]
 * @param {Array<object>} [options.tools=[]]
 * @param {string[]} [options.pinnedToolNames=[]]
 * @param {number} [options.deferThreshold=12]
 * @param {boolean} [options.forceDefer=false]
 * @param {number} [options.searchTopK=5]
 * @param {Function} [options.dispatcher]
 * @returns {{
 *   deferred: boolean,
 *   exposedTools: Array<object>,
 *   savings: ReturnType<typeof measureToolSchemaSavings>,
 *   bridge: object,
 *   invokeMetaTool: (name: string, args?: object, overrideDispatcher?: Function) => Promise<object>
 * }}
 */
export function createToolBudgetGate({
  tools = [],
  pinnedToolNames = [],
  deferThreshold = 12,
  forceDefer = false,
  searchTopK = 5,
  dispatcher
} = {}) {
  const safeTools = Array.isArray(tools) ? tools : [];
  const bridge = createDeferredToolBridge(safeTools, {
    pinnedToolNames,
    deferThreshold,
    forceDefer,
    defaultLimit: searchTopK,
    dispatcher
  });

  const exposedTools = bridge.getExposedTools();
  const savings = measureToolSchemaSavings(safeTools, exposedTools);

  async function invokeMetaTool(name, args = {}, overrideDispatcher = dispatcher) {
    const safeArgs = args && typeof args === 'object' && !Array.isArray(args) ? args : {};

    if (name === 'tool_search') {
      return bridge.search(safeArgs.query ?? '', safeArgs.limit ?? searchTopK);
    }

    if (name === 'tool_describe') {
      return bridge.describe(safeArgs.toolName ?? safeArgs.name ?? '');
    }

    if (name === 'tool_call') {
      const targetToolName = safeArgs.toolName ?? safeArgs.name ?? '';
      const innerArgs = safeArgs.args !== undefined ? safeArgs.args : {};
      if (typeof overrideDispatcher === 'function' && overrideDispatcher !== dispatcher) {
        return dispatchWithOverride(bridge, overrideDispatcher, targetToolName, innerArgs);
      }
      return bridge.call(targetToolName, innerArgs);
    }

    if (typeof overrideDispatcher === 'function' && overrideDispatcher !== dispatcher) {
      return dispatchWithOverride(bridge, overrideDispatcher, name, safeArgs);
    }
    return bridge.call(name, safeArgs);
  }

  return {
    deferred: bridge.shouldDefer,
    exposedTools,
    savings,
    bridge,
    invokeMetaTool
  };
}

/**
 * Tracks Turn-0 seeded chunk IDs, workspace file SHA-256 digests, and memoized read calls
 * so mid-session retrieval and repeated reads never re-inject duplicate tokens (`INV-GH-04`).
 *
 * @param {object} [options={}]
 * @param {string[]} [options.initialChunkIds=[]]
 * @param {Record<string, string>} [options.initialFileDigests={}]
 */
export function createDeltaContextTracker({ initialChunkIds = [], initialFileDigests = {} } = {}) {
  const normalizedInitialIds = Array.isArray(initialChunkIds)
    ? initialChunkIds.map((id) => String(id ?? '')).filter(Boolean)
    : [];
  const seenChunkIds = new Set(normalizedInitialIds);
  const turn0SeededIds = new Set(normalizedInitialIds);
  let turn0SeededCount = turn0SeededIds.size;

  const fileDigests = new Map();
  if (initialFileDigests && typeof initialFileDigests === 'object') {
    for (const [relPath, digest] of Object.entries(initialFileDigests)) {
      if (relPath && digest !== undefined && digest !== null) {
        fileDigests.set(String(relPath), String(digest));
      }
    }
  }

  const readMemo = new Map();
  let turn0DuplicatesSuppressed = 0;
  let memoizedReads = 0;

  function seedTurnZero({ chunkIds = [], fileDigests: nextDigests = {} } = {}) {
    if (Array.isArray(chunkIds)) {
      for (const rawId of chunkIds) {
        const id = String(rawId ?? '');
        if (id) {
          seenChunkIds.add(id);
          turn0SeededIds.add(id);
        }
      }
      turn0SeededCount = turn0SeededIds.size;
    }

    if (nextDigests && typeof nextDigests === 'object') {
      for (const [relPath, digest] of Object.entries(nextDigests)) {
        if (relPath && digest !== undefined && digest !== null) {
          fileDigests.set(String(relPath), String(digest));
        }
      }
    }

    return {
      turn0SeededChunks: turn0SeededCount,
      totalSeenChunks: seenChunkIds.size,
      trackedFileDigests: fileDigests.size
    };
  }

  function filterDeltaChunks(chunks = []) {
    const safeChunks = Array.isArray(chunks) ? chunks : [];
    const novelChunks = [];
    let suppressedCount = 0;

    for (const chunk of safeChunks) {
      const id = typeof chunk === 'string'
        ? chunk
        : String(chunk?.chunkId ?? chunk?.windowId ?? chunk?.entryId ?? chunk?.id ?? chunk?.contentHash ?? '');

      if (id && seenChunkIds.has(id)) {
        suppressedCount += 1;
        turn0DuplicatesSuppressed += 1;
        continue;
      }

      if (id) {
        seenChunkIds.add(id);
      }
      novelChunks.push(chunk);
    }

    return {
      novelChunks,
      suppressedCount,
      totalSeenChunks: seenChunkIds.size
    };
  }

  function hasSeenFileDigest(relPath, digest) {
    return Boolean(relPath && digest && fileDigests.get(String(relPath)) === String(digest));
  }

  function recordFileDigest(relPath, digest) {
    if (relPath && digest !== undefined && digest !== null) {
      fileDigests.set(String(relPath), String(digest));
    }
  }

  function checkReadMemo(callSignature) {
    if (readMemo.has(callSignature)) {
      memoizedReads += 1;
      return {
        hit: true,
        entry: readMemo.get(callSignature)
      };
    }
    return {
      hit: false,
      entry: null
    };
  }

  function recordReadMemo(callSignature, entry = {}) {
    const safeEntry = entry && typeof entry === 'object' ? entry : {};
    const stored = {
      preview: String(safeEntry.preview ?? ''),
      step: Number(safeEntry.step ?? 0),
      recordedAtMs: Date.now()
    };
    readMemo.set(callSignature, stored);
    return stored;
  }

  function getMetrics() {
    return {
      turn0SeededChunks: turn0SeededCount,
      totalSeenChunks: seenChunkIds.size,
      trackedFileDigests: fileDigests.size,
      turn0DuplicatesSuppressed,
      memoizedReads,
      cachedReadSignatures: readMemo.size
    };
  }

  return {
    seedTurnZero,
    filterDeltaChunks,
    hasSeenFileDigest,
    recordFileDigest,
    checkReadMemo,
    recordReadMemo,
    getMetrics
  };
}
