/**
 * @module scale-policy
 * @description Deterministic model scale metadata inference, monotonic tier resolution,
 * and small-model pre-action variable-binding directives (`INV-GH-03`).
 *
 * Pure Node 22 ESM with zero external dependencies.
 */

export const SCALE_TIERS = Object.freeze({
  SMALL_MODEL: 'SMALL_MODEL',
  MID_MODEL: 'MID_MODEL',
  FRONTIER_REASONING: 'FRONTIER_REASONING'
});

const DISABLED_EFFORT_VALUES = new Set(['none', 'off', 'disabled', 'minimal', 'false', '0']);

const NATIVE_REASONING_PATTERNS = [
  /(?:^|[/:\-_])o[134](?:$|[/:\-_])/,
  /\bdeepseek[-_/]?(?:r1|reasoner)\b/,
  /(?:^|[/:\-_])qwq(?:$|[/:\-_])/,
  /\bgemini[-_]?4[-_]?argon\b/
];

const FRONTIER_CLOUD_PATTERNS = [
  /\bgemini[-_]?4[-_]?argon\b/,
  /\bgemini[-_]?3\.8[-_]?flash\b/,
  /\bgemini[-_]?2\.5[-_]?pro\b/,
  /\bgemini[-_]?3[-_]?pro\b/,
  /\bgpt-5(?:\b|[.\-_])/,
  /(?:^|[/:\-_])o[134](?:$|[/:\-_])/,
  /\bclaude-(?:3[-.]7|4|(?:opus|sonnet)-4)(?:\b|[-_.])/,
  /\bdeepseek[-_/]?(?:r1|reasoner|v3)(?:\b|[.\-_])/,
  /(?:^|[/:\-_])qwq(?:$|[/:\-_])/,
  /\bgrok-[34](?:\b|[.\-_])/
];

const COMPACT_MID_TIER_PATTERNS = [
  /\bgemini[-_]?3\.5[-_]?flash[-_]?lite\b/,
  /\bgpt-4o-mini\b/,
  /\bgpt-4\.1-mini\b/,
  /\bclaude-(?:3[-.]5-)?haiku\b/,
  /\bministral\b/
];

const SMALL_ALIAS_DEFAULTS = [
  { pattern: /\bhermes[-_]?3\b/, paramsB: 8 },
  { pattern: /\bphi-4-mini\b/, paramsB: 3.8 },
  { pattern: /\bsmollm\d*\b/, paramsB: 1.7 },
  { pattern: /\btinyllama\b/, paramsB: 1.1 }
];

const SMALL_MODEL_PLAN_BIND_DIRECTIVE = [
  '[SCALE-AWARE PRE-ACTION STEP — SMALL MODEL] [PLAN -> BIND -> ACT]',
  '- PLAN: Identify the exact goal requirement and check whether Turn-0 grounded schemas and evidence already answer it.',
  '- BIND: Bind exact column names, record IDs, file paths, and YYYY-MM-DD dates verbatim from Turn-0 context with zero placeholders.',
  '- ACT: Execute one decisive tool call with concrete bound arguments or return the grounded final answer directly.'
].join('\n');

function parsePositiveNumberHint(value) {
  if (value === null || value === undefined || value === '' || typeof value === 'boolean') {
    return null;
  }
  const num = Number(value);
  return Number.isFinite(num) && num > 0 ? num : null;
}

function hasActiveThinkingEffort(value) {
  if (typeof value !== 'string') {
    return false;
  }
  const normalized = value.trim().toLowerCase();
  return normalized.length > 0 && !DISABLED_EFFORT_VALUES.has(normalized);
}

function isFrontierCloudFamily(normalizedModel) {
  if (!normalizedModel) {
    return false;
  }
  return FRONTIER_CLOUD_PATTERNS.some((pattern) => pattern.test(normalizedModel));
}

/**
 * Infers active/total parameter counts (in billions), MoE topology, and reasoning state
 * from a model identifier and optional runtime hints.
 *
 * @param {string} [modelId=''] - Raw model identifier string.
 * @param {object} [hints={}] - Optional runtime hints.
 * @returns {{
 *   normalizedModel: string,
 *   activeParamsB: number | null,
 *   totalParamsB: number | null,
 *   isMoe: boolean,
 *   isNativeReasoningModel: boolean,
 *   thinkingEnabled: boolean
 * }}
 */
export function inferModelScaleMetadata(modelId = '', hints = {}) {
  const normalizedModel = String(modelId || '').trim().toLowerCase();
  const safeHints = hints && typeof hints === 'object' ? hints : {};

  let activeParamsB = parsePositiveNumberHint(safeHints.activeParamsB);
  let totalParamsB = parsePositiveNumberHint(safeHints.totalParamsB);
  let isMoe = typeof safeHints.isMoe === 'boolean' ? safeHints.isMoe : false;

  const hasMoeTag = /(?:^|[/:\-_\s])moe(?:$|[/:\-_\s])/.test(normalizedModel);
  if (hasMoeTag && safeHints.isMoe !== false) {
    isMoe = true;
  }

  // Parse parameter topology from model identifier when not explicitly overridden.
  if (normalizedModel) {
    const activeMoeMatch = normalizedModel.match(/(?:^|[^a-z0-9])(\d+(?:\.\d+)?)b[-_:]a(\d+(?:\.\d+)?)b(?=$|[^a-z0-9])/);
    const mixtral8x7Match = /(?:^|[^a-z0-9])8x7b(?=$|[^a-z0-9])/.test(normalizedModel);
    const mixtral8x22Match = /(?:^|[^a-z0-9])8x22b(?=$|[^a-z0-9])/.test(normalizedModel);
    const nxmMatch = normalizedModel.match(/(?:^|[^a-z0-9])(\d+)x(\d+(?:\.\d+)?)b(?=$|[^a-z0-9])/);
    const moe30bMatch = /(?:^|[^a-z0-9])30b[-_:]moe(?=$|[^a-z0-9])/.test(normalizedModel) || (
      hasMoeTag && /(?:^|[:\-_/\s])30b(?=$|[:\-_/\s.])/.test(normalizedModel)
    );
    const edgeEffectiveMatch = normalizedModel.match(/(?:^|[:\-_/])e(\d+(?:\.\d+)?)b(?=$|[^a-z0-9])/);
    const standardParamMatch = normalizedModel.match(/(?:^|[:\-_/\s])(\d+(?:\.\d+)?)b(?=$|[:\-_/\s.])/)
      || normalizedModel.match(/\b(\d+(?:\.\d+)?)b\b/);

    if (activeMoeMatch) {
      if (totalParamsB === null) totalParamsB = Number(activeMoeMatch[1]);
      if (activeParamsB === null) activeParamsB = Number(activeMoeMatch[2]);
      if (safeHints.isMoe !== false) isMoe = true;
    } else if (mixtral8x7Match) {
      if (totalParamsB === null) totalParamsB = 47;
      if (activeParamsB === null) activeParamsB = 14;
      if (safeHints.isMoe !== false) isMoe = true;
    } else if (mixtral8x22Match) {
      if (totalParamsB === null) totalParamsB = 141;
      if (activeParamsB === null) activeParamsB = 39;
      if (safeHints.isMoe !== false) isMoe = true;
    } else if (moe30bMatch) {
      if (totalParamsB === null) totalParamsB = 30;
      if (activeParamsB === null) activeParamsB = 3;
      if (safeHints.isMoe !== false) isMoe = true;
    } else if (nxmMatch) {
      const experts = Number(nxmMatch[1]);
      const expertSize = Number(nxmMatch[2]);
      if (totalParamsB === null) totalParamsB = Number((experts * expertSize * 0.85).toFixed(1));
      if (activeParamsB === null) activeParamsB = Number((Math.min(2, experts) * expertSize).toFixed(1));
      if (safeHints.isMoe !== false) isMoe = true;
    } else if (edgeEffectiveMatch) {
      const effectiveB = Number(edgeEffectiveMatch[1]);
      if (activeParamsB === null) activeParamsB = effectiveB;
      if (totalParamsB === null) totalParamsB = effectiveB * 2;
    } else if (standardParamMatch) {
      const parsedB = Number(standardParamMatch[1]);
      if (totalParamsB === null) totalParamsB = parsedB;
      if (activeParamsB === null && !isMoe) activeParamsB = parsedB;
    }
  }

  // Known families without an explicit `<N>b` suffix.
  if (activeParamsB === null && totalParamsB === null && normalizedModel) {
    if (COMPACT_MID_TIER_PATTERNS.some((pattern) => pattern.test(normalizedModel))) {
      activeParamsB = 20;
      totalParamsB = 20;
    } else {
      for (const alias of SMALL_ALIAS_DEFAULTS) {
        if (alias.pattern.test(normalizedModel)) {
          activeParamsB = alias.paramsB;
          totalParamsB = alias.paramsB;
          break;
        }
      }
    }
  }

  // Reconcile single-sided explicit parameter hints.
  if (activeParamsB !== null && totalParamsB === null) {
    totalParamsB = activeParamsB;
  } else if (totalParamsB !== null && activeParamsB === null && !isMoe) {
    activeParamsB = totalParamsB;
  }

  if (
    safeHints.isMoe === undefined
    && activeParamsB !== null
    && totalParamsB !== null
    && totalParamsB >= 15
    && activeParamsB < totalParamsB
  ) {
    isMoe = true;
  }

  const isNativeReasoningModel = Boolean(
    normalizedModel && NATIVE_REASONING_PATTERNS.some((pattern) => pattern.test(normalizedModel))
  );

  let thinkingEnabled = false;
  if (safeHints.thinkingEnabled === true) {
    thinkingEnabled = true;
  } else if (safeHints.thinkingEnabled === false) {
    thinkingEnabled = false;
  } else if (
    isNativeReasoningModel
    || hasActiveThinkingEffort(safeHints.thinkingLevel)
    || hasActiveThinkingEffort(safeHints.reasoningEffort)
  ) {
    thinkingEnabled = true;
  }

  return {
    normalizedModel,
    activeParamsB,
    totalParamsB,
    isMoe,
    isNativeReasoningModel,
    thinkingEnabled
  };
}

/**
 * Deterministically resolves the monotonic scale-aware harness policy profile (`INV-GH-03`).
 *
 * @param {object} [options={}]
 * @param {string} [options.model='']
 * @param {number} [options.activeParamsB]
 * @param {number} [options.totalParamsB]
 * @param {boolean} [options.thinkingEnabled]
 * @param {string} [options.thinkingLevel]
 * @param {string} [options.reasoningEffort]
 * @param {string} [options.explicitTier]
 * @param {boolean} [options.preferThinkingStepForSmallActive=false]
 * @returns {Readonly<object>}
 */
export function resolveScaleProfile(options = {}) {
  const safeOptions = options && typeof options === 'object' ? options : {};
  const model = String(safeOptions.model || '');
  const preferThinkingStepForSmallActive = safeOptions.preferThinkingStepForSmallActive === true;

  const meta = inferModelScaleMetadata(model, {
    activeParamsB: safeOptions.activeParamsB,
    totalParamsB: safeOptions.totalParamsB,
    isMoe: safeOptions.isMoe,
    thinkingEnabled: safeOptions.thinkingEnabled,
    thinkingLevel: safeOptions.thinkingLevel,
    reasoningEffort: safeOptions.reasoningEffort
  });

  let tier;
  let rationale;

  if (typeof safeOptions.explicitTier === 'string' && Object.hasOwn(SCALE_TIERS, safeOptions.explicitTier)) {
    tier = SCALE_TIERS[safeOptions.explicitTier];
    rationale = `Explicit tier override (${tier}).`;
  } else if (
    meta.thinkingEnabled === true
    || meta.isNativeReasoningModel === true
    || (meta.totalParamsB !== null && meta.totalParamsB >= 70)
    || isFrontierCloudFamily(meta.normalizedModel)
  ) {
    tier = SCALE_TIERS.FRONTIER_REASONING;
    rationale = 'Frontier or reasoning-enabled model (>=70B, native reasoning, or frontier cloud family); outer 2PC/plan nudges suppressed.';
  } else if (meta.isMoe && meta.totalParamsB !== null && meta.totalParamsB >= 15) {
    if (preferThinkingStepForSmallActive && meta.activeParamsB !== null && meta.activeParamsB < 15) {
      tier = SCALE_TIERS.SMALL_MODEL;
      rationale = `MoE model (${meta.activeParamsB}B active / ${meta.totalParamsB}B total) opted into small-active PLAN->BIND->ACT step.`;
    } else {
      tier = SCALE_TIERS.MID_MODEL;
      rationale = `MoE model (${meta.activeParamsB ?? '?'}B active / ${meta.totalParamsB}B total >=15B) routed to MID_MODEL with serialized tool rescue.`;
    }
  } else if (
    (meta.activeParamsB !== null && meta.activeParamsB < 15)
    || (meta.totalParamsB !== null && meta.totalParamsB < 15)
  ) {
    tier = SCALE_TIERS.SMALL_MODEL;
    rationale = `Compact non-reasoning model (${meta.activeParamsB ?? meta.totalParamsB}B <15B); PLAN->BIND->ACT step and mechanical rescue enabled.`;
  } else {
    tier = SCALE_TIERS.MID_MODEL;
    rationale = 'Mid-scale model (15B-69B or default mid-tier); Turn-0 grounding sufficient without extra plan/2PC nudges.';
  }

  const isSmall = tier === SCALE_TIERS.SMALL_MODEL;
  const isMid = tier === SCALE_TIERS.MID_MODEL;

  return Object.freeze({
    tier,
    model,
    inferredActiveParamsB: meta.activeParamsB,
    inferredTotalParamsB: meta.totalParamsB,
    isMoe: meta.isMoe,
    thinkingEnabled: meta.thinkingEnabled,
    injectPlanBindStep: isSmall,
    rescueSerializedToolCalls: isSmall || isMid,
    softHoldPlaceholdersAndDates: isSmall,
    maxMechanicalVerifyNudges: isSmall ? 1 : 0,
    enforceZeroMutationImperativeNudge: false,
    enforceTwoPhaseAnalyticalNudge: false,
    maxReadStreak: 0,
    rationale
  });
}

/**
 * Builds the deterministic Turn-0 `[PLAN -> BIND -> ACT]` directive solely when
 * `profile.injectPlanBindStep === true` (`SMALL_MODEL`); returns `""` otherwise.
 *
 * @param {object} [profile] - Resolved scale profile.
 * @returns {string}
 */
export function buildScaleAwareDirective(profile) {
  if (!profile || profile.injectPlanBindStep !== true) {
    return '';
  }
  return SMALL_MODEL_PLAN_BIND_DIRECTIVE;
}
