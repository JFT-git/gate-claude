'use strict';
const { performance } = require('node:perf_hooks');

const TOOL_IDS = Object.freeze(['claude-code', 'tools', 'git', 'powershell']);
const STAGES = Object.freeze(['source-verify', 'host-verify', 'asset-verify', 'decompress', 'executable-verify', 'policy-verify', 'archive-read', 'archive-verify', 'archive-index', 'cache-verify', 'extract', 'staging-verify', 'publish', 'target-verify', 'profile-create', 'ready']);
const INTERVAL_MS = 250;
const NO_PROGRESS = Object.freeze({ begin() {}, update() {}, complete() {} });

// Observation only: callers never await or inspect the observer's return value.
// Events contain fixed identifiers and scalar counts, never paths or native data.
function createPreparationProgress(options = {}, testdeps = {}) {
  let observer;
  try { observer = options?.onProgress; } catch { return NO_PROGRESS; }
  if (typeof observer !== 'function') return NO_PROGRESS;
  const now = testdeps.now || (() => performance.now()), started = now();
  let active, elapsedMS = 0, lastEmittedMS = -Infinity, lastEmittedDone = -1;
  function elapsed() {
    const current = now() - started;
    if (Number.isFinite(current)) elapsedMS = Math.max(elapsedMS, Math.min(Number.MAX_SAFE_INTEGER, Math.floor(current)));
    return elapsedMS;
  }
  function emit(force) {
    const current = elapsed();
    if ((!force && current - lastEmittedMS < INTERVAL_MS) || active.done === lastEmittedDone) return;
    lastEmittedMS = current; lastEmittedDone = active.done;
    const event = Object.freeze({ toolId: active.toolId, stage: active.stage, done: active.done, total: active.total, elapsedMS: current });
    try {
      const returned = observer(event);
      // A UI observer may be async. Its rejection must not become an unhandled
      // rejection, and an unresolved promise must not hold preparation open.
      if (returned && typeof returned.then === 'function') Promise.resolve(returned).catch(() => {});
    } catch {}
  }
  function begin(toolId, stage, total) {
    if (!TOOL_IDS.includes(toolId) || !STAGES.includes(stage) || !Number.isSafeInteger(total) || total < 1) return;
    active = { toolId, stage, done: 0, total }; lastEmittedDone = -1; emit(true);
  }
  function update(done) {
    if (!active || !Number.isSafeInteger(done) || done < active.done || done > active.total) return;
    active.done = done; emit(done === active.total);
  }
  return Object.freeze({ begin, update, complete() { if (active) update(active.total); } });
}
module.exports = { createPreparationProgress, TOOL_IDS, STAGES, INTERVAL_MS };
