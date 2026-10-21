'use strict';
const path = require('node:path');
const LINK_REFUSED = 'Ссылка входа отклонена: запустите Claude через Guard и повторите вход.';
const messages = Object.freeze({ refused: LINK_REFUSED, queued: 'Ссылка входа ожидает готовности защищённой сессии.', delivered: 'Ссылка входа передана в работающий Claude.', failed: 'Не удалось передать ссылку входа. Повторите вход в Claude.', expired: 'Время ожидания ссылки входа истекло. Повторите вход в Claude.' });
// Keep this self-contained: the same validator is embedded in the Windows bootstrap.
function validateClaudeDeepLink(value) {
  if (typeof value !== 'string' || value.length > 8192 || !/^claude:\/\//i.test(value) || /[^\x21-\x7e]|["<>\\]/.test(value) || /%(?![a-f0-9]{2})/i.test(value) || /%(?:0[0-9a-f]|1[0-9a-f]|7f)/i.test(value)) return null;
  try {
    const url = new URL(value), parts = url.hash.slice(1).split(':');
    if (url.protocol !== 'claude:' || url.hostname !== 'claude.ai' || url.pathname !== '/magic-link' || url.port || url.username || url.password || parts.length !== 2 || !parts[0] || !parts[1]) return null;
    return value;
  } catch { return null; }
}
function takeDeepLinkFromArgv(argv) {
  if (!Array.isArray(argv) || argv.length > 64) return { hadLink: true, url: null };
  let candidate, count = 0, total = 0;
  for (let i = 0; i < argv.length; i++) {
    const value = argv[i]; if (typeof value !== 'string') continue;
    total += value.length;
    if (/^claude:/i.test(value)) { count++; candidate = value; argv[i] = ''; }
  }
  return { hadLink: count > 0, url: count === 1 && total <= 32768 ? validateClaudeDeepLink(candidate) : null };
}
function registerGuardProtocol(app, { platform = process.platform, execPath = process.execPath, smokeTest = false } = {}) {
  if (platform !== 'win32' || smokeTest) return { skipped: true, registered: false };
  try {
    if (!path.win32.isAbsolute(execPath)) return { registered: false };
    const args = app.isPackaged ? [] : [app.getAppPath()];
    const registered = app.setAsDefaultProtocolClient('claude', execPath, args);
    return { registered: !!registered && (!app.isDefaultProtocolClient || app.isDefaultProtocolClient('claude', execPath, args)) };
  } catch { return { registered: false }; }
}
class DeepLinkInbox {
  constructor({ active, ready, deliver, notice = () => {}, now = () => performance.now(), ttl = 30000 }) {
    if (!(ttl > 0 && ttl <= 60000)) throw Error('Invalid link lifetime');
    Object.assign(this, { active, ready, deliver, notice, now, ttl }); this.generation = 0;
  }
  clear() { this.generation++; clearTimeout(this.timer); if (this.entry) this.entry.url = ''; this.entry = null; this.flight = null; }
  async accept(raw) {
    const url = validateClaudeDeepLink(raw);
    if (!url || !this.active() || this.entry || this.flight) { this.notice('refused'); return { accepted: false }; }
    const entry = { url, expires: this.now() + this.ttl, generation: this.generation }; this.entry = entry;
    this.timer = setTimeout(() => { if (this.entry === entry) { entry.url = ''; this.entry = null; this.notice('expired'); } }, this.ttl); this.timer.unref?.();
    if (this.ready()) return this.flush();
    this.notice('queued'); return { accepted: true, queued: true };
  }
  async flush() {
    const entry = this.entry;
    if (!entry || this.flight) return { accepted: false };
    if (!this.active() || this.now() >= entry.expires || entry.generation !== this.generation) { clearTimeout(this.timer); entry.url = ''; this.entry = null; this.notice('expired'); return { accepted: false }; }
    if (!this.ready()) return { accepted: true, queued: true };
    clearTimeout(this.timer); this.entry = null;
    const flight = {}; this.flight = flight; let url = entry.url; entry.url = '';
    try {
      // Consume before attempting delivery. A timeout/error must never replay a token.
      const response = await this.deliver(url);
      const delivered = response?.delivered === true && this.generation === entry.generation && this.active();
      if (this.generation === entry.generation) this.notice(delivered ? 'delivered' : 'failed');
      return { accepted: true, delivered };
    } catch { if (this.generation === entry.generation) this.notice('failed'); return { accepted: true, delivered: false }; }
    finally { url = ''; if (this.flight === flight) this.flight = null; }
  }
}
// Runs only inside the already-authenticated Windows runtime channel.
async function forwardRuntimeDeepLink(raw, { app, profileReady, userData, executable, cwd }) {
  let url = validateClaudeDeepLink(raw);
  if (!url) throw Error('Недопустимая ссылка входа.');
  const deadline = performance.now() + 3500;
  let timer;
  const timedOut = new Promise((_, reject) => { timer = setTimeout(() => reject(Error('Handler deadline exceeded')), 3500); });
  try {
    // The deadline includes the profile barrier. Once it expires this invocation
    // is consumed; a later profile resolution must never emit the callback.
    await Promise.race([Promise.resolve(profileReady), timedOut]);
    while (app.listenerCount('second-instance') === 0) {
      const remaining = deadline - performance.now();
      if (remaining <= 0) throw Error('Handler deadline exceeded');
      await Promise.race([new Promise(resolve => setTimeout(resolve, Math.min(25, remaining))), timedOut]);
    }
    if (performance.now() >= deadline) throw Error('Handler deadline exceeded');
    const event = { defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
    if (!app.emit('second-instance', event, [executable, '--user-data-dir=' + userData, url], cwd, {})) throw Error('Handler unavailable');
    return { delivered: true };
  } catch { throw Error('Не удалось передать ссылку входа в Claude.'); }
  finally { clearTimeout(timer); url = ''; }
}
function runtimeDeepLinkSource() { return 'const validateClaudeDeepLink = ' + validateClaudeDeepLink.toString() + ';\nconst guardForwardDeepLink = ' + forwardRuntimeDeepLink.toString() + ';\n'; }
module.exports = { validateClaudeDeepLink, takeDeepLinkFromArgv, registerGuardProtocol, DeepLinkInbox, forwardRuntimeDeepLink, runtimeDeepLinkSource, LINK_REFUSED, messages };
