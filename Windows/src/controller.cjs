'use strict';
const { EventEmitter } = require('node:events');
const { spawn, execFile } = require('node:child_process');
const runFile = require('node:util').promisify(execFile);
const path = require('node:path');
const fs = require('node:fs');
const { IPPolicy, canonicalIP, networkFingerprint, validateSettings } = require('./policy.cjs');
const { SOCKSRelay, NetworkRelay } = require('./relay.cjs');
const { initialIP, currentIP } = require('./ip-check.cjs');
const { prepareRuntime } = require('./runtime.cjs');
const { Channel } = require('./channel.cjs');
const { Inspector } = require('./inspector.cjs');
const { diagnostic } = require('./sanitize.cjs');
const { NetworkFence } = require('./fence.cjs');
const { DeepLinkInbox, messages: linkMessages } = require('./deep-link.cjs');

class GuardController extends EventEmitter {
  constructor(root, resources) {
    super();
    this.deepLinks = new DeepLinkInbox({
      active: () => !this.policy?.blocked && !!this.policy?.pinned && ['starting', 'running', 'rechecking'].includes(this.state) && !!this.host && this.host.exitCode == null && !this.host.killed && !!this.channel && !this.channel.closed,
      ready: () => this.deepLinkReady === true && this.state !== 'rechecking' && !!this.channel?.socket,
      deliver: url => this.channel.command('ProxyGuard.openDeepLink', { url }),
      notice: kind => this.log(linkMessages[kind], ['refused', 'failed', 'expired'].includes(kind) ? 'warning' : 'event')
    });
    this.root = root; this.resources = resources; this.policy = new IPPolicy(); this.state = 'idle'; this.events = []; this.epoch = 0;
    try { this.events = JSON.parse(fs.readFileSync(path.join(root, 'diagnostics.json'), 'utf8')).slice(-80); } catch {}
  }
  status(message) { this.message = message; this.emit('state', this.snapshot()); }
  snapshot() { return { state: this.state, message: this.message || 'Готов к проверке', blocked: this.policy.blocked, profile: this.verified || null, country: this.country || '', exitIP: this.policy.pinned || '' }; }
  log(message, kind = 'event') {
    const event = { date: new Date().toISOString(), kind, message: diagnostic(message) };
    this.events.push(event); this.events = this.events.slice(-80);
    try {
      fs.mkdirSync(this.root, { recursive: true, mode: 0o700 });
      const file = path.join(this.root, 'diagnostics.json'), temp = file + '.tmp';
      fs.writeFileSync(temp, JSON.stringify(this.events, null, 2), { mode: 0o600 }); fs.renameSync(temp, file);
    } catch { /* A full/unavailable disk must not keep the runtime alive after a block. */ }
    this.emit('log', event);
  }
  deliverDeepLink(url) { return this.deepLinks.accept(url); }
  async start(input) {
    this.policy.assertAvailable();
    if (this.state !== 'idle') throw Error('Guard уже работает.');
    const settings = validateSettings(input); this.settings = settings;
    this.deepLinks.clear(); this.deepLinkReady = false;
    const epoch = ++this.epoch, active = () => this.epoch === epoch && !this.policy.blocked && this.state !== 'idle';
    this.state = 'checking'; this.verified = null; this.revalidationRevision = 0; this.status(settings.mode === 'network' ? 'Проверяем страну и закрепляем IP текущей сети / VPN…' : 'Проверяем страну и закрепляем IP через SOCKS5…');
    try {
      // Prepare before pinning so long disk copies cannot leave an old network baseline.
      this.runtime = await prepareRuntime(settings.claudePath, this.root, path.join(this.resources, 'RuntimeBootstrap.cjs'), text => this.status(text));
      if (!active()) return;
      if (this.runtime.signature !== 'Valid') this.log('Подпись исходного Claude не подтверждена: ' + this.runtime.signature, 'warning');
      this.fingerprint = networkFingerprint();
      this.networkTimer = setInterval(() => {
        if (!active()) return;
        const fingerprint = networkFingerprint();
        if (fingerprint !== this.fingerprint) {
          this.fingerprint = fingerprint;
          this.revalidate('Изменились локальные адреса или сетевые интерфейсы. Проверяем закреплённый IP.');
        }
      }, 1000);
      this.route = await this.routeFingerprint(); if (!active()) return;
      this.relay = settings.mode === 'network' ? new NetworkRelay() : new SOCKSRelay({ host: settings.host, port: settings.port, username: settings.username, password: settings.password });
      this.relay.on('fatal', reason => { if (active()) this.block(reason); });
      this.relay.on('revalidate', reason => { if (active()) this.revalidate(reason); });
      const port = await this.relay.start(); if (!active()) return;
      this.status('Устанавливаем сетевые ограничения Windows для копии Claude…');
      this.fencePending = true;
      let fence;
      try { fence = await NetworkFence.prepare(this.runtime, port, { helperPath: path.join(this.resources, 'NetworkFence.exe') }); }
      finally { this.fencePending = false; }
      if (!active()) { await fence.close(); return; }
      this.fence = fence;
      fence.on('fatal', () => { if (active()) this.block('Сетевая защита Windows потеряна. Сессия закрыта.'); });
      const initial = await this.requestIP(epoch, initialIP, port, this.relay.checkToken); if (!active()) return;
      const pin = this.policy.pin(initial); this.country = pin.country;
      const current = await this.requestIP(epoch, currentIP, port, this.relay.checkToken); if (!active()) return;
      this.policy.check(current.ip); if (!active()) return;
      this.log('Исходный IP закреплён: [IP скрыт] · ' + pin.country);
      // Monitor throughout runtime startup, including a slow diagnostic connection.
      this.schedulePoll(epoch, settings.interval * 1000);
      if (this.state !== 'rechecking') this.relay.unlock();
      this.channel = new Channel(); this.channel.on('fatal', reason => { if (active()) this.block(reason); });
      this.inspector = new Inspector(this.channel, settings, settings.captureBodies);
      this.inspector.on('fatal', reason => { if (active()) this.block(reason); });
      this.inspector.on('record', value => this.emit('record', value));
      this.inspector.on('notice', value => this.log(value));
      this.inspector.on('verified', profile => {
        if (!active()) return;
        this.verified = profile; this.emit('verified', profile);
        if (this.state !== 'rechecking') {
          this.state = 'running'; this.status('Проверено в Claude: ' + profile.timezone + ' · ' + profile.language);
          void this.deepLinks.flush();
        }
      });
      await this.channel.listen(); if (!active()) return;
      if (this.state !== 'rechecking') { this.state = 'starting'; this.status('Запускаем Claude и проверяем профиль страницы…'); }
      const env = { ...process.env };
      for (const key of Object.keys(env)) if (/^(?:https?|all|no)_proxy$/i.test(key) || /^ELECTRON_/i.test(key) || /^NODE_OPTIONS$/i.test(key) || /^CLAUDE_/i.test(key)) delete env[key];
      Object.assign(env, { TZ: settings.timezone, LANG: settings.language.replaceAll('-', '_') + '.UTF-8', LC_ALL: settings.language.replaceAll('-', '_') + '.UTF-8',
        LANGUAGE: settings.language, LC_MESSAGES: settings.language.replaceAll('-', '_') + '.UTF-8',
        PROXY_GUARD_CONFIG: JSON.stringify({ userData: this.runtime.profile, timezone: settings.timezone, language: settings.language,
          proxyURL: 'http://127.0.0.1:' + port, channelPipe: this.channel.path, channelToken: this.channel.token }) });
      this.host = spawn(path.join(this.resources, 'GuardHost.exe'), [this.runtime.executable, '--user-data-dir=' + this.runtime.profile, '--lang=' + settings.language], { env, stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true });
      let output = '';
      this.host.stdout.on('data', chunk => {
        output = (output + chunk).slice(-8192); let end;
        while ((end = output.indexOf('\n')) >= 0) {
          const line = output.slice(0, end); output = output.slice(end + 1);
          try { const message = JSON.parse(line); if (message.pid) this.runtimePID = message.pid; if (message.exitCode != null) this.exitCode = message.exitCode; } catch {}
        }
      });
      this.host.once('error', () => { if (active()) this.block('Не удалось запустить Windows Job Object helper.'); });
      this.host.once('exit', code => { if (active()) this.block('Claude завершился. Код: ' + (this.exitCode ?? code ?? 'неизвестен') + '.'); });
      this.host.stdin.on('error', () => {});
      const heartbeat = () => { if (this.host && !this.host.stdin.destroyed) this.host.stdin.write('ping\n'); };
      heartbeat(); this.heartbeatTimer = setInterval(heartbeat, 1000);
      await this.channel.connected(); if (!active()) return;
      await this.inspector.start(); if (!active()) return;
      this.deepLinkReady = true; await this.deepLinks.flush(); if (!active()) return;
      this.log('Локальная копия Claude запущена: ' + settings.timezone + ' · ' + settings.language);
    } catch (error) { if (this.epoch === epoch) this.block(error.message || 'Ошибка запуска.'); }
  }
  async routeFingerprint() {
    if (process.platform !== 'win32') return '';
    try {
      const { stdout } = await runFile(path.join(this.resources, 'GuardHost.exe'), ['--route-fingerprint'],
        { windowsHide: true, timeout: 4000, maxBuffer: 65536, encoding: 'utf8' });
      const routes = JSON.parse(stdout.trim());
      if (!Array.isArray(routes) || routes.some(route => typeof route !== 'string' || route.length > 256)) throw Error('Invalid route snapshot');
      return JSON.stringify(routes);
    } catch {
      throw Error('Не удалось прочитать таблицу маршрутов Windows. Трафик остаётся закрытым.');
    }
  }
  async requestIP(epoch, check, port, token) {
    // A cancelled request may still be settling; never overlap it with a new one.
    while (this.ipRequest) {
      try { await this.ipRequest; } catch {}
      if (this.epoch !== epoch) throw Error('Проверка отменена.');
    }
    if (this.epoch !== epoch) throw Error('Проверка отменена.');
    const request = Promise.resolve().then(() => check(port, token, require('node:net').isIP(this.policy.pinned || ''))); this.ipRequest = request;
    try { return await request; }
    finally { if (this.ipRequest === request) this.ipRequest = null; }
  }
  schedulePoll(epoch, delay) {
    clearTimeout(this.pollTimer);
    if (this.epoch !== epoch || this.policy.blocked || !this.relay) return;
    this.pollTimer = setTimeout(() => this.poll(epoch), Math.max(0, delay));
  }
  pauseForRevalidation(reason, invalidate = true) {
    if (!this.relay || !this.policy.pinned || this.policy.blocked || ['idle', 'blocked'].includes(this.state)) return false;
    if (invalidate) this.revalidationRevision = (this.revalidationRevision || 0) + 1;
    this.relay.pause();
    if (this.state !== 'rechecking') this.log(reason, 'warning');
    this.state = 'rechecking';
    this.status(reason + ' Трафик приостановлен до подтверждения прежнего IP.');
    return true;
  }
  revalidate(reason = 'Повторная проверка закреплённого IP.') {
    if (!this.pauseForRevalidation(reason)) return Promise.resolve();
    clearTimeout(this.pollTimer);
    return this.poll(this.epoch);
  }
  poll(epoch) {
    if (this.epoch !== epoch || this.policy.blocked || !this.relay) return Promise.resolve();
    if (this.checkTask) {
      const task = this.checkTask;
      return task.epoch === epoch ? task.promise : task.promise.then(() => this.poll(epoch));
    }
    clearTimeout(this.pollTimer);
    const task = { epoch, revision: this.revalidationRevision || 0, started: performance.now() };
    const active = () => this.epoch === epoch && !this.policy.blocked && this.relay;
    const before = networkFingerprint(), relayPort = this.relay.port, checkToken = this.relay.checkToken;
    task.promise = (async () => {
      // Validate an IP result as soon as it arrives; a slow route query cannot delay a confirmed kill.
      const address = this.requestIP(epoch, currentIP, relayPort, checkToken).then(result => {
        if (!active()) return null;
        const ip = canonicalIP(result?.ip); // A malformed provider answer is temporary, not a new IP.
        if (require('node:net').isIP(ip) !== require('node:net').isIP(this.policy.pinned)) throw Error('Сервис вернул другое семейство IP.');
        if (ip !== this.policy.pinned) {
          this.block('Внешний IP изменился. Сессия закрыта до перезапуска Guard.');
          return null;
        }
        this.policy.check(ip); return ip;
      }).catch(error => {
        if (active()) this.pauseForRevalidation('Не удалось подтвердить закреплённый IP. Повторяем проверку.', false);
        throw error;
      });
      const routes = Promise.resolve().then(() => this.routeFingerprint()).then(route => {
        if (active() && route !== this.route && this.state !== 'rechecking') {
          this.pauseForRevalidation('Изменился маршрут сети. Проверяем закреплённый IP.');
        }
        return route;
      }).catch(error => {
        if (active()) this.pauseForRevalidation('Не удалось проверить маршрут сети. Повторяем проверку.', false);
        throw error;
      });
      const [ip, route] = await Promise.allSettled([address, routes]);
      if (!active()) return;
      if (ip.status !== 'fulfilled' || !ip.value || route.status !== 'fulfilled') {
        this.pauseForRevalidation('Не удалось подтвердить закреплённый IP или маршрут. Повторяем проверку.', false);
        return;
      }
      const after = networkFingerprint();
      if (before !== after) {
        this.fingerprint = after;
        this.pauseForRevalidation('Во время проверки изменились сетевые интерфейсы. Проверяем IP повторно.');
        return;
      }
      // An event arriving during the request requires a fresh answer after that event.
      if (task.revision !== (this.revalidationRevision || 0)) return;
      if (route.value !== this.route && this.state !== 'rechecking') {
        this.pauseForRevalidation('Изменился маршрут сети. Проверяем закреплённый IP.');
        return;
      }
      if (this.state === 'rechecking') {
        this.route = route.value; this.fingerprint = after;
        this.relay.resume();
        this.state = this.verified ? 'running' : 'starting';
        void this.deepLinks.flush();
        this.log('Прежний внешний IP подтверждён. Соединение возобновлено.');
        this.status(this.verified ? 'Проверено в Claude: ' + this.verified.timezone + ' · ' + this.verified.language : 'IP подтверждён. Запускаем Claude и проверяем профиль страницы…');
      } else this.status(this.message);
    })().catch(() => {
      if (active()) this.pauseForRevalidation('Проверка сети не завершилась. Повторяем проверку.', false);
    }).finally(() => {
      if (this.checkTask === task) this.checkTask = null;
      if (!active()) return;
      const changed = task.revision !== (this.revalidationRevision || 0);
      this.schedulePoll(epoch, changed ? 0 : Math.max(0, this.settings.interval * 1000 - (performance.now() - task.started)));
    });
    this.checkTask = task; return task.promise;
  }
  teardown() {
    this.deepLinkReady = false; this.deepLinks.clear();
    this.epoch++; clearInterval(this.networkTimer); clearInterval(this.heartbeatTimer); clearTimeout(this.pollTimer);
    this.inspector?.stop(); this.channel?.close(); this.relay?.close();
    // EOF makes GuardHost close its job. Force-terminating the helper also closes its job handle.
    const host = this.host, fence = this.fence; this.host = null; this.fence = null;
    const closeFence = () => { if (fence) fence.close().catch(() => this.log('Ограничения Windows сохранены: завершение защищённой копии не подтверждено.', 'warning')); };
    if (host) {
      host.stdin.end(); const timer = setTimeout(() => host.kill(), 1000); timer.unref();
      if (host.exitCode != null || host.signalCode != null) { clearTimeout(timer); closeFence(); }
      else host.once('exit', () => { clearTimeout(timer); closeFence(); });
    } else closeFence();
    this.inspector = null; this.channel = null; this.relay = null;
    if (this.settings) this.settings.password = ''; this.settings = null; this.verified = null; this.exitCode = null;
  }
  block(reason) {
    if (this.state === 'blocked') return;
    this.policy.block(); this.teardown(); this.state = 'blocked';
    this.log(reason, 'blocked'); this.status(reason);
  }
  stop() {
    const blocked = this.policy.blocked;
    // Pinning a second exit in the same Guard process is forbidden even after a manual stop.
    const hadSession = this.policy.pinned != null || this.fencePending || Boolean(this.fence);
    if (hadSession) this.policy.block(); this.teardown();
    this.state = blocked || hadSession ? 'blocked' : 'idle';
    this.status(this.state === 'blocked' ? 'Сессия закрыта. Для нового подключения перезапустите Guard.' : 'Остановлено.');
  }
}
module.exports = { GuardController };
