'use strict';
const { EventEmitter } = require('node:events');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const { IPPolicy, networkFingerprint, validateSettings } = require('./policy.cjs');
const { SOCKSRelay, NetworkRelay } = require('./relay.cjs');
const { initialIP, currentIP } = require('./ip-check.cjs');
const { prepareRuntime, powershell } = require('./runtime.cjs');
const { Channel } = require('./channel.cjs');
const { Inspector } = require('./inspector.cjs');
const { diagnostic } = require('./sanitize.cjs');

class GuardController extends EventEmitter {
  constructor(root, resources) {
    super(); this.root = root; this.resources = resources; this.policy = new IPPolicy(); this.state = 'idle'; this.events = []; this.epoch = 0;
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
  async start(input) {
    this.policy.assertAvailable();
    if (this.state !== 'idle') throw Error('Guard уже работает.');
    const settings = validateSettings(input); this.settings = settings;
    const epoch = ++this.epoch, active = () => this.epoch === epoch && !this.policy.blocked && this.state !== 'idle';
    this.state = 'checking'; this.verified = null; this.status(settings.mode === 'network' ? 'Проверяем страну и закрепляем IP текущей сети / VPN…' : 'Проверяем страну и закрепляем IP через SOCKS5…');
    try {
      // Prepare before pinning so long disk copies cannot leave an old network baseline.
      this.runtime = await prepareRuntime(settings.claudePath, this.root, path.join(this.resources, 'RuntimeBootstrap.cjs'), text => this.status(text));
      if (!active()) return;
      if (this.runtime.signature !== 'Valid') this.log('Подпись исходного Claude не подтверждена: ' + this.runtime.signature, 'warning');
      this.fingerprint = networkFingerprint();
      this.networkTimer = setInterval(() => { if (active() && networkFingerprint() !== this.fingerprint) this.block('Изменились локальные адреса или сетевые интерфейсы.'); }, 1000);
      this.route = await this.routeFingerprint(); if (!active()) return;
      this.relay = settings.mode === 'network' ? new NetworkRelay() : new SOCKSRelay({ host: settings.host, port: settings.port, username: settings.username, password: settings.password });
      this.relay.on('fatal', reason => { if (active()) this.block(reason); });
      const port = await this.relay.start(); if (!active()) return;
      const initial = await initialIP(port); if (!active()) return;
      const pin = this.policy.pin(initial); this.country = pin.country;
      const current = await currentIP(port); if (!active()) return;
      this.policy.check(current.ip); if (!active()) return;
      this.log('Исходный IP закреплён: [IP скрыт] · ' + pin.country);
      this.relay.unlock();
      this.channel = new Channel(); this.channel.on('fatal', reason => { if (active()) this.block(reason); });
      this.inspector = new Inspector(this.channel, settings, settings.captureBodies);
      this.inspector.on('fatal', reason => { if (active()) this.block(reason); });
      this.inspector.on('record', value => this.emit('record', value));
      this.inspector.on('notice', value => this.log(value));
      this.inspector.on('verified', profile => {
        if (!active()) return;
        this.verified = profile; this.state = 'running'; this.emit('verified', profile);
        this.status('Проверено в Claude: ' + profile.timezone + ' · ' + profile.language);
      });
      await this.channel.listen(); if (!active()) return;
      this.state = 'starting'; this.status('Запускаем Claude и проверяем профиль страницы…');
      const env = { ...process.env };
      for (const key of Object.keys(env)) if (/^(?:https?|all|no)_proxy$/i.test(key) || /^ELECTRON_/i.test(key) || /^NODE_OPTIONS$/i.test(key) || /^CLAUDE_/i.test(key)) delete env[key];
      Object.assign(env, { TZ: settings.timezone, LANG: settings.language.replaceAll('-', '_') + '.UTF-8', LC_ALL: settings.language.replaceAll('-', '_') + '.UTF-8',
        LANGUAGE: settings.language, LC_MESSAGES: settings.language.replaceAll('-', '_') + '.UTF-8',
        PROXY_GUARD_CONFIG: JSON.stringify({ userData: this.runtime.profile, timezone: settings.timezone, language: settings.language,
          proxyURL: 'http://127.0.0.1:' + port, channelPipe: this.channel.path, channelToken: this.channel.token }) });
      this.host = spawn(path.join(this.resources, 'GuardHost.exe'), [this.runtime.executable, '--lang=' + settings.language], { env, stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true });
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
      this.log('Локальная копия Claude запущена: ' + settings.timezone + ' · ' + settings.language);
      this.pollTimer = setTimeout(() => this.poll(epoch), settings.interval * 1000);
    } catch (error) { if (this.epoch === epoch) this.block(error.message || 'Ошибка запуска.'); }
  }
  async routeFingerprint() {
    if (process.platform !== 'win32') return '';
    return powershell("@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1','::/0','::/1','8000::/1') } | Sort-Object InterfaceIndex,DestinationPrefix,NextHop | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.InterfaceIndex,$_.NextHop,$_.RouteMetric,$_.DestinationPrefix }) | ConvertTo-Json -Compress", 4000);
  }
  async poll(epoch) {
    if (this.epoch !== epoch || this.policy.blocked || !this.relay) return;
    const started = performance.now();
    try {
      // Start the public check immediately; route queries must not stretch the IP interval.
      const [, route] = await Promise.all([currentIP(this.relay.port).then(result => { if (this.epoch === epoch) this.policy.check(result.ip); }), this.routeFingerprint()]);
      if (this.epoch !== epoch || this.policy.blocked) return;
      if (route !== this.route) { this.block('Изменился маршрут сети.'); return; }
      this.status(this.message);
      this.pollTimer = setTimeout(() => this.poll(epoch), Math.max(0, this.settings.interval * 1000 - (performance.now() - started)));
    } catch { if (this.epoch === epoch) this.block('IP изменился, маршрут потерян или проверка завершилась ошибкой.'); }
  }
  teardown() {
    this.epoch++; clearInterval(this.networkTimer); clearInterval(this.heartbeatTimer); clearTimeout(this.pollTimer);
    this.inspector?.stop(); this.channel?.close(); this.relay?.close();
    // EOF makes GuardHost close its job. Force-terminating the helper also closes its job handle.
    const host = this.host; this.host = null;
    if (host) { host.stdin.end(); const timer = setTimeout(() => host.kill(), 1000); timer.unref(); host.once('exit', () => clearTimeout(timer)); }
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
    const hadSession = this.policy.pinned != null;
    if (hadSession) this.policy.block(); this.teardown();
    this.state = blocked || hadSession ? 'blocked' : 'idle';
    this.status(this.state === 'blocked' ? 'Сессия закрыта. Для нового подключения перезапустите Guard.' : 'Остановлено.');
  }
}
module.exports = { GuardController };
