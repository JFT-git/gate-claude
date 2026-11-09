'use strict';
const { EventEmitter } = require('node:events');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const net = require('node:net');
const { IPPolicy, canonicalIP, networkFingerprint, validateSettings } = require('./policy.cjs');
const { IPMemory, MISMATCH } = require('./ip-memory.cjs');
const { SOCKSRelay, NetworkRelay, setPinnedLocalAddresses, capturedEgressLocalAddresses, beginEgressCapture } = require('./relay.cjs');
const { initialIP, currentIP, queryDestinationIP, NetworkCheckError, dnsProbe } = require('./ip-check.cjs');
const { readSystemProxy } = require('./system-proxy.cjs');
const { prepareRuntime } = require('./runtime.cjs');
const { Channel } = require('./channel.cjs');
const { Inspector } = require('./inspector.cjs');
const { diagnostic } = require('./sanitize.cjs');
const { readRouteFingerprint, RouteReadError } = require('./route-reader.cjs');
const { NetworkFence } = require('./fence.cjs');
const { prepareCodeFiles } = require('./code-preparation.cjs');
const { prepareCodeTools, SOURCE_POLICY: CODE_TOOLS_POLICY } = require('./code-tools.cjs');
const { ensureNativeCodeAsset } = require('./native-code-asset.cjs');
const { CodeGate } = require('./code-gate.cjs');
const { randomBytes } = require('node:crypto');
const { DeepLinkInbox, messages: linkMessages } = require('./deep-link.cjs');
const DESTINATIONS = Object.freeze(['claude.ai', 'api.anthropic.com']);
const FREEZE_LIMIT_MS = 20000;
const FREEZE_RETRY_MS = 1000;
const FREEZE_CLOSE_MS = 5000;
const HOST_COMMAND_TIMEOUT_MS = 5000;
function emptyNetworkMetrics() {
  return { sources: [], organization: '', asn: '', destinations: {}, dns: { state: 'idle' }, dnsProtection: '', webRTC: 'disable_non_proxied_udp', quic: 'disabled' };
}

class GuardController extends EventEmitter {
  constructor(root, resources, options = {}) {
    super(); this.codeCleanups = new WeakMap(); this.codeStatePreparations = new WeakMap();
    this.pendingOperations = new Set(); this.startTask = null; this.shutdownFailed = false;
    this.destinationPolicies = new Map(); this.destinationRequests = new Map(); this.probeFailures = new Map();
    this.networkMetrics = emptyNetworkMetrics(); this.dnsProbe = options.dnsProbe || dnsProbe; this.dnsMetricsTask = null;
    this.deepLinks = new DeepLinkInbox({
      active: () => !this.policy?.blocked && !!this.policy?.pinned && ['starting', 'running', 'rechecking'].includes(this.state) && !!this.host && this.host.exitCode == null && !this.host.killed && !!this.channel && !this.channel.closed,
      ready: () => this.deepLinkReady === true && this.state !== 'rechecking' && !!this.channel?.socket,
      deliver: url => this.channel.command('ProxyGuard.openDeepLink', { url }),
      notice: kind => this.log(linkMessages[kind], ['refused', 'failed', 'expired'].includes(kind) ? 'warning' : 'event')
    });
    this.fenceOwnerWindow = options.ownerWindow;
    this.fenceServiceLaunch = options.serviceLaunch;
    this.root = root; this.resources = resources; this.diagnostics = options.diagnostics || { event() {} };
    this.policy = new IPPolicy(); this.state = 'idle'; this.events = []; this.epoch = 0;
    this.processFrozen = false; this.processState = 'running'; this.freezeDeadline = null; this.freezeWanted = false; this.recheckingSince = null;
    this.hostCommands = new Map(); this.hostCommandID = 0;
    this.ipMemory = new IPMemory(root); this.savedIP = null; this.ipMemoryError = '';
    try { this.savedIP = this.ipMemory.load(); } catch (error) { this.ipMemoryError = error.message; }
    try { this.events = JSON.parse(fs.readFileSync(path.join(root, 'diagnostics.json'), 'utf8')).slice(-80); } catch {}
  }
  status(message) {
    this.message = message;
    const transition = [this.epoch, this.state, this.processState].join(':');
    if (this.diagnosticTransition !== transition) {
      this.diagnosticTransition = transition;
      this.diagnostics.event('state', { epoch: this.epoch, state: this.state, processState: this.processState,
        processFrozen: this.processFrozen, hostLive: this.liveHost(), relayOpen: Boolean(this.relay && !this.relay.closed),
        relayUnlocked: this.relay?.unlocked === true, message });
    }
    this.emit('state', this.snapshot());
  }
  snapshot() {
    const secondsRemaining = this.processFrozen && this.freezeDeadline !== null ? Math.max(0, Math.ceil((this.freezeDeadline - performance.now()) / 1000)) : 0;
    const metrics = this.networkMetrics || emptyNetworkMetrics();
    return { state: this.state, message: this.message || 'Готов к проверке', blocked: this.policy.blocked, profile: this.verified || null,
      country: this.country || '', exitIP: this.policy.pinned || '', savedIP: this.savedIP, ipMemoryError: this.ipMemoryError,
      processFrozen: this.processFrozen, processState: this.processFrozen ? this.processState : 'running', secondsRemaining,
      windowsApprovalPending: NetworkFence.approvalPending,
      metrics: { ...metrics, sources: [...(metrics.sources || [])], destinations: { ...(metrics.destinations || {}) }, dns: { ...(metrics.dns || { state: 'idle' }) } } };
  }
  canResetIP() { return ['idle', 'blocked'].includes(this.state) && !NetworkFence.approvalPending && !this.fencePending && !this.codePreparationPending; }
  resetIP() {
    if (!this.canResetIP()) throw Error('Сначала остановите сессию Claude и дождитесь завершения запуска.');
    this.stop();
    this.ipMemory.reset(); this.savedIP = null; this.ipMemoryError = '';
    this.policy = new IPPolicy(); this.country = ''; this.state = 'idle';
    this.log('Закрепление IP сброшено пользователем после подтверждения.', 'warning');
    this.status('Память IP сброшена. Следующий проверенный адрес будет закреплён.');
    return this.snapshot();
  }
  log(message, kind = 'event') {
    const event = { date: new Date().toISOString(), kind, message: diagnostic(message) };
    this.events.push(event); this.events = this.events.slice(-80);
    try {
      fs.mkdirSync(this.root, { recursive: true, mode: 0o700 });
      const file = path.join(this.root, 'diagnostics.json'), temp = file + '.tmp';
      fs.writeFileSync(temp, JSON.stringify(this.events, null, 2), { mode: 0o600 }); fs.renameSync(temp, file);
    } catch { /* A full/unavailable disk must not keep the runtime alive after a block. */ }
    this.diagnostics.event('user', { kind, message: event.message });
    this.emit('log', event);
  }
  reportProbeFailure(source, error, elapsedMS) {
    if (!['geo', 'public', 'claude.ai', 'api.anthropic.com', 'proxy'].includes(source)) return;
    // Only diagnostics created by our checker cross this boundary. Never log a
    // TLS/HTTP/registry error's message, cause, headers, payload or address.
    const typed = typeof NetworkCheckError === 'function' && error instanceof NetworkCheckError;
    const code = typed && /^(?:TIMEOUT|CONNECT|TLS|HTTP_STATUS|HEADERS|SIZE|BODY|ABORTED|RESPONSE|REQUEST|INVALID_ARGUMENT)$/.test(error.code) ? error.code : 'UNCONFIRMED';
    const phase = typed && /^(?:arguments|connect|tls|request|headers|body|response)$/.test(error.phase) ? error.phase : 'check';
    const http = typed && Number.isInteger(error.httpStatus) && error.httpStatus >= 100 && error.httpStatus <= 599 ? error.httpStatus : null;
    const now = performance.now(), key = [source, code, phase, http].join(':');
    if (this.probeFailures.has(key) && now - this.probeFailures.get(key) < 30000) return;
    this.probeFailures.set(key, now);
    while (this.probeFailures.size > 32) this.probeFailures.delete(this.probeFailures.keys().next().value);
    const duration = Number.isFinite(elapsedMS) ? Math.max(0, Math.min(600000, Math.round(elapsedMS))) : 0;
    this.log('Проверка сети: ' + source + ' · ' + code + ' · ' + phase + (http === null ? '' : ' · HTTP ' + http) + ' · ' + duration + ' мс.', 'warning');
  }
  preparationProgress(value) {
    const tools = { 'claude-code': 'Claude Code', tools: 'Git и PowerShell', git: 'Git', powershell: 'PowerShell' };
    const stages = {
      'source-verify': 'Проверяем исходное приложение', 'host-verify': 'Проверяем запуск защиты',
      'asset-verify': 'Проверяем комплект', decompress: 'Распаковываем комплект',
      'executable-verify': 'Проверяем программу', 'cache-verify': 'Проверяем сохранённые файлы',
      publish: 'Сохраняем проверенные файлы', 'target-verify': 'Проверяем установленные файлы',
      'profile-create': 'Готовим изоляцию', ready: 'Файлы готовы',
      'policy-verify': 'Проверяем список файлов', 'archive-read': 'Читаем комплект',
      'archive-verify': 'Проверяем комплект', 'archive-index': 'Проверяем структуру комплекта',
      extract: 'Подготавливаем файлы', 'staging-verify': 'Проверяем подготовленные файлы'
    };
    if (!value || !Object.hasOwn(tools, value.toolId) || !Object.hasOwn(stages, value.stage) ||
        !Number.isSafeInteger(value.done) || !Number.isSafeInteger(value.total) || value.done < 0 ||
        value.total < value.done || value.total > 100000 || !Number.isFinite(value.elapsedMS) || value.elapsedMS < 0) return;
    const label = stages[value.stage] + ' · ' + tools[value.toolId];
    const stage = value.toolId + ':' + value.stage;
    if (this.preparationStage !== stage) {
      this.preparationStage = stage;
      this.log('Подготовка: ' + label + ' · ' + Math.min(86400000, Math.round(value.elapsedMS)) + ' мс.');
    }
    if (this.state !== 'rechecking') this.status(label + (value.total > 1 ? ' · ' + value.done + ' / ' + value.total : '') + '…');
  }
  deliverDeepLink(url) { return this.deepLinks.accept(url); }
  track(operation) {
    const task = Promise.resolve(operation);
    this.pendingOperations.add(task);
    task.finally(() => { this.pendingOperations.delete(task); }).catch(() => {});
    return task;
  }
  liveHost(host = this.host) {
    return !!host && host.exitCode == null && host.signalCode == null && !host.killed && !!host.stdin && !host.stdin.destroyed;
  }
  canFreezeProcess() { return !!this.verified && this.liveHost() && !!this.relay && !this.relay.closed && !this.policy.blocked; }
  resolveHostCommand(message) {
    const key = message.freezeAck !== undefined ? 'freezeAck' : message.thawAck !== undefined ? 'thawAck' : null;
    if (!key) return false;
    const id = message[key], entry = this.hostCommands.get(id);
    if (!entry || entry.command !== key.slice(0, -3)) {
      this.diagnostics.event('host_command_unmatched', { id, command: key.slice(0, -3), nativeOk: message.ok === true,
        count: Number.isSafeInteger(message.count) ? message.count : null, error: typeof message.error === 'string' ? message.error.slice(0, 256) : '' });
      return true;
    }
    this.hostCommands.delete(id); clearTimeout(entry.timer);
    const reason = typeof message.error === 'string' && message.error.length <= 256 ? ': ' + message.error : '';
    const valid = message.ok === true && Number.isSafeInteger(message.count) && message.count >= 0 && message.count <= 4096;
    this.diagnostics.event('host_command_ack', { id, command: entry.command, epoch: entry.epoch, revision: entry.revision,
      ok: valid, nativeOk: message.ok === true, count: Number.isSafeInteger(message.count) ? message.count : null,
      error: reason.slice(2), elapsedMS: performance.now() - entry.started, inFlight: this.hostCommands.size });
    if (!valid) entry.reject(Error('GuardHost rejected the process state change' + reason + '.'));
    else entry.resolve({ count: message.count });
    return true;
  }
  rejectHostCommands(host = null) {
    for (const [id, entry] of this.hostCommands) {
      if (host && entry.host !== host) continue;
      clearTimeout(entry.timer); this.hostCommands.delete(id);
      this.diagnostics.event('host_command_cancelled', { id, command: entry.command, epoch: entry.epoch, revision: entry.revision,
        elapsedMS: performance.now() - entry.started, inFlight: this.hostCommands.size });
      entry.reject(Error('GuardHost command cancelled.'));
    }
  }
  hostCommand(command, host = this.host) {
    if (!this.liveHost(host)) return Promise.reject(Error('GuardHost is not running.'));
    const id = ++this.hostCommandID, started = performance.now(), epoch = this.epoch, revision = this.revalidationRevision || 0;
    this.diagnostics.event('host_command_start', { id, command, epoch, revision, timeoutMS: HOST_COMMAND_TIMEOUT_MS, inFlight: this.hostCommands.size + 1 });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.hostCommands.delete(id);
        this.diagnostics.event('host_command_timeout', { id, command, epoch, revision, elapsedMS: performance.now() - started, inFlight: this.hostCommands.size });
        reject(Error('GuardHost command timed out.'));
      }, HOST_COMMAND_TIMEOUT_MS);
      this.hostCommands.set(id, { host, command, resolve, reject, timer, started, epoch, revision });
      host.stdin.write(command + ' ' + id + '\n', error => {
        if (!error || !this.hostCommands.has(id)) return;
        clearTimeout(timer); this.hostCommands.delete(id);
        this.diagnostics.event('host_command_write_error', { id, command, epoch, revision, code: error.code || '',
          elapsedMS: performance.now() - started, inFlight: this.hostCommands.size });
        reject(error);
      });
    });
  }
  clearProcessFreeze() {
    clearTimeout(this.freezeTimeout); clearInterval(this.freezeTicker);
    this.processFrozen = false; this.processState = 'running'; this.freezeDeadline = null; this.freezeWanted = false; this.freezeClosing = null;
  }
  requestProcessFreeze() {
    if (!this.canFreezeProcess() || this.freezeClosing) return false;
    const epoch = this.epoch, host = this.host; this.freezeWanted = true;
    this.channel?.setFrozen?.(true);
    if (!this.processFrozen) {
      this.processFrozen = true; this.processState = 'freezing'; this.freezeDeadline = performance.now() + FREEZE_LIMIT_MS;
      this.freezeTimeout = setTimeout(() => this.closeFrozenSession(epoch, host), FREEZE_LIMIT_MS);
      this.freezeTicker = setInterval(() => { if (this.epoch === epoch && this.processFrozen) this.status(this.message); }, 1000);
    }
    if (this.processState === 'thawing') return true;
    if (this.processState === 'frozen' || this.processState === 'freezing' && this.freezeTask) return true;
    this.processState = 'freezing';
    const operation = (async () => {
      try {
        await this.hostCommand('freeze', host);
        if (this.epoch !== epoch || this.host !== host) return false;
        this.freezeWanted = false; if (!this.freezeClosing) this.processState = 'frozen';
        this.status(this.message); return true;
      } catch {
        if (this.epoch === epoch && this.host === host) this.block('Windows не подтвердила приостановку процессов Claude. Сессия закрыта.');
        return false;
      } finally { if (this.freezeTask === operation) this.freezeTask = null; }
    })();
    this.freezeTask = operation; this.track(operation); return true;
  }
  async thawProcess(epoch) {
    if (!this.processFrozen) return this.epoch === epoch && !this.freezeClosing;
    if (this.freezeTask) {
      const pending = this.freezeTask, completed = await pending;
      if (this.epoch !== epoch) return false;
      if (this.processState === 'thawed') return completed && !this.freezeWanted;
      if (!completed) return false;
    }
    if (this.processState === 'thawed') {
      if (this.freezeWanted && !this.freezeClosing) { this.requestProcessFreeze(); return false; }
      return true;
    }
    if (this.processState !== 'frozen' && !(this.freezeClosing && this.processState === 'closing')) return false;
    const host = this.host;
    if (!this.liveHost(host)) return false;
    this.freezeWanted = false;
    if (!this.freezeClosing) this.processState = 'thawing';
    const operation = (async () => {
      try {
        await this.hostCommand('thaw', host);
        if (this.epoch !== epoch || this.host !== host) return false;
        this.channel?.setFrozen?.(false);
        if (!this.freezeClosing) this.processState = 'thawed';
        if (this.freezeWanted && !this.freezeClosing) { this.requestProcessFreeze(); return false; }
        this.status(this.message); return true;
      } catch {
        if (this.epoch === epoch && this.host === host) this.block('Windows не подтвердила возобновление процессов Claude. Сессия закрыта.');
        return false;
      } finally { if (this.freezeTask === operation) this.freezeTask = null; }
    })();
    this.freezeTask = operation; this.track(operation); return operation;
  }
  async resumeValidatedSession(epoch, revision) {
    const valid = () => this.epoch === epoch && (this.revalidationRevision || 0) === revision && !this.policy.blocked && !!this.relay && !this.freezeClosing;
    if (!valid() || !await this.thawProcess(epoch) || !valid() || this.freezeWanted) return false;
    try { this.relay.resume(); }
    catch { if (valid()) this.block('Не удалось возобновить защищённый шлюз. Сессия закрыта.'); return false; }
    if (!valid()) { this.relay?.pause(); return false; }
    this.recheckingSince = null; this.clearProcessFreeze();
    this.diagnostics.event('revalidation_resume', { epoch, revision, relayUnlocked: this.relay.unlocked === true });
    return true;
  }
  closeFrozenSession(epoch, host) {
    if (this.epoch !== epoch || this.host !== host || !this.processFrozen || this.freezeClosing) return;
    const closing = { epoch, host }, started = performance.now(), thawPending = this.processState === 'thawing' && this.freezeTask;
    this.freezeClosing = closing;
    this.freezeWanted = false; this.processState = 'closing'; this.revalidationRevision = (this.revalidationRevision || 0) + 1;
    clearTimeout(this.pollTimer);
    this.status('Сеть не подтверждена за 20 секунд. Возобновляем процессы и закрываем Claude…');
    const operation = (async () => {
      const active = () => this.epoch === epoch && this.host === host && this.freezeClosing === closing;
      const thawed = thawPending ? await thawPending : await this.thawProcess(epoch);
      if (!active()) return;
      if (thawed && this.channel && !this.channel.closed && this.liveHost(host)) {
        const exited = this.liveHost(host) ? new Promise(resolve => host.once('exit', resolve)) : Promise.resolve();
        let timer;
        try {
          try { void this.channel.command('Browser.close').catch(() => {}); } catch {}
          const remaining = Math.max(0, FREEZE_CLOSE_MS - (performance.now() - started));
          await Promise.race([exited, new Promise(resolve => { timer = setTimeout(resolve, remaining); })]);
        } finally { clearTimeout(timer); }
      }
      if (active()) this.block('Сеть не подтверждена за 20 секунд. Claude закрыт; открытые потоки не восстанавливаются.');
    })();
    this.track(operation);
  }
  hostedIPMismatch(reason) {
    if (this.canFreezeProcess() || this.processFrozen && this.liveHost()) {
      this.pauseForRevalidation(reason + ' Проверяем соединение с приостановленными процессами.');
    } else this.block(reason + ' Сессия закрыта до перезапуска Guard.');
    return false;
  }
  start(input) {
    const task = Promise.resolve().then(() => this.startSession(input));
    this.startTask = task;
    task.finally(() => { if (this.startTask === task) this.startTask = null; }).catch(() => {});
    return task;
  }
  async startSession(input) {
    this.policy.assertAvailable();
    if (this.state !== 'idle') throw Error('Guard уже работает.');
    const settings = validateSettings(input); this.settings = settings;
    this.networkMetrics = emptyNetworkMetrics(); this.networkMetrics.dnsProtection = settings.mode === 'socks5' ? 'remote_socks5' : 'pinned_egress'; this.dnsMetricsTask = null;
    this.deepLinks.clear(); this.deepLinkReady = false; this.probeFailures.clear(); this.preparationStage = null;
    const epoch = ++this.epoch, active = () => this.epoch === epoch && !this.policy.blocked && this.state !== 'idle';
    let code = null; this.codeFenceRequested = false; this.runtimePID = null;
    this.codePreparationPending = settings.codeEnabled === true; this.codePreparationEpoch = epoch;
    this.state = 'checking'; this.verified = null; this.revalidationRevision = 0; this.status(settings.mode === 'network' ? 'Проверяем страну и закрепляем IP текущей сети / VPN…' : 'Проверяем страну и закрепляем IP через SOCKS5…');
    try {
      try { this.savedIP = this.ipMemory.load(); this.ipMemoryError = ''; }
      catch (error) { this.ipMemoryError = error.message; throw error; }
      // Validate and clone the signed source before any Code asset can be downloaded.
      // Cancellation also latches during runtime copying, before Code's profile exists.
      const preparedRuntime = await prepareRuntime(settings.claudePath, this.root, path.join(this.resources, 'RuntimeBootstrap.cjs'), text => { if (active()) this.status(text); }, settings.codeEnabled === true ? { codeEnabled: true } : undefined);
      if (!active()) return;
      this.runtime = preparedRuntime;
      if (this.runtime.signature !== 'Valid') {
        if (settings.codeEnabled === true) throw Error('Подпись исходного Claude не подтверждена. Claude Code не запущен.');
        this.log('Подпись исходного Claude не подтверждена: ' + this.runtime.signature, 'warning');
      }
      this.fingerprint = networkFingerprint();
      this.networkTimer = setInterval(() => {
        if (!active()) return;
        const fingerprint = networkFingerprint();
        if (fingerprint !== this.fingerprint) {
          this.relay?.pause();
          this.fingerprint = fingerprint;
          this.revalidate('Изменились локальные адреса или сетевые интерфейсы. Проверяем закреплённый IP.');
        }
      }, 1000);
      this.route = await this.routeFingerprint(); if (!active()) return;
      setPinnedLocalAddresses(null); beginEgressCapture();
      this.networkProxy = settings.mode === 'network' ? Object.freeze({ ...await this.networkProxyConfiguration() }) : null;
      if (!active()) return;
      this.relay = settings.mode === 'network' ? new NetworkRelay({ upstream: this.networkProxy }) : new SOCKSRelay({ host: settings.host, port: settings.port, username: settings.username, password: settings.password });
      this.relay.on('fatal', reason => { if (active()) this.block(reason); });
      this.relay.on('revalidate', reason => { if (active()) this.revalidate(reason); });
      const port = await this.relay.start(); if (!active()) return;
      const pinExit = async () => {
        const revision = this.revalidationRevision || 0, interfaces = networkFingerprint();
        const initial = await this.requestIP(epoch, initialIP, port, this.relay.checkToken); if (!active()) return false;
        this.networkMetrics.sources = Array.isArray(initial.providers) ? initial.providers.filter(host => ['ipwho.is', 'ipinfo.io', 'ipapi.co'].includes(host)).slice(0, 3) : [];
        this.networkMetrics.organization = typeof initial.organization === 'string' ? initial.organization.slice(0, 160) : '';
        this.networkMetrics.asn = typeof initial.asn === 'string' && /^AS\d{1,10}$/.test(initial.asn) ? initial.asn : '';
        const pin = this.policy.pin(initial); this.country = pin.country;
        this.ipMemory.check(pin.ip);
        if (settings.mode === 'network') this.relay.pinIPFamily(net.isIP(pin.ip));
        const current = await this.requestIP(epoch, currentIP, port, this.relay.checkToken); if (!active()) return false;
        this.policy.check(current.ip); if (!active()) return false;
        await this.queryDestinations(epoch, port, this.relay.checkToken, true); if (!active()) return false;
        if (!await this.confirmNetworkProxy(epoch)) {
          if (active()) throw Error('Не удалось подтвердить настройки прокси Windows перед запуском.');
          return false;
        }
        const localPin = await this.refreshLocalAddresses(epoch, false); if (!active()) return false;
        if (this.usesLocalPin() && !localPin) throw Error('Локальный адрес выхода изменился во время проверки.');
        if (revision !== (this.revalidationRevision || 0) || interfaces !== networkFingerprint()) throw Error('Сеть изменилась во время начальной проверки IP.');
        if (!this.publishLocalAddresses(localPin)) throw Error('Локальный адрес изменился перед запуском.');
        // All probes and route checks must succeed before first-time persistence.
        // A failed write leaves Claude and application traffic closed.
        this.savedIP = this.ipMemory.commit(pin.ip);
        this.log('Исходный IP закреплён: [IP скрыт] · ' + pin.country);
        this.schedulePoll(epoch, settings.interval * 1000);
        void this.refreshDNSMetrics(epoch, port, this.relay.checkToken);
        return true;
      };
      if (settings.codeEnabled === true) {
        // Only Guard runs here. Its relay and monitor protect the download; no guest
        // is launched until the later WFP proof and fresh network confirmation.
        if (!await pinExit()) return;
        if (this.state !== 'rechecking') this.relay.unlock();
        try {
          this.status('Подготавливаем подтверждённый Claude Code и постоянную рабочую папку…');
          let asset;
          for (let attempt = 0; attempt < 3; attempt++) {
            if (this.state === 'rechecking' && !await this.confirmCodeLaunch(epoch, port, this.relay.checkToken)) return;
            const relay = this.relay, revision = this.revalidationRevision || 0, abort = new AbortController(); this.codeAssetAbort = abort;
            try {
              asset = await ensureNativeCodeAsset(this.root, port, { signal: abort.signal,
                active: () => active() && !!this.policy.pinned && this.relay === relay && relay.unlocked === true && !relay.closed && this.state !== 'rechecking' }, this.runtime?.version);
              break;
            } catch (error) {
              if (!active()) return;
              if (attempt === 2 || this.state !== 'rechecking' && revision === (this.revalidationRevision || 0)) throw error;
              // A pause destroys the partial download. Retry it only after a fresh
              // confirmation of the same pinned IP; integrity failures alone never retry.
              if (!await this.confirmCodeLaunch(epoch, port, this.relay.checkToken)) return;
            } finally { if (this.codeAssetAbort === abort) this.codeAssetAbort = null; }
          }
          if (!active()) return;
          const progress = { onProgress: value => { if (active()) this.preparationProgress(value); } };
          code = await prepareCodeFiles(this.runtime, settings.claudePath, this.root, this.resources, undefined, { nativeAssetPath: asset.path }, progress);
          if (active()) {
            this.codePrepared = code;
            const tools = await prepareCodeTools(this.root, this.resources, {
              gitArchive: path.join(this.resources, 'CodeTools', CODE_TOOLS_POLICY.git.archiveName),
              powerShellArchive: path.join(this.resources, 'CodeTools', CODE_TOOLS_POLICY.powershell.archiveName)
            }, undefined, progress);
            if (active()) {
              code.toolRoots = tools.toolRoots.slice();
              code.tools = Object.freeze({ environment: Object.freeze({ ...tools.environment }) });
              if (this.state !== 'rechecking') this.status('Готовим права постоянной рабочей папки Claude Code…');
              const stateStarted = performance.now();
              await this.prepareCodeState(code);
              if (active()) this.log('Постоянная рабочая папка Claude Code подготовлена · ' + Math.round(performance.now() - stateStarted) + ' мс.');
            }
          }
          if (!active()) { await this.cleanupCodeProfile(code); return; }
        } catch (error) {
          if (!active() && code) await this.cleanupCodeProfile(code);
          throw error;
        } finally { if (this.codePreparationEpoch === epoch) this.codePreparationPending = false; }
      }
      this.status('Устанавливаем сетевые ограничения Windows для копии Claude…');
      const codeConfig = code ? {
        hostPath: code.hostPath, stateRoot: code.stateRoot, workspaceRoot: code.workspaceRoot,
        runtimeExecutable: code.runtimeExecutable, containerName: code.containerName, containerSid: code.containerSid,
        tools: code.tools,
        approved: code.approved.map(item => ({ path: item.path, sha256: item.sha256, ...(item.requestedPath ? { requestedPath: item.requestedPath } : {}) })),
        relayURL: 'http://127.0.0.1:' + port, codeJobName: 'Global\\gate-code-job-' + randomBytes(16).toString('hex')
      } : null;
      this.fencePending = true;
      if (code) this.codeFenceRequested = true;
      let fence;
      try { fence = await NetworkFence.prepare(this.runtime, port, {
        helperPath: path.join(this.resources, 'NetworkFence.exe'),
        ownerWindow: this.fenceOwnerWindow?.(),
        ...(this.fenceServiceLaunch ? { serviceLaunch: this.fenceServiceLaunch } : {}),
        onStage: stage => {
          if (active() && this.state !== 'rechecking') {
            if (stage === 'approval') this.status(this.fenceServiceLaunch
              ? 'Проверяем системную службу Guard. При первой установке или обновлении службы Windows может запросить разрешение администратора.'
              : 'Подтвердите системный запрос Windows. До подтверждения защиты Claude не запускается.');
            else if (stage === 'installing') this.status('Windows разрешила запуск защиты. Устанавливаем сетевые ограничения…');
            else this.emit('state', this.snapshot());
          } else this.emit('state', this.snapshot());
        },
        ...(codeConfig ? { code: { containerName: codeConfig.containerName, containerSid: codeConfig.containerSid,
          codeJobName: codeConfig.codeJobName, relayExecutable: process.execPath } } : {})
      }); }
      finally { this.fencePending = false; }
      if (!active()) {
        try { await fence.close(); await this.cleanupCodeProfile(code); }
        catch { this.shutdownFailed = true; this.log('Ограничения Windows и профиль Code сохранены: завершение защищённой сессии не подтверждено.', 'warning'); }
        return;
      }
      this.fence = fence;
      if (codeConfig && !this.validCodeFence(fence, codeConfig)) throw Error('Windows не подтвердила сетевую изоляцию Claude Code.');
      fence.on('fatal', () => { if (active()) this.block('Сетевая защита Windows потеряна. Сессия закрыта.'); });
      // Chat keeps its original ordering: WFP is installed before its first IP check.
      if (!codeConfig && !await pinExit()) return;
      if (codeConfig) {
        const gate = new CodeGate(codeConfig, () => {
          if (!active() || gate.closed || this.codeGate !== gate || this.codePrepared !== code || !this.policy.pinned ||
              !['starting', 'running'].includes(this.state) || this.relay?.unlocked !== true || this.relay.closed ||
              !this.validCodeFence(this.fence, codeConfig) || !Number.isSafeInteger(this.runtimePID) || this.runtimePID <= 0 ||
              !this.host || this.host.killed || this.host.exitCode != null || this.host.signalCode != null) return null;
          return { runtimePID: this.runtimePID };
        });
        this.codeGate = gate;
        await gate.listen(); if (!active()) return;
        codeConfig.gatePipe = gate.pipe; codeConfig.gateToken = gate.token;
      }
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
      if (codeConfig && !await this.confirmCodeLaunch(epoch, port, this.relay.checkToken)) return;
      if (!active()) return;
      if (codeConfig && !this.validCodeFence(this.fence, codeConfig)) throw Error('Сетевая защита Claude Code потеряна до запуска.');
      if (this.state !== 'rechecking') { this.state = 'starting'; this.status('Запускаем Claude и проверяем профиль страницы…'); }
      if (!active()) return;
      const env = { ...process.env };
      for (const key of Object.keys(env)) if (/^(?:https?|all|no)_proxy$/i.test(key) || /^ELECTRON_/i.test(key) || /^NODE_OPTIONS$/i.test(key) || /^CLAUDE_/i.test(key)) delete env[key];
      Object.assign(env, { TZ: settings.timezone, LANG: settings.language.replaceAll('-', '_') + '.UTF-8', LC_ALL: settings.language.replaceAll('-', '_') + '.UTF-8',
        LANGUAGE: settings.language, LC_MESSAGES: settings.language.replaceAll('-', '_') + '.UTF-8',
        ...(codeConfig ? { CLAUDE_CONFIG_DIR: path.join(code.stateRoot, '.claude') } : {}),
        PROXY_GUARD_CONFIG: JSON.stringify({ userData: this.runtime.profile, timezone: settings.timezone, language: settings.language,
          proxyURL: 'http://127.0.0.1:' + port, channelPipe: this.channel.path, channelToken: this.channel.token,
          ...(codeConfig ? { code: codeConfig } : {}) }) });
      this.host = spawn(path.join(this.resources, 'GuardHost.exe'), [this.runtime.executable, '--user-data-dir=' + this.runtime.profile, '--lang=' + settings.language], { env, stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true });
      let output = '';
      const host = this.host;
      host.stdout.on('data', chunk => {
        output = (output + chunk).slice(-8192); let end;
        while ((end = output.indexOf('\n')) >= 0) {
          const line = output.slice(0, end); output = output.slice(end + 1);
          try {
            const message = JSON.parse(line);
            if (this.resolveHostCommand(message)) continue;
            if (this.host === host && message.pid) this.runtimePID = message.pid;
            if (this.host === host && message.exitCode != null) this.exitCode = message.exitCode;
          } catch {}
        }
      });
      host.once('error', () => { this.rejectHostCommands(host); if (active()) this.block('Не удалось запустить Windows Job Object helper.'); });
      host.once('exit', code => {
        this.rejectHostCommands(host);
        if (active() && this.freezeClosing?.host !== host) this.block('Claude завершился. Код: ' + (this.exitCode ?? code ?? 'неизвестен') + '.');
      });
      this.host.stdin.on('error', () => {});
      const heartbeat = () => { if (this.host && !this.host.stdin.destroyed) this.host.stdin.write('ping\n'); };
      heartbeat(); this.heartbeatTimer = setInterval(heartbeat, 1000);
      await this.channel.connected(); if (!active()) return;
      await this.inspector.start(); if (!active()) return;
      this.deepLinkReady = true; await this.deepLinks.flush(); if (!active()) return;
      this.log('Локальная копия Claude запущена: ' + settings.timezone + ' · ' + settings.language);
    } catch (error) {
      if (this.codePreparationEpoch === epoch) this.codePreparationPending = false;
      if (this.epoch === epoch) this.block(error.message || 'Ошибка запуска.');
    } finally { if (this.codePreparationEpoch === epoch) this.codePreparationPending = false; }
  }
  async confirmCodeLaunch(epoch, port, token) {
    const active = () => this.epoch === epoch && !this.policy.blocked && this.relay && !this.relay.closed;
    // A result begun before a slow UAC prompt is not the final launch check.
    // Retry a stable-IP route/interface transition instead of treating it as an IP change.
    for (let attempt = 0; attempt < 3; attempt++) {
      clearTimeout(this.pollTimer);
      if (this.checkTask) await this.checkTask.promise;
      clearTimeout(this.pollTimer);
      if (!active()) return false;
      this.beginLocalRevalidation();
      const revision = this.revalidationRevision || 0, interfaces = networkFingerprint();
      let beforeRoute, afterRoute, beforeRouteFailed = false;
      try {
        beforeRoute = await this.routeFingerprint();
      } catch {
        if (!active()) return false;
        beforeRouteFailed = true;
        this.pauseForRevalidation('Не удалось проверить маршрут перед запуском Claude Code. Повторяем проверку.');
      }
      if (!active()) return false;
      // A failed route read forbids launch, but must not hide a confirmed new exit.
      const checked = await Promise.allSettled([
        this.checkCurrentIP(epoch, port, token), this.queryDestinations(epoch, port, token), this.confirmNetworkProxy(epoch)
      ]);
      if (!active()) return false;
      if (checked.some(result => result.status !== 'fulfilled' || !result.value)) {
        if (!active()) return false;
        this.pauseForRevalidation('Не удалось подтвердить сеть перед запуском Claude Code. Повторяем проверку.');
        continue;
      }
      if (beforeRouteFailed) continue;
      try { afterRoute = await this.routeFingerprint(); } catch {
        if (!active()) return false;
        this.pauseForRevalidation('Не удалось проверить маршрут перед запуском Claude Code. Повторяем проверку.');
        continue;
      }
      if (!active()) return false;
      if (!await this.confirmNetworkProxy(epoch)) continue;
      if (!active()) return false;
      const afterInterfaces = networkFingerprint();
      if (revision !== (this.revalidationRevision || 0) || interfaces !== afterInterfaces || beforeRoute !== afterRoute) {
        this.pauseForRevalidation('Во время подготовки изменилась сеть. Проверяем закреплённый IP повторно.');
        continue;
      }
      const localPin = await this.refreshLocalAddresses(epoch, false); if (!active()) return false;
      if (this.usesLocalPin() && !localPin) continue;
      if (revision !== (this.revalidationRevision || 0) || interfaces !== networkFingerprint()) {
        this.pauseForRevalidation('Во время закрепления изменилась сеть. Повторяем проверку.');
        continue;
      }
      if (!this.publishLocalAddresses(localPin)) continue;
      this.route = afterRoute; this.fingerprint = afterInterfaces;
      if (!await this.resumeValidatedSession(epoch, revision)) return false;
      if (this.state === 'rechecking') this.state = 'checking';
      this.schedulePoll(epoch, this.settings.interval * 1000);
      return true;
    }
    throw Error('Не удалось подтвердить стабильную сеть перед запуском Claude Code. Соединение закрыто.');
  }
  validCodeFence(fence, config) {
    return fence?.installed === true && !fence.closed && !fence.closing && !!fence.socket && fence.socket.destroyed === false &&
      fence.codeProof?.sid === config.containerSid && fence.codeProof?.jobName === config.codeJobName && fence.codeProof?.filters === 10;
  }
  cleanupCodeProfile(code) {
    if (!code || typeof code.cleanupProfile !== 'function') return Promise.resolve();
    const preparation = this.codeStatePreparations.get(code);
    if (preparation && !preparation.closed) {
      // Do not delete a profile while an unconfirmed helper may still be applying ACLs.
      // A late close retries cleanup without keeping cancellation pending indefinitely.
      if (!preparation.cleanupRequested) this.log('Профиль AppContainer Code сохранён до подтверждения остановки подготовки. Рабочая папка сохранена.', 'warning');
      preparation.cleanupRequested = true;
      return Promise.resolve();
    }
    if (!this.codeCleanups.has(code)) {
      const cleanup = Promise.resolve().then(() => code.cleanupProfile()).catch(() => {
        this.shutdownFailed = true;
        this.log('Не удалось удалить временный профиль AppContainer Code. Рабочая папка сохранена.', 'warning');
      });
      this.codeCleanups.set(code, cleanup);
    }
    return this.codeCleanups.get(code);
  }
  prepareCodeState(code) {
    if (!code || !Array.isArray(code.approved) || code.approved.length !== 1) return Promise.reject(Error('Не подтверждён исполняемый файл Claude Code.'));
    const body = Buffer.from(JSON.stringify({ version: 1, containerName: code.containerName, containerSid: code.containerSid,
      stateRoot: code.stateRoot, executable: code.approved[0].path, executableSHA256: code.approved[0].sha256,
      runtimeExecutable: code.runtimeExecutable, toolRoots: Array.isArray(code.toolRoots) ? code.toolRoots.slice() : [] }));
    if (!body.length || body.length > 16384) return Promise.reject(Error('Неверная конфигурация состояния Claude Code.'));
    const header = Buffer.alloc(4); header.writeUInt32LE(body.length);
    const child = spawn(code.hostPath, ['--prepare-state'], { cwd: code.stateRoot, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    const preparation = { closed: false, cleanupRequested: false };
    preparation.closedTask = new Promise(resolve => { preparation.confirmClosed = resolve; });
    this.track(preparation.closedTask);
    this.codeStatePreparations.set(code, preparation); this.codeStateHost = child;
    return new Promise((resolve, reject) => {
      let stdout = Buffer.alloc(0), failure, settled = false, killTimer;
      const finish = error => {
        if (settled) return;
        settled = true; clearTimeout(timer); clearTimeout(killTimer);
        if (this.codeStateHost === child) this.codeStateHost = null;
        if (this.cancelCodeState === fail) this.cancelCodeState = null;
        if (error) reject(error); else resolve();
      };
      const fail = () => {
        if (settled || failure) return;
        failure = Error('Не удалось безопасно подготовить постоянное состояние Claude Code.');
        // kill() is a request, not proof of exit. Bound cancellation even if no close arrives.
        killTimer = setTimeout(() => finish(failure), 1000);
        try { child.kill(); } catch { /* Preserve the profile until a late close proves exit. */ }
      };
      this.cancelCodeState = fail;
      const timer = setTimeout(fail, 60000);
      child.stdout.on('data', chunk => {
        if (settled || failure) return;
        if (stdout.length + chunk.length > 8192) { fail(); return; }
        stdout = Buffer.concat([stdout, chunk]);
      });
      child.stderr.resume();
      child.on('error', fail); child.stdin.on('error', fail);
      child.once('close', status => {
        preparation.closed = true; preparation.confirmClosed();
        if (preparation.cleanupRequested) void this.track(this.cleanupCodeProfile(code)).catch(() => {});
        if (settled) return;
        if (failure || status !== 0) { finish(failure || Error('Не удалось безопасно подготовить постоянное состояние Claude Code.')); return; }
        try {
          const result = JSON.parse(stdout.toString('utf8').replace(/^\uFEFF/, '').trim());
          if (result.prepared !== true || result.name !== code.containerName || result.sid !== code.containerSid ||
              !Number.isSafeInteger(result.entries) || result.entries < 0 || result.entries > 100000) throw Error();
          finish();
        } catch { finish(Error('CodeHost не подтвердил подготовку постоянного состояния.')); }
      });
      try { child.stdin.end(Buffer.concat([header, body])); } catch { fail(); }
    });
  }
  async localEgressAddresses() {
    const pin = capturedEgressLocalAddresses();
    if (!pin.v4 && !pin.v6) throw Error('Не удалось определить локальные адреса выхода Windows. Соединение закрыто.');
    return pin;
  }
  usesLocalPin() {
    return this.settings?.mode === 'network' && this.networkProxy?.kind === 'direct';
  }
  beginLocalRevalidation() {
    this.relay?.pause();
    setPinnedLocalAddresses(null);
    beginEgressCapture();
  }

  async refreshLocalAddresses(epoch, publish = true) {
    if (!this.usesLocalPin()) return;
    const captured = JSON.stringify(capturedEgressLocalAddresses());
    let pin;
    try { pin = await this.localEgressAddresses(); }
    catch (error) { if (this.epoch === epoch) this.block(error.message); throw error; }
    if (this.epoch === epoch && !this.policy.blocked) {
      if (captured !== JSON.stringify(capturedEgressLocalAddresses())) {
        this.pauseForRevalidation('Во время закрепления изменился локальный адрес выхода. Повторяем проверку.');
        return;
      }
      this.localCaptureSignature = captured;
      if (publish && !this.publishLocalAddresses(pin)) return;
      return pin;
    }
  }
  publishLocalAddresses(pin) {
    if (!pin) return true;
    if (this.localCaptureSignature !== JSON.stringify(capturedEgressLocalAddresses())) {
      this.pauseForRevalidation('Локальный адрес изменился перед возобновлением. Повторяем проверку.');
      return false;
    }
    setPinnedLocalAddresses(pin);
    return true;
  }
  networkProxyConfiguration() { return readSystemProxy(); }
  async confirmNetworkProxy(epoch) {
    const active = () => this.epoch === epoch && !this.policy.blocked && !!this.relay;
    if (!active()) return false;
    if (this.settings?.mode !== 'network') return true;
    let current; const started = performance.now();
    try { current = await this.networkProxyConfiguration(); }
    catch (error) {
      if (active()) { this.reportProbeFailure('proxy', error, performance.now() - started); this.block('Не удалось подтвердить настройки прокси Windows. Сессия закрыта.'); }
      return false;
    }
    if (!active()) return false;
    if (!this.networkProxy || current.fingerprint !== this.networkProxy.fingerprint) {
      this.block('Настройки системного прокси изменились. Сессия закрыта до перезапуска Guard.');
      return false;
    }
    return true;
  }
  async requestDestinationIP(epoch, hostname, port, token) {
    while (this.destinationRequests.has(hostname)) {
      try { await this.destinationRequests.get(hostname); } catch {}
      if (this.epoch !== epoch) throw Error('Проверка отменена.');
    }
    if (this.epoch !== epoch) throw Error('Проверка отменена.');
    const started = performance.now();
    const request = Promise.resolve().then(() => queryDestinationIP(port, token, hostname, net.isIP(this.policy.pinned || '')));
    this.destinationRequests.set(hostname, request);
    try { return await request; }
    catch (error) {
      if (this.epoch === epoch && !this.policy.blocked && this.relay) this.reportProbeFailure(hostname, error, performance.now() - started);
      throw error;
    }
    finally { if (this.destinationRequests.get(hostname) === request) this.destinationRequests.delete(hostname); }
  }
  async queryDestinations(epoch, port, token, pin = false) {
    const active = () => this.epoch === epoch && !this.policy.blocked && !!this.relay;
    const results = await Promise.allSettled(DESTINATIONS.map(async hostname => {
      const started = performance.now();
      try {
        const result = await this.requestDestinationIP(epoch, hostname, port, token);
        if (!active()) return false;
        const ip = canonicalIP(result?.ip);
        if (result?.hostname !== hostname) throw Error('Invalid destination response');
        const policy = new IPPolicy();
        try { policy.pin(result); }
        catch {
          if (String(result.country_code || '').toUpperCase() === 'RU') this.block('Маршрут Claude вышел через RU. Сессия закрыта до перезапуска Guard.');
          throw Error('Invalid destination country');
        }
        if (ip !== this.policy.pinned) return this.hostedIPMismatch('Внешний IP маршрута Claude изменился. ' + MISMATCH);
        if (pin) this.destinationPolicies.set(hostname, policy);
        else {
          const pinned = this.destinationPolicies.get(hostname);
          if (!pinned) throw Error('Destination is not pinned');
          if (pinned.pinned !== ip) return this.hostedIPMismatch('Внешний IP маршрута Claude изменился.');
          pinned.check(ip);
        }
        this.networkMetrics.destinations[hostname] = { state: 'ok', latencyMs: Math.max(0, Math.min(600000, Math.round(performance.now() - started))) };
        return true;
      } catch {
        if (active()) {
          this.networkMetrics.destinations[hostname] = { state: 'error', latencyMs: Math.max(0, Math.min(600000, Math.round(performance.now() - started))) };
          this.pauseForRevalidation('Не удалось подтвердить маршрут Claude. Повторяем проверку.', false);
        }
        throw Error('Не удалось подтвердить маршрут Claude.');
      }
    }));
    if (!active()) return false;
    if (results.some(result => result.status !== 'fulfilled' || !result.value)) throw Error('Не удалось подтвердить маршрут Claude.');
    return true;
  }
  refreshDNSMetrics(epoch, port, token) {
    if (this.dnsMetricsTask) return this.dnsMetricsTask;
    this.networkMetrics.dns = { state: 'checking' };
    const task = (async () => {
      try {
        if (typeof this.dnsProbe !== 'function') throw Error('DNS metric unavailable');
        const value = await this.dnsProbe(port, token);
        if (this.epoch !== epoch || this.policy.blocked) return;
        if (!net.isIP(value?.ip) || typeof value.geo !== 'string' || !value.geo.length || value.geo.length > 160 || /[\x00-\x1f\x7f]/.test(value.geo)) throw Error('Invalid DNS metric');
        this.networkMetrics.dns = { state: 'ready', ip: value.ip, organization: value.geo };
      } catch {
        if (this.epoch === epoch && !this.policy.blocked) this.networkMetrics.dns = { state: 'unavailable' };
      }
    })();
    this.dnsMetricsTask = task;
    return task.finally(() => {
      if (this.dnsMetricsTask === task) this.dnsMetricsTask = null;
      if (this.epoch === epoch) this.emit('state', this.snapshot());
    });
  }
  async checkCurrentIP(epoch, port, token) {
    const active = () => this.epoch === epoch && !this.policy.blocked && !!this.relay;
    try {
      const result = await this.requestIP(epoch, currentIP, port, token);
      if (!active()) return null;
      const ip = canonicalIP(result?.ip);
      if (net.isIP(ip) !== net.isIP(this.policy.pinned)) throw Error('Unexpected IP family');
      if (ip !== this.policy.pinned) {
        this.hostedIPMismatch('Внешний IP изменился. ' + MISMATCH);
        return null;
      }
      this.policy.check(ip); return ip;
    } catch {
      if (active()) this.pauseForRevalidation('Не удалось подтвердить закреплённый IP. Повторяем проверку.', false);
      throw Error('Не удалось подтвердить закреплённый IP.');
    }
  }
  async routeFingerprint() {
    if (process.platform !== 'win32') return '';
    const epoch = this.epoch;
    try {
      const route = await readRouteFingerprint(path.join(this.resources, 'GuardHost.exe'));
      if (this.epoch === epoch) this.routeErrorCode = null;
      return route;
    } catch (error) {
      const failure = error instanceof RouteReadError ? error : new RouteReadError('EXIT_NONZERO');
      if (this.epoch === epoch && this.routeErrorCode !== failure.code) {
        this.routeErrorCode = failure.code;
        this.log('Проверка маршрутов Windows: ' + failure.code + '.', 'warning');
      }
      throw failure;
    }
  }
  async requestIP(epoch, check, port, token) {
    // A cancelled request may still be settling; never overlap it with a new one.
    while (this.ipRequest) {
      try { await this.ipRequest; } catch {}
      if (this.epoch !== epoch) throw Error('Проверка отменена.');
    }
    if (this.epoch !== epoch) throw Error('Проверка отменена.');
    const started = performance.now();
    const request = Promise.resolve().then(() => check(port, token, require('node:net').isIP(this.policy.pinned || this.savedIP || ''))); this.ipRequest = request;
    try { return await request; }
    catch (error) {
      if (this.epoch === epoch && !this.policy.blocked && this.relay) this.reportProbeFailure(check === initialIP ? 'geo' : 'public', error, performance.now() - started);
      throw error;
    }
    finally { if (this.ipRequest === request) this.ipRequest = null; }
  }
  routinePollDelay(elapsed) { return Math.max(FREEZE_RETRY_MS, this.settings.interval * 1000 - elapsed); }
  schedulePoll(epoch, delay) {
    clearTimeout(this.pollTimer);
    if (this.epoch !== epoch || this.policy.blocked || !this.relay || this.freezeClosing) return;
    this.pollTimer = setTimeout(() => this.poll(epoch), Math.max(0, delay));
  }
  pauseForRevalidation(reason, invalidate = true) {
    if (!this.relay || !this.policy.pinned || this.policy.blocked || this.freezeClosing || ['idle', 'blocked'].includes(this.state)) return false;
    const now = performance.now();
    if (this.recheckingSince !== null && now - this.recheckingSince >= FREEZE_LIMIT_MS) {
      this.block('Проверка сети не завершилась за 20 секунд. Сессия остановлена.'); return true;
    }
    this.recheckingSince ??= now;
    if (invalidate) this.revalidationRevision = (this.revalidationRevision || 0) + 1;
    this.relay.pause();
    setPinnedLocalAddresses(null);
    if (this.state !== 'rechecking') this.log(reason, 'warning');
    this.state = 'rechecking';
    const frozen = this.requestProcessFreeze();
    this.status(reason + (frozen ? ' Процессы Claude приостанавливаются на время проверки.' : ' Трафик приостановлен до подтверждения прежнего IP.'));
    return true;
  }
  revalidate(reason = 'Повторная проверка закреплённого IP.') {
    if (!this.pauseForRevalidation(reason)) return Promise.resolve();
    clearTimeout(this.pollTimer);
    return this.poll(this.epoch);
  }
  poll(epoch) {
    if (this.epoch !== epoch || this.policy.blocked || !this.relay || this.freezeClosing) return Promise.resolve();
    if (this.checkTask) {
      const task = this.checkTask;
      return task.epoch === epoch ? task.promise : task.promise.then(() => this.poll(epoch));
    }
    clearTimeout(this.pollTimer);
    const task = { epoch, revision: this.revalidationRevision || 0, started: performance.now() };
    const rechecking = this.state === 'rechecking';
    const active = () => this.epoch === epoch && !this.policy.blocked && this.relay;
    const before = networkFingerprint(), relayPort = this.relay.port, checkToken = this.relay.checkToken;
    task.promise = (async () => {
      // Reopening traffic requires an IP sample taken between two stable route
      // snapshots. A concurrent route result may belong to a newer route than
      // the IP request, even when no interface event increments the revision.
      let beforeRoute, beforeRouteFailed = false;
      if (rechecking) {
        this.beginLocalRevalidation();
        try { beforeRoute = await this.routeFingerprint(); }
        catch {
          if (active()) this.pauseForRevalidation('Не удалось проверить маршрут сети. Повторяем проверку.', false);
          beforeRouteFailed = true;
        }
        if (!active()) return;
      }
      // Validate an IP result immediately; a slow route query cannot delay the protective response.
      const address = this.checkCurrentIP(epoch, relayPort, checkToken);
      const destinations = this.queryDestinations(epoch, relayPort, checkToken);
      const proxy = this.confirmNetworkProxy(epoch);
      const confirmation = Promise.allSettled([address, destinations, proxy]).then(results => results.every(result => result.status === 'fulfilled' && result.value));
      const routes = (rechecking
        ? confirmation.then(valid => active() && valid && !beforeRouteFailed ? this.routeFingerprint() : null)
        : Promise.resolve().then(() => this.routeFingerprint())).then(route => {
        if (active() && route !== this.route && this.state !== 'rechecking') {
          this.pauseForRevalidation('Изменился маршрут сети. Проверяем закреплённый IP.');
        }
        return route;
      }).catch(error => {
        if (active()) this.pauseForRevalidation('Не удалось проверить маршрут сети. Повторяем проверку.', false);
        throw error;
      });
      const [ip, route, destinationResult, proxyResult] = await Promise.allSettled([address, routes, destinations, proxy]);
      if (!active()) return;
      if (beforeRouteFailed || ip.status !== 'fulfilled' || !ip.value || route.status !== 'fulfilled' ||
          destinationResult.status !== 'fulfilled' || !destinationResult.value || proxyResult.status !== 'fulfilled' || !proxyResult.value) {
        this.pauseForRevalidation('Не удалось подтвердить закреплённый IP или маршрут. Повторяем проверку.', false);
        return;
      }
      if (rechecking && !await this.confirmNetworkProxy(epoch)) return;
      if (!active()) return;
      const localPin = rechecking ? await this.refreshLocalAddresses(epoch, false) : null; if (!active()) return;
      if (rechecking && this.usesLocalPin() && !localPin) return;
      const after = networkFingerprint();
      if (before !== after) {
        this.fingerprint = after;
        this.pauseForRevalidation('Во время проверки изменились сетевые интерфейсы. Проверяем IP повторно.');
        return;
      }
      // An event arriving during the request requires a fresh answer after that event.
      if (task.revision !== (this.revalidationRevision || 0)) return;
      if (rechecking && beforeRoute !== route.value) {
        this.pauseForRevalidation('Во время проверки изменился маршрут сети. Проверяем IP повторно.');
        return;
      }
      if (route.value !== this.route && this.state !== 'rechecking') {
        this.pauseForRevalidation('Изменился маршрут сети. Проверяем закреплённый IP.');
        return;
      }
      if (!this.publishLocalAddresses(localPin)) return;
      if (this.state === 'rechecking') {
        this.route = route.value; this.fingerprint = after;
        if (!await this.resumeValidatedSession(epoch, task.revision)) return;
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
      const changed = task.revision !== (this.revalidationRevision || 0), elapsed = performance.now() - task.started;
      if (rechecking || changed || this.state === 'rechecking') this.diagnostics.event('revalidation_poll', {
        epoch, revision: task.revision, currentRevision: this.revalidationRevision || 0, changed, elapsedMS: elapsed,
        state: this.state, processState: this.processState, recheckingMS: this.recheckingSince === null ? null : performance.now() - this.recheckingSince
      });
      this.schedulePoll(epoch, this.processFrozen ? Math.max(0, FREEZE_RETRY_MS - elapsed) : changed ? FREEZE_RETRY_MS : this.routinePollDelay(elapsed));
    });
    this.checkTask = task; return task.promise;
  }
  teardown() {
    setPinnedLocalAddresses(null);
    this.codeGate?.close(); this.codeGate = null;
    this.codeAssetAbort?.abort(); this.codeAssetAbort = null;
    this.cancelCodeState?.();
    this.deepLinkReady = false; this.deepLinks.clear();
    this.recheckingSince = null; this.epoch++;
    if (this.networkMetrics?.dns?.state === 'checking') this.networkMetrics.dns = { state: 'idle' };
    this.dnsMetricsTask = null;
    clearInterval(this.networkTimer); clearInterval(this.heartbeatTimer); clearTimeout(this.pollTimer);
    this.clearProcessFreeze(); this.rejectHostCommands(); this.freezeTask = null;
    this.inspector?.stop(); this.channel?.close(); this.relay?.close();
    // EOF makes GuardHost close its job. Force-terminating the helper also closes its job handle.
    const host = this.host, fence = this.fence, code = this.codePrepared;
    const unusedCode = !this.codePreparationPending && !this.codeFenceRequested;
    this.host = null; this.fence = null; this.codePrepared = null; this.runtimePID = null;
    const closeFence = async () => {
      if (fence) {
        try { await fence.close(); await this.cleanupCodeProfile(code); }
        catch { this.shutdownFailed = true; this.log('Ограничения Windows и профиль Code сохранены: завершение защищённой копии не подтверждено.', 'warning'); }
      } else if (unusedCode) await this.cleanupCodeProfile(code);
    };
    const drain = () => { this.track(closeFence()).catch(() => { this.shutdownFailed = true; }); };
    if (host) {
      try { host.stdin.end(); } catch {}
      const timer = setTimeout(() => host.kill(), 1000); timer.unref();
      const exited = new Promise(resolve => {
        if (host.exitCode != null || host.signalCode != null) { clearTimeout(timer); resolve(); }
        else host.once('exit', () => { clearTimeout(timer); resolve(); });
      });
      this.track(exited.then(drain));
    } else drain();
    this.inspector = null; this.channel = null; this.relay = null;
    if (this.settings) this.settings.password = ''; this.settings = null; this.verified = null; this.exitCode = null;
  }
  block(reason) {
    if (this.state === 'blocked') return;
    this.diagnostics.event('block', { epoch: this.epoch, previousState: this.state, processState: this.processState,
      processFrozen: this.processFrozen, runtimePID: this.runtimePID || null, hostLive: this.liveHost(),
      relayOpen: Boolean(this.relay && !this.relay.closed), relayUnlocked: this.relay?.unlocked === true,
      fenceInstalled: this.fence?.installed === true, reason });
    this.policy.block(); this.teardown(); this.state = 'blocked';
    this.log(reason, 'blocked'); this.status(reason);
  }
  stop() {
    const blocked = this.policy.blocked;
    // Pinning a second exit in the same Guard process is forbidden even after a manual stop.
    const hadSession = this.policy.pinned != null || this.fencePending || Boolean(this.fence) || this.codePreparationPending || Boolean(this.codePrepared);
    if (hadSession) this.policy.block(); this.teardown();
    this.state = blocked || hadSession ? 'blocked' : 'idle';
    this.status(this.state === 'blocked' ? 'Сессия закрыта. Для нового подключения перезапустите Guard.' : 'Остановлено.');
  }
  async quiesce() {
    if (NetworkFence.approvalPending) return false;
    this.stop();
    if (this.startTask) { try { await this.startTask; } catch {} }
    while (this.pendingOperations.size) {
      const operations = [...this.pendingOperations];
      await Promise.allSettled(operations);
      if (NetworkFence.approvalPending) return false;
    }
    return !this.shutdownFailed && !NetworkFence.approvalPending && !this.fencePending && !this.codePreparationPending && !this.codeStateHost && !this.host;
  }
}
module.exports = { GuardController };
