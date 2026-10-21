'use strict';
const { EventEmitter } = require('node:events');
const S = require('./sanitize.cjs');
const attachParameters = { autoAttach: true, waitForDebuggerOnStart: true, flatten: true,
  filter: [{ type: 'page' }, { type: 'iframe' }, { exclude: true }] };
const targetClosed = error => /target closed|session closed|session with given id not found|no session with given id|no target with given id|inspected target navigated or closed|object has been destroyed/i.test(error.message || error);
const expression = '({timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,language:navigator.language,locale:Intl.DateTimeFormat().resolvedOptions().locale,url:location.href})';

class Inspector extends EventEmitter {
  constructor(channel, profile, captureBodies) {
    super(); this.channel = channel; this.profile = profile; this.captureBodies = captureBodies;
    this.sessions = new Map(); this.records = new Map(); this.earlyHeaders = new Map(); this.running = true;
    channel.on('event', (method, params, sid) => this.event(method, params, sid));
    channel.on('fatal', reason => this.fatal(reason));
  }
  async start() {
    const version = await this.channel.command('Browser.getVersion'); this.userAgent = version.userAgent;
    if (!this.userAgent) throw Error('Claude не открыл диагностику.');
    this.deadline = setTimeout(() => this.fatal('За 25 секунд не подтверждены язык и таймзона Claude.'), 25000);
    await this.channel.command('Target.setAutoAttach', attachParameters);
  }
  fatal(reason) { if (this.running) { this.running = false; this.clearTimers(); this.emit('fatal', reason); } }
  clearTimers() { clearTimeout(this.deadline); for (const item of this.sessions.values()) clearTimeout(item.timer); }
  stop() { this.running = false; this.clearTimers(); this.sessions.clear(); }
  retire(sid) { const item = this.sessions.get(sid); if (item) clearTimeout(item.timer); this.sessions.delete(sid); }
  arm(sid, item) {
    clearTimeout(item.timer); item.verified = false;
    item.timer = setTimeout(() => {
      if (this.running && this.sessions.get(sid) === item && !item.verified) this.fatal('Не подтверждён профиль активной страницы Claude.');
    }, 25000);
  }
  async configure(sid) {
    if (this.sessions.has(sid) || !this.running) return;
    const item = { contexts: new Set() }; this.sessions.set(sid, item); this.arm(sid, item);
    const tasks = [
      ['Emulation.setTimezoneOverride', { timezoneId: this.profile.timezone }],
      ['Emulation.setLocaleOverride', { locale: this.profile.language.replaceAll('-', '_') }],
      ['Network.enable', { maxTotalBufferSize: 2097152, maxResourceBufferSize: 131072, maxPostDataSize: this.captureBodies ? 32768 : 0 }],
      ['Network.setUserAgentOverride', { userAgent: this.userAgent, acceptLanguage: this.profile.language }],
      ['Network.setExtraHTTPHeaders', { headers: { 'Accept-Language': this.profile.language } }],
      ['Runtime.enable', {}], ['Target.setAutoAttach', attachParameters], ['Runtime.runIfWaitingForDebugger', {}]
    ];
    for (const [method, params] of tasks) {
      if (!this.running || this.sessions.get(sid) !== item) return;
      try { await this.channel.command(method, params, sid); }
      catch (error) {
        if (!this.running || this.sessions.get(sid) !== item) return;
        if (targetClosed(error)) { this.retire(sid); return; }
        if (method === 'Emulation.setLocaleOverride' && error.message.includes('Another locale override is already in effect')) {
          this.emit('notice', 'Локаль общего renderer уже задана; проверяем фактический профиль.'); continue;
        }
        this.fatal('Ошибка настройки ' + method + ': ' + S.diagnostic(error.message)); return;
      }
    }
  }
  async verify(sid, item, id) {
    try {
      const response = await this.channel.command('Runtime.evaluate', { expression, contextId: id, returnByValue: true }, sid);
      if (!this.running || this.sessions.get(sid) !== item || !item.contexts.has(id)) return;
      const value = response.result?.value;
      const normalize = language => String(language || '').replaceAll('_', '-').toLowerCase();
      // These values come from our fixed expression in the actual default
      // renderer context, never from a request body or account preference.
      let mismatch;
      if (!value || response.exceptionDetails) mismatch = 'renderer.profile.unconfirmed';
      else if (!(value.timezone === this.profile.timezone ||
          (this.profile.timezone === 'Etc/UTC' && value.timezone === 'UTC'))) mismatch = 'renderer.Intl.timeZone';
      else if (normalize(value.language) !== normalize(this.profile.language)) mismatch = 'renderer.navigator.language';
      else if (normalize(value.locale) !== normalize(this.profile.language)) mismatch = 'renderer.Intl.locale';
      if (mismatch) { this.fatal('Проверка профиля не пройдена: ' + mismatch + '.'); return; }
      item.verified = true; clearTimeout(item.timer); clearTimeout(this.deadline);
      this.emit('verified', { sessionId: sid, timezone: value.timezone, language: value.language, locale: value.locale, url: S.safeURL(value.url) });
    } catch (error) {
      if (!this.running || this.sessions.get(sid) !== item || !item.contexts.has(id) || targetClosed(error) || /context/i.test(error.message)) return;
      this.fatal('Не удалось проверить профиль страницы Claude.');
    }
  }
  save(record) {
    if (!this.running) return;
    this.records.set(record.id, record);
    while (this.records.size > 200) this.records.delete(this.records.keys().next().value);
    this.emit('record', record);
    if (record.warnings?.length) this.fatal('Проверка профиля не пройдена: ' + record.warnings.join(', ') + '.');
  }
  append(key, base64) {
    const record = this.records.get(key); if (!record || !this.running) return;
    record.received = S.bounded(record.received + S.body(Buffer.from(base64, 'base64').toString('utf8'))); this.save(record);
  }
  event(method, p, sid) {
    if (!this.running) return;
    if (method === 'ProxyGuard.error') { this.fatal('Ошибка адаптера Claude: ' + S.diagnostic(p.message)); return; }
    if (method === 'ProxyGuard.notice') { this.emit('notice', S.diagnostic(p.message)); return; }
    if (method === 'Target.attachedToTarget') { this.configure(p.sessionId).catch(() => this.fatal('Ошибка подключения к странице.')); return; }
    if (method === 'Target.detachedFromTarget') { this.retire(p.sessionId); return; }
    const item = this.sessions.get(sid); if (!item) return;
    if (method === 'Runtime.executionContextsCleared') { item.contexts.clear(); this.arm(sid, item); return; }
    if (method === 'Runtime.executionContextDestroyed') { item.contexts.delete(p.executionContextId); return; }
    if (method === 'Runtime.executionContextCreated') {
      if (p.context?.auxData?.isDefault) { item.contexts.add(p.context.id); this.verify(sid, item, p.context.id); } return;
    }
    if (!p.requestId) return;
    const key = sid + ':' + p.requestId, record = this.records.get(key);
    const fresh = () => ({ id: key, date: new Date().toISOString(), method: '', url: '', kind: '', status: null,
      requestHeaders: '', responseHeaders: '', sent: '', received: '', note: '', warnings: [] });
    switch (method) {
      case 'Network.requestWillBeSentExtraInfo':
        if (record) {
          record.requestHeaders = S.headers(p.headers); record.warnings = [...new Set([...record.warnings, ...S.auditRequestHeaders(p.headers, this.profile.language)])]; this.save(record);
        } else {
          const warnings = S.auditRequestHeaders(p.headers, this.profile.language);
          if (warnings.length) { this.fatal('Проверка профиля не пройдена: ' + warnings.join(', ') + '.'); break; }
          this.earlyHeaders.set(key, p.headers); if (this.earlyHeaders.size > 200) this.earlyHeaders.delete(this.earlyHeaders.keys().next().value);
        }
        break;
      case 'Network.responseReceivedExtraInfo':
        if (record) { record.responseHeaders = S.headers(p.headers); record.status = p.statusCode || record.status; this.save(record); } break;
      case 'Network.requestWillBeSent': {
        const value = fresh(), request = p.request || {}, headers = this.earlyHeaders.get(key) || request.headers || {};
        this.earlyHeaders.delete(key);
        Object.assign(value, { method: request.method || '?', url: S.safeURL(request.url), kind: p.type || 'HTTP',
          requestHeaders: S.headers(headers), warnings: S.auditRequestHeaders(headers, this.profile.language),
          sent: this.captureBodies ? S.body(request.postData) : '[содержимое отключено]' }); this.save(value); break;
      }
      case 'Network.responseReceived':
        if (record) {
          Object.assign(record, { status: p.response?.status, responseHeaders: S.headers(p.response?.headers), note: p.response?.mimeType || '' }); this.save(record);
          if (this.captureBodies && record.note.includes('event-stream')) this.channel.command('Network.streamResourceContent', { requestId: p.requestId }, sid)
            .then(r => { if (r.bufferedData) this.append(key, r.bufferedData); }).catch(() => {});
        } break;
      case 'Network.dataReceived': if (this.captureBodies && p.data) this.append(key, p.data); break;
      case 'Network.eventSourceMessageReceived':
        if (this.captureBodies && record) { record.received = S.bounded(record.received + '\n' + S.body(p.data)); this.save(record); } break;
      case 'Network.loadingFinished':
        if (record && this.captureBodies && /json|text|javascript|xml/i.test(record.note)) {
          this.channel.command('Network.getResponseBody', { requestId: p.requestId }, sid).then(r => {
            if (!this.running || !this.records.has(key)) return;
            record.received = S.body(r.base64Encoded ? Buffer.from(r.body || '', 'base64').toString('utf8') : r.body); this.save(record);
          }).catch(() => { if (this.running && !record.received) { record.received = '[тело недоступно в диагностическом буфере]'; this.save(record); } });
        } break;
      case 'Network.loadingFailed': if (record) { record.note = S.bounded(p.errorText); this.save(record); } break;
      case 'Network.webSocketCreated': this.save({ ...fresh(), method: 'WS', kind: 'WebSocket', url: S.safeURL(p.url) }); break;
      case 'Network.webSocketWillSendHandshakeRequest':
        if (record) {
          record.requestHeaders = S.headers(p.request?.headers);
          record.warnings = [...new Set([...record.warnings, ...S.auditRequestHeaders(p.request?.headers, this.profile.language)])]; this.save(record);
        } break;
      case 'Network.webSocketFrameSent':
      case 'Network.webSocketFrameReceived':
        if (record && this.captureBodies && p.response?.opcode === 1) {
          const field = method.endsWith('Sent') ? 'sent' : 'received';
          record[field] = S.bounded(record[field] + '\n' + S.body(p.response.payloadData)); this.save(record);
        } break;
    }
  }
}
module.exports = { Inspector, expression, attachParameters };
