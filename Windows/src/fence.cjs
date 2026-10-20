'use strict';
const fs = require('./raw-fs.cjs').promises;
const path = require('node:path');
const net = require('node:net');
const { EventEmitter, once } = require('node:events');
const { randomBytes } = require('node:crypto');
const { powershell, psQuote } = require('./windows.cjs');

const COVERAGE = 'private-runtime-executables';
const MAX_EXECUTABLES = 512;

async function assertNoLinks(file) {
  let cursor = file;
  while (cursor && path.dirname(cursor) !== cursor) {
    const info = await fs.lstat(cursor);
    if (info.isSymbolicLink()) throw Error('Сетевая защита не принимает ссылки в папке копии Claude.');
    cursor = path.dirname(cursor);
  }
}

async function collectExecutables(runtime) {
  if (!runtime?.executable || !path.isAbsolute(runtime.executable) || path.basename(runtime.executable).toLowerCase() !== 'claude.exe') throw Error('Не задана отдельная копия Claude для сетевой защиты.');
  const executable = path.resolve(runtime.executable), root = path.dirname(executable);
  if (!/^Runtime-[a-f0-9]{24}$/.test(path.basename(root))) throw Error('Сетевая защита разрешена только для отдельной копии Guard.');
  await assertNoLinks(root);
  await fs.access(path.join(root, 'guard-manifest.json'));
  const files = [];
  async function walk(directory) {
    for (const item of await fs.readdir(directory, { withFileTypes: true })) {
      const file = path.join(directory, item.name), info = await fs.lstat(file);
      if (info.isSymbolicLink()) throw Error('В папке копии Claude обнаружена ссылка. Запуск остановлен.');
      if (info.isDirectory()) await walk(file);
      else if (/\.exe$/i.test(item.name)) {
        if (!info.isFile() || info.size < 16 || info.nlink !== 1 || files.length >= MAX_EXECUTABLES) throw Error('Не удалось проверить исполняемые файлы копии Claude.');
        const canonical = await fs.realpath(file);
        if (canonical.toLowerCase() !== path.resolve(file).toLowerCase()) throw Error('Путь исполняемого файла изменился при проверке.');
        files.push(canonical);
      }
    }
  }
  await walk(root);
  files.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase(), 'en'));
  if (!files.some(file => file.toLowerCase() === executable.toLowerCase())) throw Error('Копия Claude не найдена при настройке сетевой защиты.');
  return { root, files };
}

function installRequest(root, files, relayPort) {
  if (!Number.isInteger(relayPort) || relayPort < 1 || relayPort > 65535) throw Error('Неверный порт защищённого шлюза.');
  if (!files.length || files.length > MAX_EXECUTABLES || [root, ...files].some(value => /[\0\r\n\t]/.test(value))) throw Error('Неверный список исполняемых файлов.');
  return ['install', Buffer.from(root).toString('base64'), String(relayPort), Buffer.from(files.join('\n')).toString('base64')].join('\t') + '\n';
}

function safeError(message) {
  const code = Number.isInteger(message?.code) ? ` (${message.code})` : '';
  return Error('Windows не подтвердила установку сетевой защиты' + code + '. Claude не запущен.');
}

class NetworkFence extends EventEmitter {
  constructor() { super(); this.closed = false; this.closing = false; this.installed = false; }

  static async prepare(runtime, relayPort, options = {}) {
    if (process.platform !== 'win32') throw Error('Сетевая защита WFP доступна только в Windows.');
    const inventory = await collectExecutables(runtime);
    const request = installRequest(inventory.root, inventory.files, relayPort);
    const helper = options.helperPath || path.join(process.resourcesPath || path.resolve(__dirname, '..'), 'NetworkFence.exe');
    await fs.access(helper);
    const instance = new NetworkFence();
    instance.inventory = inventory; instance.relayPort = relayPort;
    const token = randomBytes(32).toString('hex');
    const name = 'gate-network-fence-' + randomBytes(16).toString('hex');
    const pipe = '\\\\.\\pipe\\' + name;
    const server = net.createServer(); instance.server = server;
    const ready = new Promise((resolve, reject) => {
      let authenticated = false, connected = false;
      const timeout = setTimeout(() => reject(Error('Windows не подтвердила сетевую защиту. Повторите запуск и подтвердите запрос UAC.')), options.timeout || 120000);
      const finish = (error, value) => { clearTimeout(timeout); if (error) reject(error); else resolve(value); };
      instance.once('prepare-error', error => finish(error));
      server.on('error', () => finish(Error('Не удалось открыть канал сетевой защиты.')));
      server.on('connection', socket => {
        if (connected) { socket.destroy(); return; }
        connected = true; instance.socket = socket;
        let buffer = '';
        socket.setEncoding('utf8');
        socket.on('data', chunk => {
          buffer += chunk;
          if (buffer.length > 16384) { socket.destroy(); return; }
          let end;
          while ((end = buffer.indexOf('\n')) >= 0) {
            const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
            let message; try { message = JSON.parse(line); } catch { socket.destroy(); return; }
            if (!authenticated) {
              if (message.type !== 'hello' || message.version !== 1 || message.token !== token) { socket.destroy(); return; }
              authenticated = true; socket.write(request); continue;
            }
            if (message.type === 'installed') {
              if (message.version !== 1 || message.coverage !== COVERAGE || message.paths !== inventory.files.length || message.filters !== inventory.files.length * 6 || message.persistent !== true) { finish(safeError()); socket.destroy(); return; }
              instance.installed = true;
              instance.proof = { coverage: COVERAGE, paths: message.paths, filters: message.filters, persistent: true };
              finish(null, instance);
            } else if (message.type === 'removed') instance.emit('removed', message.removed === true);
            else if (message.type === 'error') {
              if (!instance.installed) finish(safeError(message));
              else instance.emit('broker-error', safeError(message));
            } else { socket.destroy(); return; }
          }
        });
        const disconnected = () => {
          if (!instance.installed) finish(Error('Канал сетевой защиты закрылся до подтверждения. Claude не запущен.'));
          else if (!instance.closing && !instance.closed) instance.emit('fatal', 'Канал сетевой защиты прерван. Фильтры Windows оставлены включёнными.');
        };
        socket.on('error', () => {}); socket.once('close', disconnected);
      });
    });
    // Attach rejection handling before requesting UAC; cancellation can race the
    // named-pipe handshake. The runtime is never spawned from elevated code.
    ready.catch(() => {});
    try {
      server.listen(pipe); await once(server, 'listening');
      const script = "$p=Start-Process -FilePath " + psQuote(path.resolve(helper)) + " -Verb RunAs -ArgumentList @('--pipe'," + psQuote(name) + ",'--token'," + psQuote(token) + ") -WindowStyle Hidden -PassThru; $p.Id";
      const launch = options.launch || (value => powershell(value, options.timeout || 120000));
      Promise.resolve(launch(script)).catch(() => instance.emit('prepare-error', Error('Не удалось включить сетевую защиту Windows. Подтвердите запрос UAC.')));
      return await ready;
    } catch (error) { instance.abandon(); throw error; }
  }

  async close() {
    if (this.closed) return;
    if (!this.installed || !this.socket || this.socket.destroyed) { this.abandon(); throw Error('Фильтры Windows оставлены включёнными: нет подтверждённого канала удаления.'); }
    this.closing = true;
    try {
      const removed = await new Promise((resolve, reject) => {
        const cleanup = () => { clearTimeout(timer); this.off('removed', accepted); this.off('broker-error', failed); this.socket.off('close', disconnected); };
        const accepted = value => { cleanup(); resolve(value); }, failed = error => { cleanup(); reject(error); };
        const disconnected = () => failed(Error('Фильтры Windows оставлены включёнными после потери канала.'));
        const timer = setTimeout(() => failed(Error('Фильтры Windows оставлены включёнными: истекло время проверки завершения Claude.')), 10000);
        this.once('removed', accepted); this.once('broker-error', failed); this.socket.once('close', disconnected);
        this.socket.write('remove-after-job-exit\n');
      });
      if (!removed) throw Error('Claude ещё работает или его завершение не подтверждено. Фильтры Windows оставлены включёнными.');
      this.installed = false;
    } finally { this.abandon(); }
  }

  abandon() {
    // EOF never requests filter removal. Persistent BLOCK survives this process.
    this.closed = true; this.socket?.destroy();
    try { this.server?.close(); } catch {}
  }
}

module.exports = { NetworkFence, collectExecutables, installRequest, COVERAGE };
