'use strict';
const crypto = require('node:crypto');
const path = require('node:path');
const { runtimeDeepLinkSource } = require('./deep-link.cjs');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function parseArchive(buffer) {
  if (buffer.length < 16 || buffer.readUInt32LE(0) !== 4) throw Error('Неизвестный ASAR.');
  const headerSize = buffer.readUInt32LE(4), stringSize = buffer.readUInt32LE(12), payloadStart = 8 + headerSize;
  if (headerSize < stringSize + 8 || payloadStart > buffer.length || stringSize > 64 * 1024 * 1024) throw Error('Повреждённый заголовок ASAR.');
  const raw = buffer.subarray(16, 16 + stringSize), header = JSON.parse(raw.toString('utf8'));
  function entry(filename) {
    const components = filename.replace(/^\.\//, '').split('/');
    if (components.some(x => !x || x === '..' || x === '.') || filename.includes('\\') || path.posix.isAbsolute(filename)) throw Error('Неверный путь ASAR.');
    let node = header;
    for (const component of components) { node = node.files?.[component]; if (!node) throw Error('Файл ASAR не найден.'); }
    if (node.unpacked || node.link) throw Error('Файл входа должен находиться внутри ASAR.');
    return node;
  }
  function read(filename) {
    const item = entry(filename), offset = Number(item.offset), size = item.size;
    if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(size) || size < 0 || offset + size > buffer.length - payloadStart) throw Error('Некорректная запись ASAR.');
    return buffer.subarray(payloadStart + offset, payloadStart + offset + size);
  }
  return { header, raw, payloadStart, entry, read, digest: hash(raw) };
}

function addBootstrap(original, boot) {
  const archive = parseArchive(original), metadata = JSON.parse(archive.read('package.json').toString('utf8'));
  const main = metadata.main;
  if (typeof main !== 'string' || !/\.(?:c?js)$/.test(main) || metadata.type === 'module') throw Error('Неподдерживаемый входной модуль Claude.');
  const entry = archive.read(main);
  const marker = Buffer.from('"use strict";require("./proxy-guard-boot.cjs");\n');
  if (entry.includes(marker)) throw Error('Выберите оригинальную установку Claude.');
  const changed = Buffer.concat([marker, entry]);
  let body = original.subarray(archive.payloadStart);
  function append(filename, data) {
    const blockSize = 4194304, blocks = [];
    for (let offset = 0; offset < data.length; offset += blockSize) blocks.push(hash(data.subarray(offset, offset + blockSize)));
    const components = filename.replace(/^\.\//, '').split('/'); let parent = archive.header;
    for (const component of components.slice(0, -1)) {
      parent = parent.files?.[component]; if (!parent?.files) throw Error('Неизвестная структура ASAR.');
    }
    parent.files[components.at(-1)] = { size: data.length, offset: String(body.length), integrity: { algorithm: 'SHA256', hash: hash(data), blockSize, blocks } };
    body = Buffer.concat([body, data]);
  }
  append(main, changed);
  append(path.posix.join(path.posix.dirname(main), 'proxy-guard-boot.cjs'), boot);
  const raw = Buffer.from(JSON.stringify(archive.header)), padding = (4 - raw.length % 4) % 4;
  const prefix = Buffer.alloc(16); prefix.writeUInt32LE(4, 0); prefix.writeUInt32LE(8 + raw.length + padding, 4);
  prefix.writeUInt32LE(4 + raw.length + padding, 8); prefix.writeUInt32LE(raw.length, 12);
  const result = Buffer.concat([prefix, raw, Buffer.alloc(padding), body]);
  return { archive: result, oldDigest: archive.digest, digest: hash(raw), version: String(metadata.version || 'unknown') };
}

// Update only an existing, structurally validated PE integrity resource, preserving fuses.
// The private copy becomes unsigned; the installed executable is never changed.
function updatePEIntegrity(source, oldDigest, newDigest) {
  const bytes = Buffer.from(source);
  function range(offset, length) { if (!Number.isSafeInteger(offset) || offset < 0 || length < 0 || offset + length > bytes.length) throw Error('Повреждённый PE.'); return offset; }
  const u16 = offset => bytes.readUInt16LE(range(offset, 2)), u32 = offset => bytes.readUInt32LE(range(offset, 4));
  if (u16(0) !== 0x5a4d) throw Error('Выберите Windows Claude.exe.');
  const pe = u32(0x3c); if (u32(pe) !== 0x4550) throw Error('Неизвестный PE.');
  const sectionCount = u16(pe + 6), opt = pe + 24, optSize = u16(pe + 20), magic = u16(opt);
  const directory = opt + (magic === 0x20b ? 112 : magic === 0x10b ? 96 : -1);
  if (![0x20b, 0x10b].includes(magic) || sectionCount < 1 || sectionCount > 96 || directory + 40 > opt + optSize) throw Error('Неподдерживаемый PE.');
  const sections = [];
  for (let index = 0; index < sectionCount; index++) {
    const record = opt + optSize + index * 40; range(record, 40);
    sections.push({ rva: u32(record + 12), rawSize: u32(record + 16), raw: u32(record + 20) });
  }
  function fileOffset(rva, length) {
    const section = sections.find(s => rva >= s.rva && rva + length <= s.rva + s.rawSize);
    if (!section) throw Error('PE-ресурс выходит за границы секции.');
    return range(section.raw + rva - section.rva, length);
  }
  const resourceRVA = u32(directory + 16), resourceSize = u32(directory + 20), root = fileOffset(resourceRVA, resourceSize);
  function resourceOffset(relative, size) {
    if (relative < 0 || relative + size > resourceSize) throw Error('Неверная таблица PE-ресурсов.');
    return range(root + relative, size);
  }
  function entries(relative) {
    const location = resourceOffset(relative, 16), count = u16(location + 12) + u16(location + 14);
    if (count > 1024) throw Error('Слишком большая таблица ресурсов.');
    resourceOffset(relative, 16 + count * 8);
    return Array.from({ length: count }, (_, index) => {
      const record = location + 16 + index * 8, name = u32(record), target = u32(record + 4);
      let id = name;
      if (name & 0x80000000) {
        const position = resourceOffset(name & 0x7fffffff, 2), length = u16(position);
        resourceOffset((name & 0x7fffffff) + 2, length * 2);
        id = bytes.subarray(position + 2, position + 2 + length * 2).toString('utf16le').toUpperCase();
      }
      return { id, directory: !!(target & 0x80000000), target: target & 0x7fffffff };
    });
  }
  const type = entries(0).find(x => x.id === 'INTEGRITY' && x.directory);
  const name = type && entries(type.target).find(x => x.id === 'ELECTRONASAR' && x.directory);
  if (!name) throw Error('В Claude.exe не найден ожидаемый ресурс целостности ASAR.');
  let changed = 0;
  for (const language of entries(name.target)) {
    if (language.directory) throw Error('Неизвестная структура ресурса целостности.');
    const record = resourceOffset(language.target, 16), size = u32(record + 4);
    if (!size || size > 1024 * 1024) throw Error('Неверный ресурс целостности.');
    const position = fileOffset(u32(record), size), text = bytes.subarray(position, position + size).toString('utf8');
    const items = JSON.parse(text.replace(/\0+$/, ''));
    const match = Array.isArray(items) && items.filter(x => String(x.file).replaceAll('/', '\\').toLowerCase() === 'resources\\app.asar');
    if (!match || match.length !== 1 || String(match[0].alg).toUpperCase() !== 'SHA256' || match[0].value !== oldDigest) throw Error('Целостность исходного Claude не подтверждена.');
    const replaced = text.replaceAll(oldDigest, newDigest), output = Buffer.from(replaced);
    if (output.length !== size || replaced === text) throw Error('Не удалось обновить ресурс целостности.');
    output.copy(bytes, position); changed++;
  }
  if (!changed) throw Error('Пустой ресурс целостности.');
  // Drop the invalidated Authenticode directory on the copy; no vendor signature is claimed.
  bytes.fill(0, directory + 32, directory + 40);
  return bytes;
}

function windowsBootstrap(base, networkGuard = '') {
  const original = "const reader = fs.createReadStream(null, { fd: 3, autoClose: false });\nconst writer = fs.createWriteStream(null, { fd: 4, autoClose: false });";
  if (base.split(original).length !== 2) throw Error('Неизвестная версия адаптера Guard.');
  const profileAnchor = '  ready.catch(targetFailure);';
  const commandAnchor = 'async function command(m) {\n  let result;';
  if (base.split(commandAnchor).length !== 2) throw Error('Неизвестная версия канала Guard.');
  const navigationAnchor = 'wc[name] = (...args) => ready.then';
  if (base.split(profileAnchor).length !== 2 || base.split(navigationAnchor).length !== 2) throw Error('Неизвестная версия защиты профиля Guard.');
  const replacement = `app.setPath('sessionData', cfg.userData);
// Cookie SQLite flushes separately from Chromium's delayed Local State writes.
// Never admit a login page until its Windows DPAPI-wrapped key is on disk.
const guardProfileReady = app.whenReady().then(async () => {
  if (bridge.connecting) await new Promise(resolve => bridge.once('connect', resolve));
  if (!electron.safeStorage.isEncryptionAvailable()) throw Error('Шифрование профиля Windows недоступно.');
  const keyFile = path.join(cfg.userData, 'Local State');
  const deadline = performance.now() + 20000;
  let waitingNotice = false;
  while (performance.now() < deadline) {
    try {
      const stat = await fs.promises.lstat(keyFile);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 4194304) throw Error('Небезопасное хранилище ключа профиля.');
      const saved = JSON.parse(await fs.promises.readFile(keyFile, 'utf8'));
      const opaqueKey = saved?.os_crypt?.encrypted_key;
      if (typeof opaqueKey === 'string' && opaqueKey.length <= 16384 &&
          Buffer.from(opaqueKey, 'base64').length >= 64 &&
          Buffer.from(opaqueKey, 'base64').subarray(0, 5).toString('ascii') === 'DPAPI') {
        if (waitingNotice) emit({method:'ProxyGuard.notice',params:{message:'Зашифрованный профиль сохранён и готов к работе.'}});
        return;
      }
    } catch (error) {
      if (!(error instanceof SyntaxError) && !['ENOENT','EBUSY','EACCES'].includes(error.code)) throw error;
    }
    if (!waitingNotice) {
      waitingNotice = true;
      emit({method:'ProxyGuard.notice',params:{message:'Подготавливаем зашифрованный профиль Windows. Первый запуск может занять несколько секунд.'}});
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw Error('Windows не сохранила ключ зашифрованного профиля. Запуск остановлен без удаления данных.');
});
guardProfileReady.catch(fatal);
if (!cfg.channelPipe || !/^[a-f0-9]{64}$/.test(cfg.channelToken || '')) throw Error('Guard channel required');
const bridge = require('node:net').connect(cfg.channelPipe);
const reader = bridge, writer = bridge;
bridge.once('connect', () => emit({method:'ProxyGuard.hello',params:{token:cfg.channelToken}}));
if (process.platform === 'win32') app.setAppUserModelId('local.proxyguard.claude.runtime');`;
  const guard = networkGuard ? `\n{const guardModule={exports:{}};(function(require,module){\n${networkGuard}\n})(require,guardModule);guardModule.exports.installNetworkGuard(cfg);}\n` : '';
  return Buffer.from(base.replace(original, replacement + guard)
    .replace(commandAnchor, runtimeDeepLinkSource() + commandAnchor + `
  if (!m.sessionId && m.method === 'ProxyGuard.openDeepLink') {
    const response = await guardForwardDeepLink(m.params?.url, { app, profileReady: guardProfileReady, userData: cfg.userData, executable: process.execPath, cwd: path.dirname(process.execPath) });
    emit({ id: m.id, result: response }); return;
  }`)
    .replace(profileAnchor, '  const durableReady = ready.then(() => guardProfileReady);\n  durableReady.catch(targetFailure);')
    .replace(navigationAnchor, 'wc[name] = (...args) => durableReady.then'));
}
module.exports = { parseArchive, addBootstrap, updatePEIntegrity, windowsBootstrap, hash };
