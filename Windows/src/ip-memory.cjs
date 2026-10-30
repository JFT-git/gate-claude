'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { canonicalIP } = require('./policy.cjs');
const UNAVAILABLE = 'Не удалось прочитать или сохранить закреплённый IP. Доступ закрыт. Проверьте файл памяти IP или сбросьте закрепление в интерфейсе.';
const MISMATCH = 'Внешний IP не совпадает с сохранённым. Верните закреплённый IP. Перезапуск Guard не разрешает другой адрес; смена возможна только после сброса с подтверждением.';

class IPMemory {
  constructor(root) { this.file = path.join(root, 'ip-memory.json'); }
  load() {
    let fd;
    try {
      const stat = fs.lstatSync(this.file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 4096) throw Error();
      fd = fs.openSync(this.file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      const actual = fs.fstatSync(fd);
      if (!actual.isFile() || actual.nlink !== 1 || actual.size > 4096 || actual.ino !== stat.ino || actual.dev !== stat.dev) throw Error();
      const value = JSON.parse(fs.readFileSync(fd, 'utf8'));
      if (!value || value.version !== 1 || Object.keys(value).sort().join(',') !== 'pinnedIP,version') throw Error();
      if (value.pinnedIP === null) return null;
      if (typeof value.pinnedIP !== 'string' || value.pinnedIP.includes('%')) throw Error();
      return canonicalIP(value.pinnedIP);
    } catch (error) {
      if (error.code === 'ENOENT' && fd === undefined) return null;
      throw Error(UNAVAILABLE);
    } finally { if (fd !== undefined) fs.closeSync(fd); }
  }
  check(ip) {
    const saved = this.load();
    if (saved !== null && saved !== canonicalIP(ip)) throw Error(MISMATCH);
    return saved;
  }
  commit(ip) {
    const canonical = canonicalIP(ip);
    if (this.check(canonical) !== null) return canonical;
    this.write(canonical);
    if (this.load() !== canonical) throw Error(UNAVAILABLE);
    return canonical;
  }
  reset() { this.write(null); if (this.load() !== null) throw Error(UNAVAILABLE); }
  write(pinnedIP) {
    const directory = path.dirname(this.file), temp = this.file + '.' + randomUUID() + '.tmp';
    let fd;
    try {
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      const parent = fs.lstatSync(directory);
      if (!parent.isDirectory() || parent.isSymbolicLink()) throw Error();
      try {
        const current = fs.lstatSync(this.file);
        if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1) throw Error();
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
      fd = fs.openSync(temp, 'wx', 0o600);
      fs.writeFileSync(fd, JSON.stringify({ version: 1, pinnedIP }, null, 2) + '\n');
      fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
      fs.renameSync(temp, this.file);
    } catch { throw Error(UNAVAILABLE); }
    finally {
      if (fd !== undefined) fs.closeSync(fd);
      try { fs.unlinkSync(temp); } catch {}
    }
  }
}
module.exports = { IPMemory, MISMATCH, UNAVAILABLE };
