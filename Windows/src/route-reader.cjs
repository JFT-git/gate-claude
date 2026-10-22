'use strict';
const { execFile } = require('node:child_process');
const runFile = require('node:util').promisify(execFile);

const MESSAGE = 'Не удалось прочитать таблицу маршрутов Windows. Трафик остаётся закрытым.';
const CODES = new Set(['TIMEOUT', 'ENOENT', 'EACCES', 'EXIT_NONZERO', 'INVALID_SNAPSHOT']);
class RouteReadError extends Error {
  constructor(code) {
    super(MESSAGE);
    this.code = CODES.has(code) ? code : 'EXIT_NONZERO';
  }
}

async function readRouteFingerprint(helper, { execute = runFile } = {}) {
  let result;
  try {
    result = await execute(helper, ['--route-fingerprint'],
      { windowsHide: true, timeout: 4000, maxBuffer: 65536, encoding: 'utf8' });
  } catch (error) {
    // Buffer overflow can also kill the child; classify it before timeout.
    const code = error?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' ? 'INVALID_SNAPSHOT'
      : error?.code === 'ENOENT' ? 'ENOENT'
      : ['EACCES', 'EPERM'].includes(error?.code) ? 'EACCES'
      : error?.killed === true || error?.code === 'ETIMEDOUT' ? 'TIMEOUT' : 'EXIT_NONZERO';
    // Subprocess messages, paths, stdout and stderr never escape this boundary.
    throw new RouteReadError(code);
  }
  try {
    if (typeof result?.stdout !== 'string' || Buffer.byteLength(result.stdout, 'utf8') > 65536) throw Error();
    const routes = JSON.parse(result.stdout.trim());
    if (!Array.isArray(routes) || routes.some(route => typeof route !== 'string' || route.length > 256)) throw Error();
    return JSON.stringify(routes);
  } catch { throw new RouteReadError('INVALID_SNAPSHOT'); }
}

module.exports = { readRouteFingerprint, RouteReadError };
