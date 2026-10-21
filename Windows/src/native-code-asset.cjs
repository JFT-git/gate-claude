'use strict';
const fs = require('./raw-fs.cjs').promises;
const path = require('node:path');
const crypto = require('node:crypto');
const https = require('node:https');
const tls = require('node:tls');
const { connectTunnel } = require('./relay.cjs');
const { safeFilesystem } = require('./code-tools.cjs');
const { SOURCE_POLICY } = require('./code-preparation.cjs');
const { sha256 } = require('./async-bytes.cjs');

// Source provenance is compiled into Guard. Callers cannot choose a URL, host,
// checksum, TLS authority, or proxy bypass. No account credentials are sent.
const ASSET = Object.freeze({ hostname: 'downloads.claude.ai',
  pathname: '/claude-code-releases/2.1.304/win32-x64/claude.exe.zst',
  filename: 'win32-x64.zst', bytes: SOURCE_POLICY.compressedSize, sha256: SOURCE_POLICY.compressedSHA256 });
const DOWNLOAD_TIMEOUT_MS = 180000, IDLE_TIMEOUT_MS = 15000;
const failure = () => Object.assign(Error('Не удалось безопасно загрузить Claude Code через Guard. Соединение закрыто.'), { code: 'ERR_GUARD_CODE_ASSET' });
function checkControls(controls) {
  if (!controls || typeof controls !== 'object' || Array.isArray(controls) || Object.keys(controls).some(key => !['active', 'signal'].includes(key)) || typeof controls.active !== 'function') throw failure();
  const signal = controls.signal;
  if (signal !== undefined && (!signal || typeof signal.addEventListener !== 'function' || typeof signal.removeEventListener !== 'function' || typeof signal.aborted !== 'boolean')) throw failure();
  return () => { if (signal?.aborted || controls.active() !== true) throw failure(); };
}
function download(relayPort, controls, check, file) {
  let raw, secure, request, response, finished = false;
  const agent = new https.Agent({ keepAlive: false, maxSockets: 1 });
  return new Promise((resolve, reject) => {
    const finish = error => {
      if (finished) return; finished = true;
      clearTimeout(deadline); clearInterval(activePoll); controls.signal?.removeEventListener('abort', abort);
      response?.destroy(); request?.destroy(); secure?.destroy(); raw?.destroy(); agent.destroy();
      if (error) reject(failure()); else resolve();
    };
    const abort = () => finish(failure());
    const deadline = setTimeout(abort, DOWNLOAD_TIMEOUT_MS);
    const activePoll = setInterval(() => { try { check(); } catch { abort(); } }, 100);
    controls.signal?.addEventListener('abort', abort, { once: true });
    agent.createConnection = (_options, callback) => {
      // Empty checkToken means ordinary application traffic. This cannot borrow
      // the IP-check exception while the relay is locked or paused.
      connectTunnel(relayPort, ASSET.hostname, 443, '', socket => { raw = socket; if (finished) socket.destroy(); }).then(socket => {
        raw = socket;
        if (finished) { socket.destroy(); callback(failure()); return; }
        try { check(); } catch { socket.destroy(); callback(failure()); return; }
        secure = tls.connect({ socket, servername: ASSET.hostname, rejectUnauthorized: true, minVersion: 'TLSv1.2' });
        let completed = false;
        const complete = (error, stream) => { if (!completed) { completed = true; callback(error, stream); } };
        secure.once('secureConnect', () => complete(null, secure));
        secure.once('error', error => complete(error));
      }).catch(error => callback(error));
    };
    try {
      check();
      request = https.request({ hostname: ASSET.hostname, port: 443, path: ASSET.pathname, method: 'GET', agent,
        headers: { Accept: 'application/octet-stream', 'Accept-Encoding': 'identity', Connection: 'close', 'User-Agent': 'gate-claude-code-assets' } }, incoming => {
        response = incoming;
        response.once('error', abort);
        void (async () => {
          // Redirects are refused: the pinned release has one fixed HTTPS URL.
          // Exact identity framing also rejects transparently compressed bodies.
          const lengths = incoming.rawHeaders.filter((_, index) => index % 2 === 0 && incoming.rawHeaders[index].toLowerCase() === 'content-length');
          if (incoming.statusCode !== 200 || lengths.length !== 1 || incoming.headers['content-length'] !== String(ASSET.bytes) || incoming.headers['transfer-encoding'] !== undefined || ![undefined, 'identity'].includes(incoming.headers['content-encoding'])) throw failure();
          const digest = crypto.createHash('sha256'); let total = 0;
          for await (const chunk of incoming) {
            check(); if (finished || !Buffer.isBuffer(chunk) || total + chunk.length > ASSET.bytes) throw failure();
            total += chunk.length; digest.update(chunk);
            let offset = 0;
            while (offset < chunk.length) { const result = await file.write(chunk, offset, chunk.length - offset); if (!result.bytesWritten) throw failure(); offset += result.bytesWritten; }
          }
          check(); if (!incoming.complete || total !== ASSET.bytes || digest.digest('hex') !== ASSET.sha256) throw failure();
          finish();
        })().catch(abort);
      });
      request.setTimeout(IDLE_TIMEOUT_MS, abort);
      request.once('error', abort); request.end();
    } catch { abort(); }
  });
}
async function ensureNativeCodeAsset(guardRoot, relayPort, controls) {
  const safe = safeFilesystem(fs); let staging, handle;
  try {
    const check = checkControls(controls); check();
    if (typeof guardRoot !== 'string' || !path.isAbsolute(guardRoot) || path.resolve(guardRoot) !== guardRoot || !Number.isInteger(relayPort) || relayPort < 1 || relayPort > 65535) throw failure();
    await safe.inspect(guardRoot, true); check();
    const assets = await safe.directory(path.join(guardRoot, 'CodeAssets')), target = await safe.directory(path.join(assets, ASSET.sha256));
    const assetPath = path.join(target, ASSET.filename), names = await fs.readdir(target);
    if (names.some(name => name !== ASSET.filename)) throw failure();
    const verify = async file => { check(); const bytes = await safe.read(file, ASSET.bytes); check(); if (bytes.length !== ASSET.bytes || await sha256(bytes) !== ASSET.sha256) throw failure(); check(); };
    if (names.length === 1) { await verify(assetPath); return { path: assetPath }; }
    check();
    const candidate = path.join(assets, 'Preparing-' + crypto.randomBytes(16).toString('hex') + '.zst');
    handle = await fs.open(candidate, 'wx', 0o600); staging = candidate;
    await download(relayPort, controls, check, handle); await handle.sync(); await handle.close(); handle = undefined;
    await verify(staging); await safe.inspect(target, true); check();
    // link is an atomic no-replace publication even on systems where rename can
    // replace an existing file. Remove our temporary link before validation.
    await fs.link(staging, assetPath); await fs.unlink(staging); staging = undefined;
    await verify(assetPath); return { path: assetPath };
  } catch { throw failure(); }
  finally {
    if (handle) { try { await handle.close(); } catch {} }
    if (staging) { try { await fs.unlink(staging); } catch {} }
  }
}
module.exports = { ensureNativeCodeAsset, ASSET };
