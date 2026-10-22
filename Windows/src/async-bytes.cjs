'use strict';
const crypto = require('node:crypto');
const { setImmediate: yieldTurn } = require('node:timers/promises');
const CHUNK = 1024 * 1024;

// Give socket, child-process and deadline callbacks a turn while authenticating
// large local assets. The complete input is still hashed before it is accepted.
async function sha256(bytes) {
  if (!Buffer.isBuffer(bytes)) throw TypeError('Expected bytes');
  const digest = crypto.createHash('sha256');
  for (let offset = 0; offset < bytes.length; offset += CHUNK) {
    if (bytes.length > CHUNK) await yieldTurn();
    digest.update(bytes.subarray(offset, Math.min(offset + CHUNK, bytes.length)));
  }
  return digest.digest('hex');
}
module.exports = { sha256 };
