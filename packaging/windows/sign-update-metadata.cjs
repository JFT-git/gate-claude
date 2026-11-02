'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { PUBLIC_KEY_SPKI_BASE64 } = require('../../Windows/src/updater.cjs');

function main() {
  const metadataPath = path.resolve(process.argv[2] || '');
  const signaturePath = path.resolve(process.argv[3] || metadataPath + '.sig');
  const keyPath = process.env.GUARD_WINDOWS_UPDATE_PRIVATE_KEY;
  if (!process.argv[2] || !keyPath || !path.isAbsolute(keyPath)) throw Error('Set GUARD_WINDOWS_UPDATE_PRIVATE_KEY to an absolute external Ed25519 PEM path and pass latest.yml.');
  const metadata = fs.readFileSync(metadataPath);
  if (!metadata.length || metadata.length > 128 * 1024) throw Error('Invalid update metadata size.');
  const privateKey = fs.readFileSync(keyPath);
  const publicKey = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  if (!publicKey.equals(Buffer.from(PUBLIC_KEY_SPKI_BASE64, 'base64'))) throw Error('The external private key does not match the pinned updater public key.');
  const signature = crypto.sign(null, metadata, privateKey);
  fs.writeFileSync(signaturePath, signature.toString('base64') + '\n', { flag: 'wx', mode: 0o644 });
  process.stdout.write(signaturePath + '\n');
}

try { main(); }
catch (error) { console.error(error.message); process.exitCode = 1; }
