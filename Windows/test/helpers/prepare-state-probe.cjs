'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const work = path.resolve(process.argv[2]), codeHost = path.resolve(process.argv[3]);
const cache = path.join(work, 'Cache'), runtime = fs.readdirSync(cache).find(name => /^Runtime-[a-f0-9]{24}$/.test(name));
if (!runtime) throw Error('Runtime fixture missing');
const codeBin = path.join(cache, 'CodeBin'), hash = fs.readdirSync(codeBin).find(name => /^[a-f0-9]{64}$/.test(name));
const tools = path.join(cache, 'CodeTools');
const toolRoots = ['Git', 'PowerShell'].map(prefix => {
  const name = fs.readdirSync(tools).find(item => item.startsWith(prefix + '-'));
  if (!name) throw Error('Tool root missing: ' + prefix);
  return path.join(tools, name);
});
const containerName = 'gate-code-' + 'a'.repeat(24);
const created = JSON.parse(execFileSync(codeHost, ['--create-profile', containerName], { encoding: 'utf8', windowsHide: true }));
const body = Buffer.from(JSON.stringify({ version: 1, containerName, containerSid: created.sid,
  stateRoot: path.join(cache, 'CodeState'), executable: path.join(codeBin, hash, 'claude.exe'), executableSHA256: hash,
  runtimeExecutable: path.join(cache, runtime, 'Claude.exe'), toolRoots }));
const header = Buffer.alloc(4); header.writeUInt32LE(body.length);
try {
  const result = execFileSync(codeHost, ['--prepare-state'], { input: Buffer.concat([header, body]), encoding: 'utf8', windowsHide: true, maxBuffer: 8192 });
  console.log(result.trim());
} finally {
  try { execFileSync(codeHost, ['--delete-profile', containerName], { encoding: 'utf8', windowsHide: true }); } catch {}
}
