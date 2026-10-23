'use strict';
const path = require('node:path');
const { promisify } = require('node:util');
const run = promisify(require('node:child_process').execFile);
async function powershell(script, timeout = 30000) {
  const encoded = Buffer.from("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);\n" + script, 'utf16le').toString('base64');
  const exe = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const result = await run(exe, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], { windowsHide: true, timeout, maxBuffer: 1048576 });
  return result.stdout.replace(/^\uFEFF/, '').trim();
}
const psQuote = value => {
  const text = String(value);
  if (/[\u0000-\u001f\u2018\u2019\u201a\u201b\u201c\u201d\u201e]/.test(text)) throw Error('Unsupported character in PowerShell argument.');
  return "'" + text.replaceAll("'", "''") + "'";
};
module.exports = { powershell, psQuote };
