'use strict';
const https = require('node:https');
const request = https.get('https://downloads.claude.ai/claude-code-releases/2.1.304/win32-x64/claude.exe.zst', {
  timeout: 20000,
  headers: { Accept: 'application/octet-stream', 'Accept-Encoding': 'identity', 'User-Agent': 'gate-claude-code-assets' }
}, response => {
  console.log(JSON.stringify({ status: response.statusCode, length: response.headers['content-length'], encoding: response.headers['content-encoding'], transfer: response.headers['transfer-encoding'] }));
  response.resume(); response.on('end', () => console.log('END'));
});
request.on('error', error => console.log(JSON.stringify({ error: error.code, message: error.message })));
request.on('timeout', () => { console.log('TIMEOUT'); request.destroy(); });
