'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(process.env.TEMP, 'guard-hardlink-probe');
fs.mkdirSync(root, { recursive: true });
const source = path.join(root, 'source'), target = path.join(root, 'target');
fs.writeFileSync(source, 'synthetic');
try { fs.linkSync(source, target); console.log(JSON.stringify({ result: 'PASS', nlink: fs.statSync(target).nlink })); }
catch (error) { console.log(JSON.stringify({ result: 'FAIL', code: error.code, message: error.message })); process.exitCode = 1; }
finally { fs.rmSync(root, { recursive: true, force: true }); }
