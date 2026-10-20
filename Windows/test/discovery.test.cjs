'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { packageCandidates, selectCandidate } = require('../src/discovery.cjs');

test('WindowsApps comes from package manifest without enumerating the protected root', async () => {
  const root = 'C:\\Program Files\\WindowsApps\\Claude_3.1623.0.0_x64__fixture';
  const candidates = packageCandidates([{ location: root, version: '3.1623.0.0', executables: ['app\\Claude.exe', 'app\\resources\\claude-ssh-askpass.exe'] }]);
  assert.equal(candidates[0].path, root + '\\app\\Claude.exe');
  assert.equal(candidates[0].kind, 'msix');
  assert.equal(candidates.filter(x => /askpass/i.test(x.path)).length, 0);
  const result = await selectCandidate(candidates, async item => assert.equal(item.path, root + '\\app\\Claude.exe'));
  assert.equal(result.status, 'found'); assert.match(result.message, /WindowsApps/);
});
test('latest installed version wins; manifest cannot escape the package directory', () => {
  const candidates = packageCandidates([
    { location: 'C:\\Program Files\\WindowsApps\\Claude_old', version: '3.9.0.0', executables: ['app\\claude.exe'] },
    { location: 'C:\\Program Files\\WindowsApps\\Claude_new', version: '3.20.0.0', executables: ['..\\claude.exe', 'C:\\elsewhere\\claude.exe', 'app\\claude.exe'] }
  ]);
  assert.match(candidates[0].path, /Claude_new\\app\\claude.exe$/);
  assert.ok(candidates.every(x => !x.path.includes('elsewhere')));
  assert.ok(candidates.every(x => /WindowsApps\\Claude_(old|new)\\/.test(x.path)));
});
test('stale/unreadable installation falls through, and access denied is reported explicitly', async () => {
  const candidates = [{ path: 'stale', kind: 'msix' }, { path: 'readable', kind: 'legacy' }];
  const found = await selectCandidate(candidates, async item => { if (item.path === 'stale') throw Object.assign(Error(), { code: 'ENOENT' }); });
  assert.equal(found.path, 'readable');
  const denied = await selectCandidate(candidates, async () => { throw Object.assign(Error(), { code: 'EACCES' }); });
  assert.equal(denied.status, 'access-denied'); assert.equal(denied.path, '');
  assert.equal((await selectCandidate([])).status, 'not-found');
});
