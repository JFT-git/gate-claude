'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createUpdateMenu, RELEASES_URL } = require('../src/update-menu.cjs');
const Menu = { buildFromTemplate(template) {
  return { items: template.map(item => ({ ...item, submenu: Array.isArray(item.submenu) ? { items: item.submenu } : item.submenu })) };
} };

test('Windows update menu checks in background and gates installation on a downloaded update', () => {
  let checks = 0, installs = 0, releases = [];
  const view = createUpdateMenu({ Menu, onCheck: () => { checks++; }, onInstall: () => { installs++; }, onOpenReleases: url => releases.push(url) });
  const items = view.menu.items[0].submenu.items;
  assert.equal(view.menu.items[0].label, 'Обновления');
  assert.equal(items[1].enabled, false);
  assert.equal(items[2].visible, false);
  view.update({ state: 'idle', supported: true });
  assert.equal(items[1].enabled, true);
  items[1].click(); assert.equal(checks, 1);
  view.update({ state: 'checking', supported: true });
  assert.equal(items[1].enabled, false);
  assert.equal(items[2].enabled, false);
  view.update({ state: 'downloaded', supported: true, version: '0.9.1' });
  assert.equal(items[2].enabled, true);
  assert.equal(items[2].visible, true);
  items[2].click(); assert.equal(installs, 1);
  items[4].click(); assert.deepEqual(releases, [RELEASES_URL]);
  view.update({ state: 'idle', supported: false, reason: 'portable' });
  assert.equal(items[1].enabled, false);
  assert.match(items[0].label, /ZIP-сборка/);
});
