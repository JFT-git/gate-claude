'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { psQuote } = require('../src/windows.cjs');

test('psQuote preserves straight-quote escaping', () => {
  assert.equal(psQuote("C:\\O'Brien\\claude.exe"), "'C:\\O''Brien\\claude.exe'");
});

test('psQuote rejects every PowerShell smart quote and control character without echoing input', () => {
  const forbidden = [...'\u2018\u2019\u201a\u201b\u201c\u201d\u201e', ...Array.from({ length: 32 }, (_, code) => String.fromCharCode(code))];
  for (const character of forbidden) {
    const hostile = `C:\\hostile${character}; injected-command; #`;
    assert.throws(() => psQuote(hostile), error => {
      assert.equal(error.message, 'Unsupported character in PowerShell argument.');
      assert.equal(error.message.includes(hostile), false);
      return true;
    });
  }
});
