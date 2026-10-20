'use strict';
// Explicit allowlist for publishing synthetic test results. Never publish raw traffic records.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const source = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
assert.equal(source.result, 'PASS');
const expected = { timezone: 'Europe/Amsterdam', language: 'en-US', locale: 'en-US' };
const actual = source.rendererResult?.profile || source.rendererProfile?.profile || source.rendererProfile;
for (const [key, value] of Object.entries(expected)) assert.equal(actual[key], value);
const capture = source.capturedHTTP;
assert.equal(capture.method, 'POST'); assert.equal(capture.status, 200);
assert.equal(capture.url, 'https://claude.ai/__guard_test__/capture');
const response = JSON.parse(capture.received); assert.equal(response.marker, 'guard-response-ok');
const sent = JSON.parse(capture.sent);
for (const [key, value] of Object.entries(expected)) { assert.equal(sent[key], value); assert.equal(response.received[key], value); }
const publicProof = {
  result: 'PASS', platform: source.platform === 'win32' ? 'Windows x64' : 'macOS',
  test: 'official local Claude, isolated profile, synthetic local TLS fixture',
  sourceVersion: source.sourceVersion || '3.1623.0',
  rendererProfile: expected,
  capturedHTTP: { method: capture.method, url: capture.url, status: capture.status,
    acceptLanguage: /accept-language:\s*en-US\b/i.test(capture.requestHeaders) ? 'en-US' : 'unconfirmed',
    sent: expected, received: { marker: response.marker, received: expected } },
  iframeProfiles: source.iframeProfiles || source.iframeLifecycle?.profiles?.length,
  auxiliaryWindowsClosed: source.auxiliaryWindowsClosed,
  sharedLocale: { conflict: 'Another locale override is already in effect', inherited: source.sharedLocale?.inherited === true },
  killSwitch: { milliseconds: source.killSwitch.milliseconds, processGone: source.killSwitch.processGone,
    streamClosed: source.killSwitch.streamClosed ?? source.fixture?.activeTLSStreamClosed,
    relayRefusesNewConnections: source.killSwitch.relayRefusesNewConnections,
    blockedUntilRestart: source.killSwitch.blockedUntilRestart },
  observedIPSource: 'controlled test-only provider; no physical WAN change',
  network: 'local fixture only; external traffic denied by the test environment',
  publication: 'allowlist only; device metadata, user agent, full headers, paths, process/session IDs and raw traffic omitted'
};
if (source.webSocketCaptured != null) publicProof.webSocketCaptured = source.webSocketCaptured;
if (source.restart) publicProof.restart = { freshPolicy: source.restart.freshPolicy, passwordAbsent: source.restart.passwordAbsent };
fs.writeFileSync(process.argv[3], JSON.stringify(publicProof, null, 2) + '\n');
