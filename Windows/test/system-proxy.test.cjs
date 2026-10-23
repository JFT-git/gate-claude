'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readSystemProxy, parseRegistryOutput, parseProxyServer, SystemProxyError } = require('../src/system-proxy.cjs');

const key = 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
const secret = 'PRIVATE_PROXY_PASSWORD_AND_ACCOUNT';
function registry(entries = []) {
  return '\r\n' + key + '\r\n' + entries.map(([name, type, value]) => '    ' + name + '    ' + type + '    ' + value).join('\r\n') + '\r\n';
}
const enabled = server => registry([['ProxyEnable', 'REG_DWORD', '0x1'], ['ProxyServer', 'REG_SZ', server]]);
function safeError(code) {
  return error => {
    assert.ok(error instanceof SystemProxyError);
    assert.equal(error.message, 'Не удалось безопасно определить прокси Windows. Выберите явный SOCKS5-прокси в Guard.');
    if (code) assert.equal(error.code, code);
    assert.deepEqual(Object.keys(error), ['code']);
    assert.equal(error.message.includes(secret), false); assert.equal(JSON.stringify(error).includes(secret), false);
    return true;
  };
}

test('non-Windows uses a stable immutable direct descriptor without invoking a registry command', async () => {
  const execute = () => { throw Error('unexpected command'); };
  const first = await readSystemProxy({ platform: 'darwin', execute }), second = await readSystemProxy({ platform: 'linux', execute });
  assert.deepEqual(first, second); assert.equal(first.kind, 'direct'); assert.equal(first.host, ''); assert.equal(first.port, 0);
  assert.match(first.fingerprint, /^[a-f0-9]{64}$/); assert.equal(Object.isFrozen(first), true);
});

test('Windows reads the entire fixed key once through absolute reg.exe with bounded execution and output', async () => {
  let calls = 0;
  const result = await readSystemProxy({ platform: 'win32', systemRoot: 'D:\\Windows', execute: async (file, args, options) => {
    calls++; assert.equal(file, 'D:\\Windows\\System32\\reg.exe'); assert.deepEqual(args, ['query', key]);
    assert.deepEqual(options, { windowsHide: true, timeout: 2000, maxBuffer: 65536, encoding: 'utf8' });
    return { stdout: enabled('127.0.0.1:9697'), stderr: secret };
  } });
  assert.equal(calls, 1); assert.equal(result.kind, 'http'); assert.equal(result.host, '127.0.0.1'); assert.equal(result.port, 9697);
  assert.deepEqual(Object.keys(result).sort(), ['fingerprint', 'host', 'kind', 'port']);
  assert.equal(Object.isFrozen(result), true); assert.equal(JSON.stringify(result).includes(secret), false);
});

test('static authority parsing accepts strict IPv4, DNS and bracketed IPv6 proxies', () => {
  for (const [text, host, port] of [['127.0.0.1:9697', '127.0.0.1', 9697], ['Proxy.Example:8080', 'proxy.example', 8080], ['localhost:1', 'localhost', 1], ['[2001:db8::1]:65535', '2001:db8::1', 65535], ['proxy.example.:1080', 'proxy.example.', 1080]]) {
    assert.deepEqual(parseProxyServer(text), { kind: 'http', host, port });
  }
});

test('protocol maps choose HTTPS then HTTP then SOCKS while validating every configured entry', () => {
  assert.deepEqual(parseProxyServer('socks=socks.example:1080;http=plain.example:8080;HTTPS=secure.example:3128'), { kind: 'http', host: 'secure.example', port: 3128 });
  assert.deepEqual(parseProxyServer('socks=socks.example:1080; http = plain.example:8080'), { kind: 'http', host: 'plain.example', port: 8080 });
  assert.deepEqual(parseProxyServer('socks=[::1]:1080'), { kind: 'socks5', host: '::1', port: 1080 });
  assert.throws(() => parseProxyServer('https=good.example:80;http=' + secret + '@bad.example:80'), safeError());
});

test('credentials, URI syntax, numeric ambiguity, malformed DNS/IPv6 and invalid ports are refused', () => {
  for (const text of ['', 'host', 'host:0', 'host:65536', 'host:080', 'host:-1', 'host:1/path', 'host:1?x', 'host:1#x', 'host:1\\path', 'http://host:80', secret + '@host:80', 'user:' + secret + '@host:80', '127.1:80', '0177.0.0.1:80', '2130706433:80', '0x7f000001:80', 'host..example:80', '-host:80', 'host-:80', 'a'.repeat(64) + ':80', '2001:db8::1:80', '[not-ip]:80', '[fe80::1%25eth0]:80', '[::1]:80/path', 'host :80', 'host:80\t', 'host:80\n' + secret]) {
    assert.throws(() => parseProxyServer(text), safeError());
  }
});

test('unknown, mixed, duplicate or incomplete maps are refused rather than falling back to direct', () => {
  for (const text of ['http=host:80;https=host:81;http=host:82', 'https=host:80;HTTPS=host:80', 'ftp=host:80', 'http=host:80;socks=', 'http=host:80;', ';http=host:80', 'http=host:80;other:81', 'http=host:80=bad', 'http=host:80;https=bad:0']) assert.throws(() => parseProxyServer(text), safeError());
});

test('missing or disabled static proxy stays direct without fingerprinting unused server values', () => {
  const absent = parseRegistryOutput(registry()), disabled = parseRegistryOutput(registry([['ProxyEnable', 'REG_DWORD', '0x0']]));
  const invalidDisabled = parseRegistryOutput(registry([['ProxyEnable', 'REG_DWORD', '0x0'], ['ProxyServer', 'REG_SZ', secret + '@invalid']]));
  const binaryDisabled = parseRegistryOutput(registry([['ProxyServer', 'REG_BINARY', '010203']]));
  for (const value of [absent, disabled, invalidDisabled, binaryDisabled]) assert.equal(value.kind, 'direct');
  for (const value of [disabled, invalidDisabled, binaryDisabled]) assert.equal(value.fingerprint, absent.fingerprint);
  assert.equal(JSON.stringify(invalidDisabled).includes(secret), false);
});

test('configuration fingerprints are stable and change only with the validated route', () => {
  const first = parseRegistryOutput(enabled('127.0.0.1:9697'));
  assert.equal(first.fingerprint, parseRegistryOutput(enabled('127.0.0.1:9697')).fingerprint);
  assert.notEqual(first.fingerprint, parseRegistryOutput(enabled('127.0.0.1:9698')).fingerprint);
  const disabled = server => parseRegistryOutput(registry([['ProxyEnable', 'REG_DWORD', '0x0'], ['ProxyServer', 'REG_SZ', server]]));
  assert.equal(disabled('host:80').fingerprint, disabled('host:81').fingerprint);
  assert.equal(parseRegistryOutput(registry()).fingerprint, parseRegistryOutput(registry([['AutoConfigURL', 'REG_SZ', '']])).fingerprint);
});

test('equivalent map ordering, DNS case and formatting keep the captured proxy identity', () => {
  const expected = parseRegistryOutput(enabled('Proxy.Example:8080'));
  for (const server of [
    'proxy.example:8080', ' PROXY.EXAMPLE:8080 ',
    'http=proxy.example:8080;https=Proxy.Example:8080;socks=unused.example:1080',
    'socks=unused.example:1080;HTTPS=PROXY.EXAMPLE:8080; http = proxy.example:8080',
    'https=proxy.example:8080;http=different-unused.example:3128'
  ]) {
    const current = parseRegistryOutput(enabled(server));
    assert.deepEqual(current, expected); assert.equal(Object.isFrozen(current), true);
  }
  const paddedState = registry([['ProxyEnable', 'REG_DWORD', '0x00000001'], ['ProxyServer', 'REG_SZ', 'proxy.example:8080'], ['AutoConfigURL', 'REG_SZ', '']]);
  assert.deepEqual(parseRegistryOutput(paddedState), expected);
});

test('effective direct, protocol, host and port changes produce distinct identities', () => {
  const configurations = [registry(), enabled('proxy.example:8080'), enabled('socks=proxy.example:8080'), enabled('other.example:8080'), enabled('proxy.example:8081')];
  const identities = configurations.map(value => parseRegistryOutput(value).fingerprint);
  assert.equal(new Set(identities).size, configurations.length);
  assert.notEqual(parseRegistryOutput(enabled('proxy.example:8080')).fingerprint,
    parseRegistryOutput(registry([['ProxyEnable', 'REG_DWORD', '0x0'], ['ProxyServer', 'REG_SZ', 'proxy.example:8080']])).fingerprint);
});

test('literal IPv6 spelling is normalized without merging DNS or different address families', () => {
  const compressed = parseRegistryOutput(enabled('[2001:db8::1]:8080'));
  const expanded = parseRegistryOutput(enabled('[2001:0DB8:0:0:0:0:0:1]:8080'));
  assert.equal(compressed.fingerprint, expanded.fingerprint);
  for (const [first, second] of [['proxy.example:8080', 'proxy.example.:8080'], ['localhost:8080', '127.0.0.1:8080'], ['127.0.0.1:8080', '[::ffff:127.0.0.1]:8080']]) {
    assert.notEqual(parseRegistryOutput(enabled(first)).fingerprint, parseRegistryOutput(enabled(second)).fingerprint);
  }
});

test('semantic identity never masks unsupported PAC or an invalid unselected proxy entry', () => {
  const baseline = parseRegistryOutput(enabled('proxy.example:8080'));
  const pac = registry([['ProxyEnable', 'REG_DWORD', '0x1'], ['ProxyServer', 'REG_SZ', 'proxy.example:8080'], ['AutoConfigURL', 'REG_SZ', 'https://private.invalid/proxy.pac']]);
  assert.throws(() => parseRegistryOutput(pac), safeError('UNSUPPORTED_PAC'));
  assert.throws(() => parseRegistryOutput(enabled('https=proxy.example:8080;http=bad:0')), safeError('INVALID_SETTINGS'));
  assert.throws(() => parseRegistryOutput(enabled('https=proxy.example:8080;http=user:' + secret + '@bad:80')), safeError('INVALID_SETTINGS'));
  assert.equal(baseline.host, 'proxy.example'); assert.equal(baseline.port, 8080); assert.equal(Object.isFrozen(baseline), true);
});

test('enabled static proxy requires one valid REG_SZ server and boolean REG_DWORD state', () => {
  for (const entries of [
    [['ProxyEnable', 'REG_DWORD', '0x1']],
    [['ProxyEnable', 'REG_DWORD', '0x1'], ['ProxyServer', 'REG_SZ', '']],
    [['ProxyEnable', 'REG_DWORD', '0x1'], ['ProxyServer', 'REG_BINARY', '010203']],
    [['ProxyEnable', 'REG_DWORD', '0x1'], ['ProxyServer', 'REG_EXPAND_SZ', '%USERPROFILE%:80']],
    [['ProxyEnable', 'REG_SZ', '0x1'], ['ProxyServer', 'REG_SZ', 'host:80']],
    [['ProxyEnable', 'REG_DWORD', '1'], ['ProxyServer', 'REG_SZ', 'host:80']],
    [['ProxyEnable', 'REG_DWORD', '0x2'], ['ProxyServer', 'REG_SZ', 'host:80']]
  ]) assert.throws(() => parseRegistryOutput(registry(entries)), safeError());
  assert.equal(parseRegistryOutput(registry([['ProxyEnable', 'REG_DWORD', '0x00000001'], ['ProxyServer', 'REG_SZ', 'host:80']])).kind, 'http');
});

test('nonempty PAC fails closed even with disabled static proxy; empty PAC is harmless', () => {
  for (const state of ['0x0', '0x1']) assert.throws(() => parseRegistryOutput(registry([['ProxyEnable', 'REG_DWORD', state], ['ProxyServer', 'REG_SZ', 'host:80'], ['AutoConfigURL', 'REG_SZ', 'https://' + secret + '.invalid/proxy.pac']])), safeError('UNSUPPORTED_PAC'));
  assert.equal(parseRegistryOutput(registry([['AutoConfigURL', 'REG_SZ', '']])).kind, 'direct');
  assert.throws(() => parseRegistryOutput(registry([['AutoConfigURL', 'REG_EXPAND_SZ', '%USERPROFILE%']])), safeError('UNSUPPORTED_PAC'));
});

test('known rows are case insensitive and unrelated values or subkeys do not become proxy controls', () => {
  const text = registry([['proxyenable', 'REG_DWORD', '0x1'], ['PROXYSERVER', 'REG_SZ', 'host:80'], ['Unrelated localized value', 'REG_SZ', 'обычный текст']]) + key + '\\Connections\r\n';
  assert.equal(parseRegistryOutput(text).host, 'host');
  const original = parseRegistryOutput(enabled('host:80'));
  assert.equal(parseRegistryOutput(enabled('host:80') + '    Unrelated    REG_SZ    changed\r\n').fingerprint, original.fingerprint);
});

test('NULL values, duplicate known values, binary payloads and newline injections are rejected safely', () => {
  for (const text of [null, undefined, Buffer.from(enabled('host:80')), '', 'ERROR: ' + secret,
    enabled('NULL'), enabled('(null)'), enabled('host:80\0' + secret),
    registry([['ProxyEnable', 'REG_DWORD', '0x1'], ['proxyenable', 'REG_DWORD', '0x0'], ['ProxyServer', 'REG_SZ', 'host:80']]),
    enabled('host:80\r\n    ProxyEnable    REG_DWORD    0x0'),
    enabled('host:80\r\n' + secret),
    enabled('host:80\n    ProxyServer    REG_BINARY    ' + secret),
    key + '\r\n    ProxyServer    REG_SZ    host:80\rINJECTED',
    key + '\\Connections\r\n    ProxyEnable    REG_DWORD    0x0',
    enabled('host:80') + 'HKEY_CURRENT_USER\\Other\r\n',
    enabled('host:80') + key + '\r\n',
    key + '\r\n    ProxyServer    REG_SZ    ' + 'x'.repeat(4097),
    'x'.repeat(65537)]) assert.throws(() => parseRegistryOutput(text), safeError());
});

test('registry failures and hostile subprocess diagnostics never escape through errors', async () => {
  for (const details of [{ code: 'ENOENT' }, { code: 'EACCES' }, { code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' }, { killed: true, code: 'ETIMEDOUT' }]) {
    await assert.rejects(readSystemProxy({ platform: 'win32', execute: async () => { throw Object.assign(Error(secret.repeat(10000)), details, { stdout: secret, stderr: secret, path: 'C:\\' + secret, cmd: secret }); } }), safeError('READ_FAILED'));
  }
  await assert.rejects(readSystemProxy({ platform: 'win32', execute: async () => undefined }), safeError('INVALID_SETTINGS'));
  await assert.rejects(readSystemProxy({ platform: 'win32', execute: async () => ({ stdout: 'x'.repeat(65537), stderr: secret }) }), safeError('INVALID_SETTINGS'));
});

test('untrusted executable roots cannot select a relative, UNC or malformed reg.exe path', async () => {
  for (const systemRoot of ['relative', '\\\\server\\share', 'C:\\Windows\n' + secret, 'C:\\Win"dows']) {
    await assert.rejects(readSystemProxy({ platform: 'win32', systemRoot, execute: async () => { throw Error('must not execute'); } }), safeError('INVALID_SETTINGS'));
  }
});
