'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { performance } = require('node:perf_hooks');
const { promisify } = require('node:util');
const run = promisify(require('node:child_process').execFile);
const { powershell } = require('../src/windows.cjs');
const helper = process.env.GATE_HOST || path.resolve(__dirname, '..', 'dist', 'Claude Proxy Guard-win32-x64', 'resources', 'GuardHost.exe');
const windowsOnly = { skip: process.platform !== 'win32' };

test('native route identities validate ABI, select both default and VPN split routes, and ignore aging fields', { ...windowsOnly, timeout: 25000 }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-route-unit-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const fixture = path.join(root, 'RouteFixture.cs'), executable = path.join(root, 'RouteFixture.exe');
  await fs.writeFile(fixture, `
using System;
using System.Collections.Generic;
using System.Net;
internal static class RouteFixture {
  static void Check(bool ok) { if (!ok) throw new Exception("Synthetic route assertion failed."); }
  static GuardHost.SOCKADDR_INET Address(string text) {
    var bytes=IPAddress.Parse(text).GetAddressBytes();var value=new GuardHost.SOCKADDR_INET();
    value.family=(ushort)(bytes.Length==4?2:23);
    if(bytes.Length==4)value.data0=BitConverter.ToUInt32(bytes,0);
    else{value.data1=BitConverter.ToUInt32(bytes,0);value.data2=BitConverter.ToUInt32(bytes,4);value.data3=BitConverter.ToUInt32(bytes,8);value.data4=BitConverter.ToUInt32(bytes,12);}
    return value;
  }
  static GuardHost.MIB_IPFORWARD_ROW2 Row(string prefix,byte length,string hop) {
    var row=new GuardHost.MIB_IPFORWARD_ROW2();row.index=7;row.metric=42;
    row.destination.prefix=Address(prefix);row.destination.length=length;row.nextHop=Address(hop);return row;
  }
  public static int Main() {
    GuardHost.ValidateRouteLayout();
    foreach(var prefix in new[]{"0.0.0.0/0","0.0.0.0/1","128.0.0.0/1","::/0","::/1","8000::/1"}) {
      var parts=prefix.Split('/');string hop=parts[0].Contains(":")?"fe80::1234":"192.0.2.1";
      var row=Row(parts[0],byte.Parse(parts[1]),hop);var identity=GuardHost.RouteIdentity(row);
      Check(identity=="7|"+hop+"|42|"+prefix);
      row.age=99;row.validLifetime=123;row.preferredLifetime=17;row.protocol=3;row.origin=2;row.nextHop.scope=7;
      Check(GuardHost.RouteIdentity(row)==identity);
      row.metric++;Check(GuardHost.RouteIdentity(row)!=identity);
    }
    Check(GuardHost.RouteIdentity(Row("192.0.2.0",24,"192.0.2.1"))==null);
    Check(GuardHost.RouteIdentity(Row("2001:db8::",32,"fe80::1234"))==null);
    var invalid=Row("0.0.0.0",0,"192.0.2.1");invalid.nextHop.family=0;
    bool rejected=false;try{GuardHost.RouteIdentity(invalid);}catch(InvalidOperationException){rejected=true;}Check(rejected);
    Check(GuardHost.EncodeRouteSnapshot(new List<string>())=="[]");
    Check(GuardHost.EncodeRouteSnapshot(new List<string>{"9|::|0|::/0","1|0.0.0.0|0|0.0.0.0/0"})=="[\\"1|0.0.0.0|0|0.0.0.0/0\\",\\"9|::|0|::/0\\"]");
    Console.WriteLine("PASS");return 0;
  }
}
  `);
  const csc = path.join(process.env.SystemRoot, 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
  await run(csc, ['/nologo', '/platform:x64', '/target:exe', '/main:RouteFixture', '/out:' + executable,
    path.resolve(__dirname, '../native/GuardHost.cs'), fixture], { windowsHide: true, timeout: 15000 });
  const result = await run(executable, [], { windowsHide: true, timeout: 4000 });
  assert.equal(result.stdout.trim(), 'PASS');
});

test('native route snapshots match ActiveStore and ten consecutive calls stay within the four-second deadline', { ...windowsOnly, timeout: 65000 }, async t => {
  async function snapshot() {
    const started = performance.now();
    const result = await run(helper, ['--route-fingerprint'], { windowsHide: true, timeout: 4000, maxBuffer: 65536 });
    const elapsed = performance.now() - started;
    assert.equal(result.stderr, '');
    const entries = JSON.parse(result.stdout.trim());
    assert.ok(Array.isArray(entries) && entries.every(entry => typeof entry === 'string' && entry.length <= 256));
    assert.deepEqual(entries, [...entries].sort());
    return { entries, elapsed };
  }
  const first = await snapshot();
  // This reference is intentionally allowed to cold-load the NetTCPIP module.
  // Production uses only the native helper and keeps its four-second deadline.
  const reference = JSON.parse(await powershell(`ConvertTo-Json -InputObject @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1','::/0','::/1','8000::/1') } | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.InterfaceIndex,([Net.IPAddress]::Parse($_.NextHop).ToString().Split('%')[0]),$_.RouteMetric,$_.DestinationPrefix }) -Compress`, 30000));
  assert.deepEqual(first.entries, reference.sort());
  const durations = [first.elapsed];
  for (let index = 1; index < 10; index++) {
    const value = await snapshot(); assert.deepEqual(value.entries, first.entries);
    assert.ok(value.elapsed < 4000); durations.push(value.elapsed);
  }
  t.diagnostic('Native route snapshots (ms): ' + durations.map(value => Math.round(value)).join(', '));
});

test('route query mode rejects extra arguments without a successful empty snapshot', { ...windowsOnly, timeout: 10000 }, async () => {
  await assert.rejects(run(helper, ['--route-fingerprint', 'unexpected'], { windowsHide: true, timeout: 4000 }),
    error => error.code === 64 && error.stdout.trim() === '');
});
