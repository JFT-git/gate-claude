'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { packager } = require('@electron/packager');
const { validatePolicy, safeFilesystem, MAX_POLICY_BYTES } = require('../src/code-tools.cjs');
const { sha256, LIMITS } = require('../src/portable-zip.cjs');

async function main() {
  const root = path.resolve(__dirname, '..'), project = path.resolve(root, '..');
  const args = process.argv.slice(2), argument = name => args[args.indexOf(name) + 1];
  const platform = args.includes('--platform') ? argument('--platform') : 'win32';
  const arch = args.includes('--arch') ? argument('--arch') : 'x64';
  const stage = path.join(root, '.stage');
  await fs.rm(stage, { recursive: true, force: true }); await fs.mkdir(stage, { recursive: true });
  const pkg = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
  const electronVersion = pkg.devDependencies.electron;
  delete pkg.devDependencies; delete pkg.scripts; delete pkg.engines; delete pkg.private;
  await fs.writeFile(path.join(stage, 'package.json'), JSON.stringify(pkg, null, 2));
  await fs.cp(path.join(root, 'src'), path.join(stage, 'src'), { recursive: true });
  await fs.mkdir(path.join(stage, 'resources'), { recursive: true });
  await fs.copyFile(path.join(project, 'Resources', 'RuntimeBootstrap.cjs'), path.join(stage, 'resources', 'RuntimeBootstrap.cjs'));
  await fs.copyFile(path.join(project, 'LICENSE'), path.join(stage, 'LICENSE'));
  const extraResource = [path.join(stage, 'resources', 'RuntimeBootstrap.cjs')];
  if (platform === 'win32') {
    const helper = path.join(stage, 'resources', 'GuardHost.exe');
    if (process.platform === 'win32') {
      const csc = path.join(process.env.SystemRoot || 'C:\\Windows', 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
      execFileSync(csc, ['/nologo', '/optimize+', '/platform:anycpu', '/target:exe', '/out:' + helper, path.join(root, 'native', 'GuardHost.cs')], { stdio: 'inherit', windowsHide: true });
    } else {
      if (!args.includes('--host')) throw Error('Cross-build requires --host /absolute/path/to/GuardHost.exe compiled from native/GuardHost.cs on Windows.');
      await fs.copyFile(path.resolve(argument('--host')), helper);
    }
    extraResource.push(helper);
    const fence = path.join(stage, 'resources', 'NetworkFence.exe');
    if (process.platform === 'win32') {
      const csc = path.join(process.env.SystemRoot || 'C:\\Windows', 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
      execFileSync(csc, ['/nologo', '/optimize+', '/platform:x64', '/target:exe', '/out:' + fence, ...['NetworkFence.cs', 'CodeNetworkFence.cs', 'CodeFenceSession.cs'].map(file => path.join(root, 'native', file))], { stdio: 'inherit', windowsHide: true });
    } else {
      if (!args.includes('--fence')) throw Error('Cross-build requires --fence /absolute/path/to/NetworkFence.exe compiled from native/NetworkFence.cs.');
      await fs.copyFile(path.resolve(argument('--fence')), fence);
    }
    extraResource.push(fence);
    const codeHost = path.join(stage, 'resources', 'CodeHost.exe');
    if (process.platform === 'win32') {
      const csc = path.join(process.env.SystemRoot || 'C:\\Windows', 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
      execFileSync(csc, ['/nologo', '/optimize+', '/platform:x64', '/target:exe', '/r:System.Web.Extensions.dll', '/out:' + codeHost, path.join(root, 'native', 'CodeHost.cs')], { stdio: 'inherit', windowsHide: true });
    } else {
      if (!args.includes('--code-host')) throw Error('Cross-build requires --code-host /absolute/path/to/CodeHost.exe compiled from native/CodeHost.cs.');
      await fs.copyFile(path.resolve(argument('--code-host')), codeHost);
    }
    extraResource.push(codeHost);
    if (args.includes('--code-tools-dir')) {
      const toolsInput = path.resolve(argument('--code-tools-dir')), safe = safeFilesystem(fs);
      await safe.inspect(toolsInput, true);
      const policyBytes = await safe.read(path.join(toolsInput, 'code-tools-policy.json'), MAX_POLICY_BYTES);
      const policy = validatePolicy(JSON.parse(policyBytes.toString('utf8')));
      const toolsOutput = path.join(stage, 'resources', 'CodeTools');
      await fs.mkdir(toolsOutput);
      for (const tool of policy.tools) {
        const bytes = await safe.read(path.join(toolsInput, tool.archiveName), LIMITS.archive);
        if (bytes.length !== tool.archiveSize || sha256(bytes) !== tool.archiveSHA256) throw Error('CodeTools sidecar checksum mismatch.');
        await fs.writeFile(path.join(toolsOutput, tool.archiveName), bytes, { flag: 'wx' });
      }
      const policyOutput = path.join(stage, 'resources', 'code-tools-policy.json');
      await fs.writeFile(policyOutput, policyBytes, { flag: 'wx' });
      extraResource.push(toolsOutput, policyOutput);
    }
  }
  // Runtime dependencies are Node built-ins; no profiles, test hooks or Claude binaries are staged.
  const results = await packager({ dir: stage, name: 'Claude Proxy Guard', platform, arch, electronVersion,
    out: path.join(root, 'dist'), overwrite: true, asar: true, prune: false, extraResource,
    appBundleId: 'local.proxyguard.gate-claude', appCopyright: 'Copyright 2026 gate-claude contributors',
    win32metadata: { CompanyName: 'gate-claude contributors', FileDescription: 'Claude Proxy Guard', ProductName: 'Claude Proxy Guard', OriginalFilename: 'Claude Proxy Guard.exe' },
    ignore: [/^\/resources\//], appVersion: pkg.version });
  for (const result of results) {
    await fs.copyFile(path.join(root, 'README.md'), path.join(result, 'README.ru.md'));
    await fs.copyFile(path.join(project, 'LICENSE'), path.join(result, 'GUARD-LICENSE.txt'));
    console.log(result);
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
