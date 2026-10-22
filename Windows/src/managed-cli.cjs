"use strict";
// The OS broker is the network boundary. This module only adapts the vendor SDK
// to that broker; an approved path/hash is revalidated natively before execution.
const path = require('node:path').win32;
const { ChildProcess } = require('node:child_process');
const MAX_PACKET_BYTES = 262144;
const FAILURE = 'Guard could not launch the protected Claude Code process.';
const WORKSPACE_FAILURE = 'Откройте проект в постоянной рабочей папке Guard.';
const PROXY_NAME = /^(?:https?|all|no)_proxy$/i;
const TOOL_ENV = new Set(['PATH','GIT_EXEC_PATH','GIT_TEMPLATE_DIR','GIT_CONFIG_NOSYSTEM','CLAUDE_CODE_USE_POWERSHELL_TOOL','PSMODULEPATH','POWERSHELL_TELEMETRY_OPTOUT','POWERSHELL_UPDATECHECK']);
// Desktop's Sentry propagator adds this optional SDK carrier. Its hyphenated
// name is outside the native broker's environment contract.
const PRIVATE_ENV = /^(?:PROXY_GUARD_|GATE_|ELECTRON_|CLAUDE_CDP_AUTH$|NODE_OPTIONS$|SSLKEYLOGFILE$|SHELL$|CLAUDE_CODE_GIT_BASH_PATH$|GIT_CEILING_DIRECTORIES$|SENTRY-TRACE$)/i;
let installed;
function denied() { const error = Error(FAILURE); error.code = 'ERR_GUARD_CODE_DENIED'; return error; }
function ownObject(value) { return value && typeof value === 'object' && !Array.isArray(value) && [null, Object.prototype].includes(Object.getPrototypeOf(value)); }
function text(value, max = 32767) { return typeof value === 'string' && value.length <= max && !value.includes('\0'); }
function absolute(value, executable = false) {
  if (!text(value) || !/^[a-z]:\\/i.test(value) || /[\x00-\x1f<>"|?*]/.test(value) || value.slice(2).includes(':')) throw denied();
  if (value.includes('/') || path.normalize(value) !== value || value.split('\\').slice(1).some(part => !part || /[. ]$/.test(part) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) throw denied();
  if (executable && !/\.exe$/i.test(value)) throw denied();
  return value;
}
function relayURL(value) {
  if (!text(value, 128)) throw denied();
  const url = new URL(value);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || Number(url.port) < 1 || Number(url.port) > 65535 || url.username || url.password || url.pathname !== '/' || url.search || url.hash || !/^http:\/\/127\.0\.0\.1:[1-9]\d{0,4}\/?$/.test(value)) throw denied();
  return 'http://127.0.0.1:' + Number(url.port);
}
function configCopy(input) {
  if (!ownObject(input) || process.platform !== 'win32') throw denied();
  const approved = input.approved;
  if (!Array.isArray(approved) || approved.length < 1 || approved.length > 16) throw denied();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(input.containerName || '') || !/^S-1-15-2-(?:\d+-){6}\d+$/.test(input.containerSid || '')) throw denied();
  const output = { hostPath: absolute(input.hostPath, true), containerName: input.containerName, containerSid: input.containerSid,
    relayURL: relayURL(input.relayURL), stateRoot: absolute(input.stateRoot), runtimeExecutable: absolute(input.runtimeExecutable, true), gatePipe: input.gatePipe, gateToken: input.gateToken, codeJobName: input.codeJobName, approved: [] };
  if (output.stateRoot.includes(';')) throw denied(); // Git's Windows path-list separator has no quoting escape.
  output.workspaceRoot = absolute(input.workspaceRoot === undefined ? path.join(output.stateRoot, 'Workspace') : input.workspaceRoot);
  if (output.workspaceRoot.toLowerCase() !== path.join(output.stateRoot, 'Workspace').toLowerCase() || !/^Global\\gate-code-job-[a-f0-9]{32}$/.test(output.codeJobName || '')) throw denied();
  if (!/^\\\\\.\\pipe\\gate-claude-code-[a-f0-9]{32}$/.test(output.gatePipe || '') || !/^[a-f0-9]{64}$/.test(output.gateToken || '')) throw denied();
  if (output.runtimeExecutable.toLowerCase() !== absolute(process.execPath, true).toLowerCase()) throw denied();
  const seen = new Set();
  for (const item of approved) {
    if (!ownObject(item) || !/^[a-f0-9]{64}$/.test(item.sha256 || '')) throw denied();
    const file = absolute(item.path, true), key = file.toLowerCase();
    if (path.basename(file).toLowerCase() !== 'claude.exe' || seen.has(key) || key === output.hostPath.toLowerCase()) throw denied();
    const requestedPath = item.requestedPath === undefined ? undefined : absolute(item.requestedPath, true);
    if (requestedPath && (path.basename(requestedPath).toLowerCase() !== 'claude.exe' || seen.has(requestedPath.toLowerCase()))) throw denied();
    seen.add(key); if (requestedPath) seen.add(requestedPath.toLowerCase());
    output.approved.push(Object.freeze({ path: file, sha256: item.sha256, ...(requestedPath ? { requestedPath } : {}) }));
  }
  const environment = {};
  if (input.tools !== undefined) {
    if (!ownObject(input.tools) || !ownObject(input.tools.environment)) throw denied();
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(input.tools.environment))) {
      if (!TOOL_ENV.has(key.toUpperCase()) || !('value' in descriptor) || !text(descriptor.value) || /[\r\n]/.test(descriptor.value) || Object.keys(environment).some(name => name.toUpperCase() === key.toUpperCase())) throw denied();
      environment[key] = descriptor.value;
    }
  }
  output.tools = Object.freeze({ environment: Object.freeze(environment) });
  Object.freeze(output.approved); return Object.freeze(output);
}
function initCodeTransport(config, spawnBroker) {
  try {
    if (typeof spawnBroker !== 'function') throw denied();
    const code = configCopy(config), fingerprint = JSON.stringify(code);
    if (installed) {
      if (installed.fingerprint !== fingerprint || installed.spawnBroker !== spawnBroker) throw denied();
      return;
    }
    installed = Object.freeze({ code, spawnBroker, fingerprint });
  } catch { throw denied(); }
}
function proxyEnv(env, lowerCase = false) {
  if (!ownObject(env)) throw denied();
  const result = {}, names = new Map(); let characters = 1;
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(env))) {
    if (!('value' in descriptor) || !text(key, 256) || !key || key.includes('=') || /[\x00-\x1f]/.test(key) || !text(descriptor.value)) throw denied();
    if (/^CLAUDE_CODE_(?:PROXY_RESOLVES_HOSTS|USE_POWERSHELL_TOOL)$/i.test(key) || PROXY_NAME.test(key) || PRIVATE_ENV.test(key) || Object.keys(installed.code.tools.environment).some(name => name.toUpperCase() === key.toUpperCase())) continue;
    // Windows env names are case-insensitive. Preserve one deterministic spelling.
    const previous = names.get(key.toUpperCase()); if (previous) delete result[previous];
    names.set(key.toUpperCase(), key); Object.defineProperty(result, key, { value: descriptor.value, writable: true, enumerable: true, configurable: true });
  }
  Object.assign(result, installed.code.tools.environment);
  // An empty Workspace must not make Git discover repositories above the
  // readable state tree. AppContainer deliberately cannot inspect that parent.
  result.GIT_CEILING_DIRECTORIES = installed.code.stateRoot;
  for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']) result[key] = installed.code.relayURL;
  result.NO_PROXY = '';
  result.CLAUDE_CODE_PROXY_RESOLVES_HOSTS = '1';
  result.CLAUDE_CODE_USE_POWERSHELL_TOOL = '1';
  if (lowerCase) for (const key of ['http_proxy', 'https_proxy', 'all_proxy']) result[key] = installed.code.relayURL;
  if (lowerCase) result.no_proxy = '';
  for (const [key, value] of Object.entries(result)) characters += key.length + value.length + 2;
  if (Object.keys(result).length > 256 || characters > 32767) throw denied();
  return result;
}
function jsonCopy(value, depth = 0, seen = new Set()) {
  if (depth > 32) throw denied();
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value))) return value;
  if ((!Array.isArray(value) && !ownObject(value)) || seen.has(value)) throw denied();
  seen.add(value); const output = Array.isArray(value) ? [] : {};
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (Array.isArray(value) && key === 'length') continue;
    if (!('value' in descriptor)) throw denied();
    Object.defineProperty(output, key, { value: jsonCopy(descriptor.value, depth + 1, seen), enumerable: true, writable: true, configurable: true });
  }
  seen.delete(value); return output;
}
function mergeManagedSettings(settings) {
  try {
    if (!installed || (settings != null && !ownObject(settings))) throw denied();
    const result = settings == null ? {} : jsonCopy(settings);
    result.env = proxyEnv(result.env == null ? {} : result.env, true);
    // Stock MSYS Git Bash cannot initialize inside this AppContainer. Use the
    // pinned CLI's native Windows PowerShell tool without weakening the token.
    if (result.permissions == null) result.permissions = {};
    if (!ownObject(result.permissions)) throw denied();
    if (result.permissions.deny == null) result.permissions.deny = [];
    if (!Array.isArray(result.permissions.deny) || !result.permissions.deny.every(value => text(value, 16384))) throw denied();
    if (!result.permissions.deny.includes('Bash')) result.permissions.deny.push('Bash');
    result.defaultShell = 'powershell';
    if (Buffer.byteLength(JSON.stringify(result)) > MAX_PACKET_BYTES / 2) throw denied();
    return result;
  } catch { throw denied(); }
}
function brokerEnvironment() {
  const output = {};
  for (const wanted of ['SystemRoot', 'WINDIR', 'SystemDrive', 'TEMP', 'TMP']) {
    const name = Object.keys(process.env).find(key => key.toLowerCase() === wanted.toLowerCase());
    if (name && text(process.env[name])) output[wanted] = process.env[name];
  }
  return output;
}
function configureLocalSessions(api) {
  if (!installed || !ownObject(api) || typeof api.start !== 'function') throw denied();
  const workspace = installed.code.workspaceRoot;
  return { ...api,
    start(info) {
      if (!ownObject(info)) throw denied();
      const descriptors = Object.getOwnPropertyDescriptors(info);
      if (Object.values(descriptors).some(item => !('value' in item))) throw denied();
      // Resolve "No folder" before the vendor creates session metadata or builds
      // its SDK options. Redirecting only the final spawn would leave the model,
      // transcript and file tools pointing at the user's home directory.
      if (info.remoteTarget != null || info.sshConfig != null) throw denied();
      const requested = info.cwd;
      if (requested !== undefined && !text(requested)) throw denied();
      const cwd = requested === undefined || !requested.trim() ? workspace : absolute(requested);
      if (cwd.toLowerCase() !== workspace.toLowerCase() && !cwd.toLowerCase().startsWith(workspace.toLowerCase() + '\\')) {
        const error = Error(WORKSPACE_FAILURE); error.code = 'ERR_GUARD_CODE_WORKSPACE_REQUIRED'; throw error;
      }
      return api.start.call(api, { ...info, cwd });
    },
    // Optional vendor prewarms create disposable scratch directories outside the
    // permanent workspace. Decline them; normal starts above use the real folder
    // and never label it as scratch data that the vendor may later delete.
    prewarmFolderless: async () => ({ refusedReason: 'unavailable' }),
    prewarmLocal: async () => ({ refusedReason: 'unavailable' }),
    createScratchWorkspace: async () => ({ refusedReason: 'unavailable' })
  };
}
function spawnManaged(options) {
  let child;
  try {
    if (!installed || !ownObject(options)) throw denied();
    const code = installed.code, executable = absolute(options.command, true), match = code.approved.find(item => item.path.toLowerCase() === executable.toLowerCase() || item.requestedPath?.toLowerCase() === executable.toLowerCase());
    if (!match || !Array.isArray(options.args) || options.args.length > 256 || !options.args.every(value => text(value, 16384)) || options.args.reduce((total, value) => total + value.length + 3, executable.length + 2) > 32767) throw denied();
    if (options.signal?.aborted) throw denied();
    let cwd = code.workspaceRoot;
    if (!(options.args.length === 1 && options.args[0] === '--version') && options.cwd !== undefined) {
      const canonicalCwd = absolute(options.cwd), requestedCwd = canonicalCwd.toLowerCase(), workspace = code.workspaceRoot.toLowerCase();
      if (requestedCwd === workspace || requestedCwd.startsWith(workspace + '\\')) cwd = canonicalCwd;
      else if (![code.stateRoot, path.dirname(code.runtimeExecutable)].some(value => value.toLowerCase() === requestedCwd)) {
        const error = Error(WORKSPACE_FAILURE); error.code = 'ERR_GUARD_CODE_WORKSPACE_REQUIRED'; throw error;
      }
    }
    const packet = { version: 1, containerName: code.containerName, containerSid: code.containerSid, relayURL: code.relayURL, stateRoot: code.stateRoot,
      gatePipe: code.gatePipe, gateToken: code.gateToken, codeJobName: code.codeJobName, executable: match.path, executableSHA256: match.sha256, args: options.args.slice(), cwd, env: proxyEnv(options.env),
      ownerPid: process.pid, ownerExecutable: code.runtimeExecutable };
    const data = Buffer.from(JSON.stringify(packet)); if (data.length < 1 || data.length > MAX_PACKET_BYTES) throw denied();
    const header = Buffer.allocUnsafe(4); header.writeUInt32LE(data.length);
    child = installed.spawnBroker(code.hostPath, ['--managed'], { cwd: code.stateRoot, env: brokerEnvironment(), stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, signal: options.signal });
    if (!(child instanceof ChildProcess) || !Number.isSafeInteger(child.pid) || child.pid < 1 || !child.stdin?.write || !child.stdout || !child.stderr) throw denied();
    // Queue the complete header before returning. Subsequent SDK writes stay FIFO
    // even when this first write applies backpressure; no SDK bytes are consumed.
    child.stdin.once('error', () => { try { child.kill(); } catch {} });
    child.stdin.write(Buffer.concat([header, data]), error => { if (error) { try { child.kill(); } catch {} } });
    return child;
  } catch (error) {
    try { child?.kill(); } catch {}
    if (error?.code === 'ERR_GUARD_CODE_WORKSPACE_REQUIRED') throw error;
    throw denied();
  }
}
function resolveManagedCliPath(requestedPath) {
  try {
    if (!installed) throw denied();
    const requested = absolute(requestedPath, true).toLowerCase();
    const match = installed.code.approved.find(item => item.requestedPath?.toLowerCase() === requested);
    if (!match) throw denied();
    return match.path;
  } catch { throw denied(); }
}
function runManagedCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    let child, completed = false, timer, killTimer, failure, bytes = 0;
    const stdout = [], stderr = [], maxBuffer = 10 * 1024 * 1024;
    const result = code => ({ stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8'), code,
      pid: child?.pid, stdoutBuffer: Buffer.concat(stdout), stderrBuffer: Buffer.concat(stderr) });
    function finish(error, code = null) {
      if (completed) return; completed = true; clearTimeout(timer); clearTimeout(killTimer);
      const value = result(code);
      if (error) { error.result = value; reject(error); }
      else if (code !== 0 && options.ignoreExitCode !== true) { const failed = Error(FAILURE); failed.code = 'ERR_GUARD_CODE_EXIT'; failed.result = value; reject(failed); }
      else resolve(value);
    }
    function fail(code) {
      if (completed || failure) return;
      failure = Error(FAILURE); failure.code = code;
      try { child?.kill(); } catch {}
      // Kernel jobs own descendants even if the SDK stops consuming a pipe.
      killTimer = setTimeout(() => finish(failure), 2000); killTimer.unref?.();
    }
    try {
      if (!ownObject(options) || options.timeout !== undefined && (!Number.isSafeInteger(options.timeout) || options.timeout < 1 || options.timeout > 600000) || options.stdin !== undefined && typeof options.stdin !== 'string' && !Buffer.isBuffer(options.stdin)) throw denied();
      if (options.stdin !== undefined && Buffer.byteLength(options.stdin) > maxBuffer) throw denied();
      child = spawnManaged({ command, args, cwd: options.cwd, env: options.env, signal: options.signal });
      for (const [stream, chunks] of [[child.stdout, stdout], [child.stderr, stderr]]) {
        stream.on('data', data => { if (completed || failure) return; const chunk = Buffer.from(data); bytes += chunk.length; if (bytes > maxBuffer) { fail('ERR_GUARD_CODE_MAXBUFFER'); return; } chunks.push(chunk); });
        stream.once('error', () => fail('ERR_GUARD_CODE_PIPE'));
      }
      child.once('error', () => fail('ERR_GUARD_CODE_SPAWN'));
      child.once('close', code => finish(failure, failure ? null : Number.isInteger(code) ? code : null));
      child.stdin.once('error', () => fail('ERR_GUARD_CODE_PIPE'));
      timer = setTimeout(() => fail('ETIMEDOUT'), options.timeout ?? 30000); timer.unref?.();
      child.stdin.end(options.stdin);
    } catch (error) { try { child?.kill(); } catch {} finish(error?.code ? error : denied()); }
  });
}
module.exports = { initCodeTransport, spawnManaged, runManagedCommand, resolveManagedCliPath, mergeManagedSettings, configureLocalSessions, MAX_PACKET_BYTES };
