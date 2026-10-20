"""Opt-in, offline test of the user's installed Claude in a private sandboxed copy.

No personal profile, Keychain, public network, trust store, or TCC grants are used.
The pinned fixture certificate exists only in the test bootstrap. The app's usual
claude.ai origin is routed to loopback, so its navigation allowlist remains intact.
Usage: python3 Tests/installed_e2e.py --work-dir /absolute/scratch/directory
"""
import argparse
import hashlib
import http.server
import json
import os
import pathlib
import select
import socket
import ssl
import struct
import subprocess
import threading
import time


def exact(connection, count):
    data = b""
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise EOFError()
        data += chunk
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    project = pathlib.Path(__file__).resolve().parents[1]
    scratch = args.work_dir.resolve()
    scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert, key = scratch / "fixture-lifecycle.crt", scratch / "fixture-lifecycle.key"
    if not cert.exists() or subprocess.run(["/usr/bin/openssl", "x509", "-checkend", "60", "-noout", "-in", str(cert)],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=claude.ai", "-addext", "subjectAltName=DNS:claude.ai,DNS:challenges.cloudflare.com",
                        "-keyout", str(key), "-out", str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest().upper()
    fingerprint = ":".join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2))
    bootstrap = scratch / "test-bootstrap.cjs"
    bootstrap.write_text((project / "Resources/RuntimeBootstrap.cjs").read_text() + "\n" + r"""
// Test fixture support, never included in the distributed application resource.
const testFingerprint = FINGERPRINT;
function pinFixture(s) {
  s.setCertificateVerifyProc((request, callback) => {
    if (!['claude.ai', 'challenges.cloudflare.com'].includes(request.hostname)) return callback(-3);
    try {
      const actual = new (require('node:crypto').X509Certificate)(request.certificate.data).fingerprint256;
      callback(actual === testFingerprint ? 0 : -2);
    } catch { callback(-2); }
  });
}
app.on('session-created', pinFixture);
app.whenReady().then(() => pinFixture(electron.session.defaultSession));
let testWindowsDone = 0;
const productionCommand = command;
command = async message => {
  if (message.method === 'ProxyGuard.testSharedLocale') {
    const target = sessions.get(message.params.targetSession);
    if (!target || target.child) throw Error('Root fixture target required');
    const dbg = target.wc.debugger;
    await dbg.sendCommand('Emulation.setLocaleOverride', { locale: '' });
    const info = await dbg.sendCommand('Target.getTargetInfo');
    const attach = () => dbg.sendCommand('Target.attachToTarget', { targetId: info.targetInfo.targetId, flatten: true });
    const first = await attach();
    await dbg.sendCommand('Emulation.setLocaleOverride', { locale: cfg.language.replaceAll('-', '_') }, first.sessionId);
    let conflict;
    try { await dbg.sendCommand('Emulation.setLocaleOverride', { locale: cfg.language.replaceAll('-', '_') }); }
    catch (error) { conflict = error.message; }
    if (!conflict || !conflict.includes('Another locale override is already in effect')) throw Error('Native locale conflict was not reproduced');
    const inherited = await ensureRendererLocale(target.wc);
    const second = await attach();
    emit({ id: message.id, result: { conflict, inherited, firstSession: first.sessionId, secondSession: second.sessionId } }); return;
  }
  if (message.method === 'ProxyGuard.testExit') {
    emit({ id: message.id, result: {} }); setTimeout(() => process.kill(process.pid, 'SIGKILL'), 20); return;
  }
  if (message.method === 'ProxyGuard.testWindowLifecycle') {
    for (const delay of [1, 75]) {
      const window = new electron.BrowserWindow({ show: false });
      window.loadURL('https://claude.ai/__guard_test__/aux').catch(() => {});
      setTimeout(() => { if (!window.isDestroyed()) window.destroy(); testWindowsDone++; }, delay);
    }
    emit({ id: message.id, result: {} }); return;
  }
  if (message.method === 'ProxyGuard.testWindowStatus') {
    emit({ id: message.id, result: { completed: testWindowsDone } }); return;
  }
  return productionCommand(message);
};
""".replace("FINGERPRINT", json.dumps(fingerprint)))
    home = pathlib.Path.home()
    tmp = pathlib.Path(os.environ.get("TMPDIR", "/tmp")).resolve()
    policy = ["(version 1)", "(allow default)", "(deny network*)",
              '(allow network-outbound (remote ip "localhost:*"))', "(deny file-write*)"]
    for allowed in (scratch, pathlib.Path("/private/tmp"), tmp):
        policy.append("(allow file-write* (subpath " + json.dumps(str(allowed)) + "))")
    policy.append('(allow file-write* (literal "/dev/null"))')
    for denied in (home / "Library/Application Support/Claude", home / ".claude", home / ".claude.json",
                   home / "Library/Keychains", home / "Library/Cookies",
                   home / "Library/HTTPStorages/com.anthropic.claudefordesktop"):
        policy.append("(deny file-read* (subpath " + json.dumps(str(denied)) + "))")
    policy.append(r'(deny mach-lookup (global-name-regex "^com\\.apple\\.securityd.*"))')
    sandbox = scratch / "claude.sb"
    sandbox.write_text("\n".join(policy) + "\n")
    swift_sources = sorted(str(p) for p in (project / "Source").glob("*.swift"))
    helper, executable = scratch / "GuardHost", scratch / "InstalledE2E"
    subprocess.run(["xcrun", "clang", "-O2", "-DGUARD_HOST_TEST", str(project / "Source/GuardHost.c"), "-o", str(helper)], check=True)
    native_arch = subprocess.check_output(["/usr/bin/uname", "-m"], text=True).strip()
    subprocess.run(["xcrun", "swiftc", "-swift-version", "5", "-target", native_arch + "-apple-macosx13.0",
                    "-module-cache-path", str(scratch / "ModuleCache"), "-D", "PREVIEW", "-D", "GUARD_E2E", "-parse-as-library",
                    "-framework", "SwiftUI", "-framework", "AppKit", "-framework", "Network", *swift_sources,
                    str(project / "Tests/InstalledE2E.swift"), "-o", str(executable)], check=True)
    stream_closed = threading.Event()
    requests, destinations = [], []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                # The kill-switch deliberately destroys live and idle TLS sockets.
                pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append({"path": self.path, "headers": dict(self.headers), "body": json.loads(body)})
            response = json.dumps({"marker": "guard-response-ok", "received": json.loads(body)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response)

        def do_GET(self):
            if self.path.startswith('/__guard_test__/frame'):
                body = b'''<!doctype html><meta charset=utf-8><script>
                parent.postMessage({guardFixture:true,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,
                language:navigator.language,locale:Intl.DateTimeFormat().resolvedOptions().locale},'https://claude.ai');
                </script>'''
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/__guard_test__/stream":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                try:
                    for index in range(150):
                        self.wfile.write(("data: stream-" + str(index) + "\n\n").encode())
                        self.wfile.flush()
                        time.sleep(0.1)
                except (OSError, ssl.SSLError):
                    stream_closed.set()
                return
            body = b"<!doctype html><meta charset=utf-8><title>Local Guard fixture</title>Local synthetic traffic only"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()

    def socks(connection):
        upstream = None
        try:
            connection.settimeout(15)
            version, count = exact(connection, 2)
            methods = exact(connection, count)
            assert version == 5 and 0 in methods
            connection.sendall(b"\x05\x00")
            version, operation, _, address_type = exact(connection, 4)
            assert version == 5 and operation == 1
            if address_type == 3:
                host = exact(connection, exact(connection, 1)[0]).decode()
            elif address_type == 1:
                host = socket.inet_ntop(socket.AF_INET, exact(connection, 4))
            else:
                host = socket.inet_ntop(socket.AF_INET6, exact(connection, 16))
            port = struct.unpack("!H", exact(connection, 2))[0]
            destinations.append((host, port))
            if host not in ['claude.ai', 'challenges.cloudflare.com'] or port != 443:
                connection.sendall(b"\x05\x04\x00\x01\x7f\x00\x00\x01\x00\x00")
                return
            upstream = socket.create_connection(("127.0.0.1", server.server_port), timeout=15)
            connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb")
            while True:
                readable, _, _ = select.select([connection, upstream], [], [], 15)
                if not readable:
                    return
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is connection else connection).sendall(data)
        except (OSError, EOFError, AssertionError):
            pass
        finally:
            connection.close()
            if upstream:
                upstream.close()

    def accept():
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=socks, args=(connection,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    proof_path = scratch / "proof.json"
    try:
        result = subprocess.run([str(executable), str(scratch), str(listener.getsockname()[1]), str(bootstrap),
                                 str(sandbox), str(helper), str(proof_path)], timeout=120)
        if result.returncode:
            (scratch / "fixture-failure.json").write_text(json.dumps({"requests": requests, "destinations": destinations}, indent=2))
            raise SystemExit(result.returncode)
        assert stream_closed.wait(3), "TLS stream stayed open after IP change"
        capture = next(record for record in requests if record["path"] == "/__guard_test__/capture")
        assert capture["body"] == {"timezone": "Europe/Amsterdam", "language": "en-US", "locale": "en-US"}, capture
        assert {k.lower(): v for k, v in capture["headers"].items()}.get("accept-language") == "en-US", capture
        assert ("claude.ai", 443) in destinations, destinations
        assert ("challenges.cloudflare.com", 443) in destinations, destinations
        proof = json.loads(proof_path.read_text())
        proof["fixture"] = {"serverReceived": capture, "activeTLSStreamClosed": True,
                            "socksForwardedOnly": "claude.ai / challenges.cloudflare.com -> loopback TLS fixture; no real Anthropic or Cloudflare server contacted"}
        proof_path.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n")
        print("PASS fixture: Accept-Language=en-US; open TLS stream closed; no public connections forwarded", flush=True)
        print("Proof: " + str(proof_path), flush=True)
    finally:
        listener.close()
        server.shutdown()


if __name__ == "__main__":
    main()
