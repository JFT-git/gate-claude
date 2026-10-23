"""Offline integration tests. Python is needed only for development, not by the app."""
import pathlib
import socket
import struct
import subprocess
import threading

root = pathlib.Path(__file__).resolve().parents[1]

def exact(conn, n):
    out = b""
    while len(out) < n:
        chunk = conn.recv(n - len(out))
        if not chunk:
            raise EOFError()
        out += chunk
    return out

seen = []

def serve(conn):
    try:
        conn.settimeout(10)
        version, count = exact(conn, 2)
        assert version == 5 and 2 in exact(conn, count)
        conn.sendall(b"\x05\x02")
        assert exact(conn, 1) == b"\x01"
        user = exact(conn, exact(conn, 1)[0])
        password = exact(conn, exact(conn, 1)[0])
        if user != b"user" or password != b"secret":
            conn.sendall(b"\x01\x01")
            return
        conn.sendall(b"\x01\x00")
        assert exact(conn, 4) == b"\x05\x01\x00\x03"
        host = exact(conn, exact(conn, 1)[0]).decode()
        port = struct.unpack("!H", exact(conn, 2))[0]
        seen.append((host, port))
        if host == "refused.test":
            conn.sendall(b"\x05\x05\x00\x01\x7f\x00\x00\x01\x00\x50")
            return
        if host == "aborted-before-reply.test":
            return
        conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
        if host == "reset.test":
            request = b""
            while b"\r\n\r\n" not in request:
                request += exact(conn, 1)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            return
        if host == "hold.test":
            while conn.recv(1024):
                pass
        else:
            request = b""
            while b"\r\n\r\n" not in request:
                request += exact(conn, 1)
            body = (f"h={host}\nip=203.0.113.7\nloc=DE\n" if request.startswith(b"GET /cdn-cgi/trace ") else f"ok:{host}").encode()
            conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    except (OSError, EOFError):
        pass
    finally:
        conn.close()

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    def accept():
        while True:
            try:
                connection, _ = listener.accept()
                threading.Thread(target=serve, args=(connection,), daemon=True).start()
            except OSError:
                return
    threading.Thread(target=accept, daemon=True).start()
    result = subprocess.run([str(root / ".build/RelayTests"), str(port)], timeout=60)
    assert result.returncode == 0
    assert seen.count(("destination.test", 443)) == 1, seen
    assert ("ipwho.is", 443) in seen
    print("PASS upstream fixture confirms remote DNS names and no pre-verification escape", flush=True)
