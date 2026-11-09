#!/usr/bin/env python3
"""Verify the exact signed universal app, including Sparkle's nested bundle."""
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import zipfile

root = pathlib.Path(__file__).resolve().parents[2]
prefix = "Claude Proxy Guard.app/Contents/"
contents = root / "Claude Proxy Guard.app" / "Contents"
regular = {}
links = {}
modes = {}
directories = set()
for directory, dirnames, filenames in os.walk(contents, followlinks=False):
    for name in list(dirnames):
        path = pathlib.Path(directory) / name
        rel = path.relative_to(contents).as_posix()
        if path.is_symlink():
            links[rel] = os.readlink(path)
            dirnames.remove(name)
        else:
            directories.add(rel)
    for name in filenames:
        path = pathlib.Path(directory) / name
        rel = path.relative_to(contents).as_posix()
        if path.is_symlink():
            links[rel] = os.readlink(path)
        elif path.is_file():
            regular[rel] = path
            modes[rel] = stat.S_IMODE(path.stat().st_mode)
        else:
            raise SystemExit("Unexpected bundle object: " + rel)

required_links = {
    "Frameworks/Sparkle.framework/Autoupdate": "Versions/Current/Autoupdate",
    "Frameworks/Sparkle.framework/Headers": "Versions/Current/Headers",
    "Frameworks/Sparkle.framework/Modules": "Versions/Current/Modules",
    "Frameworks/Sparkle.framework/PrivateHeaders": "Versions/Current/PrivateHeaders",
    "Frameworks/Sparkle.framework/Resources": "Versions/Current/Resources",
    "Frameworks/Sparkle.framework/Sparkle": "Versions/Current/Sparkle",
    "Frameworks/Sparkle.framework/Updater.app": "Versions/Current/Updater.app",
    "Frameworks/Sparkle.framework/Versions/Current": "B",
    "Frameworks/Sparkle.framework/XPCServices": "Versions/Current/XPCServices",
}
executables = {
    "MacOS/ClaudeProxyGuard",
    "MacOS/GuardHost",
    "MacOS/GuardDrop",
    "Frameworks/Sparkle.framework/Versions/B/Sparkle",
    "Frameworks/Sparkle.framework/Versions/B/Autoupdate",
    "Frameworks/Sparkle.framework/Versions/B/Updater.app/Contents/MacOS/Updater",
    "Frameworks/Sparkle.framework/Versions/B/XPCServices/Downloader.xpc/Contents/MacOS/Downloader",
    "Frameworks/Sparkle.framework/Versions/B/XPCServices/Installer.xpc/Contents/MacOS/Installer",
}
universal = {
    "MacOS/ClaudeProxyGuard",
    "MacOS/GuardHost",
    "MacOS/GuardDrop",
    "Frameworks/Sparkle.framework/Versions/B/Sparkle",
    "Frameworks/Sparkle.framework/Versions/B/Autoupdate",
}
for rel, target in required_links.items():
    if links.get(rel) != target:
        raise SystemExit("Missing or incorrect Sparkle symlink: " + rel)
for rel in executables:
    if rel not in regular or not modes.get(rel, 0) & stat.S_IXUSR:
        raise SystemExit("Missing executable in built app: " + rel)


def reject_private_data(rel):
    parts = rel.lower().split("/")
    name = parts[-1]
    if any(part in {"profile", "runtime", "ip-memory", "diagnostics", "keychain", "credentials"} for part in parts):
        raise SystemExit("Private profile/runtime data in archive: " + rel)
    if name.startswith(".env") or name in {"settings.json", "ip-memory.json", "diagnostics.jsonl"}:
        raise SystemExit("Private settings in archive: " + rel)
    if pathlib.PurePosixPath(name).suffix in {".pem", ".key", ".p12", ".pfx"}:
        raise SystemExit("Private key material in archive: " + rel)


seen = set()
with zipfile.ZipFile(sys.argv[1]) as archive:
    if archive.testzip() is not None:
        raise SystemExit("ZIP CRC failure")
    for info in archive.infolist():
        name = info.filename
        if "\\" in name or name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts:
            raise SystemExit("Unsafe archive path: " + name)
        if name.endswith("/"):
            if name == "Claude Proxy Guard.app/":
                continue
            if not name.startswith(prefix):
                raise SystemExit("Unexpected archive directory: " + name)
            rel = name[len(prefix):].rstrip("/")
            if not rel:
                continue
            reject_private_data(rel)
            if rel not in directories:
                raise SystemExit("Unexpected archive directory: " + name)
            continue
        if not name.startswith(prefix):
            raise SystemExit("Unexpected archive path: " + name)
        rel = name[len(prefix):]
        reject_private_data(rel)
        if rel in seen or (rel not in regular and rel not in links):
            raise SystemExit("Unexpected or duplicate entry: " + rel)
        kind = (info.external_attr >> 16) & 0o170000
        payload = archive.read(name)
        if rel in links:
            if kind != 0o120000 or payload.decode() != links[rel]:
                raise SystemExit("Symlink mismatch: " + rel)
        else:
            if kind not in {0, 0o100000} or payload != regular[rel].read_bytes():
                raise SystemExit("Byte mismatch: " + rel)
            archived_mode = (info.external_attr >> 16) & 0o777
            if archived_mode != modes[rel]:
                raise SystemExit("Mode mismatch: " + rel)
        seen.add(rel)
if seen != set(regular) | set(links):
    raise SystemExit("Missing expected bundle files or symlinks")
import plistlib
metadata = plistlib.loads(regular["Info.plist"].read_bytes())
if metadata.get("LSUIElement") is not True:
    raise SystemExit("macOS release must remain an accessory/status-bar application")

with tempfile.TemporaryDirectory(prefix="guard-macos-zip-") as temporary:
    subprocess.run(["/usr/bin/ditto", "-x", "-k", str(pathlib.Path(sys.argv[1]).resolve()), temporary], check=True)
    app = pathlib.Path(temporary) / "Claude Proxy Guard.app"
    for rel in sorted(universal):
        architectures = subprocess.check_output(["/usr/bin/lipo", "-archs", str(app / "Contents" / rel)], text=True).split()
        if set(architectures) != {"arm64", "x86_64"}:
            raise SystemExit("Unexpected architectures for " + rel + ": " + " ".join(architectures))
    nested = [
        "Contents/Frameworks/Sparkle.framework/Versions/B/XPCServices/Downloader.xpc",
        "Contents/Frameworks/Sparkle.framework/Versions/B/XPCServices/Installer.xpc",
        "Contents/Frameworks/Sparkle.framework/Versions/B/Updater.app",
        "Contents/Frameworks/Sparkle.framework/Versions/B/Autoupdate",
        "Contents/Frameworks/Sparkle.framework",
    ]
    for rel in nested:
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(app / rel)], check=True)
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True)

print(json.dumps({
    "status": "PASS",
    "regularFiles": len(regular),
    "sparkleSymlinks": len(required_links),
    "executables": len(executables),
    "universalBinaries": len(universal),
    "nestedSignatures": "PASS",
    "resourcesAndDocuments": "BYTE_MATCH",
    "privateProfileSecretEntries": 0,
    "runtimeTest": "NOT_RUN_BY_THIS_CHECK",
}))
