#!/usr/bin/env python3
"""Run genuine local Sparkle updates using only synthetic application data."""
import argparse
import base64
import http.server
import json
import os
import pathlib
import plistlib
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

SPARKLE = "http://www.andymatuschak.org/xml-namespaces/sparkle"
ET.register_namespace("sparkle", SPARKLE)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--work-dir", type=pathlib.Path, required=True)
args = parser.parse_args()
project = pathlib.Path(__file__).resolve().parents[2]
work = args.work_dir.resolve()
if work.exists():
    raise SystemExit("Use a fresh test directory")
work.mkdir(parents=True, mode=0o700)
tools = project / ".build/Sparkle-2.10.1/bin"
if not (tools / "generate_appcast").exists():
    subprocess.run(["bash", "build.sh"], cwd=project, check=True)
server_root = work / "server"
server_root.mkdir()
current_feed = server_root / "initial.xml"
current_feed.write_text("<rss/>")


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path == "/appcast.xml":
            path = current_feed
        else:
            candidate = (server_root / self.path.lstrip("/")).resolve()
            if server_root not in candidate.parents or not candidate.is_file():
                self.send_error(404)
                return
            path = candidate
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/xml" if path.suffix == ".xml" else "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
server.daemon_threads = True
threading.Thread(target=server.serve_forever, daemon=True).start()
base_url = f"http://127.0.0.1:{server.server_port}"
report = {"sparkle": "2.10.1", "tests": {}, "realUserData": "NOT_USED"}


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def build(name, version, short_version):
    app = work / "build" / f"{name}.app"
    app.parent.mkdir(exist_ok=True)
    environment = os.environ.copy()
    environment.update({
        "GUARD_BUILD_APP_PATH": str(app),
        "GUARD_BUILD_VERSION": str(version),
        "GUARD_BUILD_SHORT_VERSION": short_version,
        "GUARD_BUILD_SWIFT_FLAGS": "-D GUARD_UPDATE_TEST",
        "TMPDIR": str(work),
    })
    run(["bash", "build.sh"], cwd=project, env=environment)
    return app


def bundle_version(app):
    with (app / "Contents/Info.plist").open("rb") as handle:
        return plistlib.load(handle)["CFBundleVersion"]


def zip_app(app, destination):
    run(["/usr/bin/ditto", "-c", "-k", "--norsrc", "--noextattr", "--noqtn", "--keepParent", str(app), str(destination)])


def make_feed(name, archive):
    global current_feed
    directory = server_root / "feeds" / name
    directory.mkdir(parents=True)
    served_archive = directory / "update.zip"
    shutil.copy2(archive, served_archive)
    run([str(tools / "generate_appcast"), "--maximum-deltas", "0", "--download-url-prefix", base_url + "/feeds/" + name + "/", str(directory)], stdout=subprocess.DEVNULL)
    current_feed = directory / "appcast.xml"
    run([str(tools / "sign_update"), "--verify", str(current_feed)], stdout=subprocess.DEVNULL)
    return current_feed, served_archive


def rewrite_feed(feed, signature=None, length=None, remove_feed_signature=False):
    tree = ET.parse(feed)
    enclosure = tree.getroot().find("./channel/item/enclosure")
    if signature is not None:
        enclosure.set(f"{{{SPARKLE}}}edSignature", signature)
    if length is not None:
        enclosure.set("length", str(length))
    feed.write_bytes(ET.tostring(tree.getroot(), encoding="utf-8", xml_declaration=True))
    if not remove_feed_signature:
        run([str(tools / "sign_update"), str(feed)], stdout=subprocess.DEVNULL)
        run([str(tools / "sign_update"), "--verify", str(feed)], stdout=subprocess.DEVNULL)


def sentinels(home):
    relative = [
        "Library/Application Support/Claude Proxy Guard/Profile/sentinel.txt",
        "Library/Application Support/Claude Proxy Guard/Runtime/sentinel.txt",
        "Library/Application Support/Claude Proxy Guard/ip-memory/sentinel.txt",
        "Library/Application Support/Claude Proxy Guard/diagnostics/sentinel.txt",
    ]
    for item in relative:
        path = home / item
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("preserve-me\n")
    return relative


def configure(app, name, expected_version=None):
    scenario = work / "scenarios" / name
    home = scenario / "home"
    configuration = {
        "GUARD_UPDATE_TEST_HOME": str(home),
        "GUARD_UPDATE_TEST_TMPDIR": str(scenario / "tmp"),
        "GUARD_UPDATE_TEST_FEED": base_url + "/appcast.xml",
        "GUARD_UPDATE_TEST_RESULT": str(scenario / "result.json"),
        "GUARD_UPDATE_TEST_SHUTDOWN": str(scenario / "shutdown.txt"),
    }
    if expected_version:
        configuration["GUARD_UPDATE_TEST_EXPECT_VERSION"] = expected_version
        configuration["GUARD_UPDATE_TEST_AUTOINSTALL"] = "1"
    else:
        configuration["GUARD_UPDATE_TEST_EXPECT_FAILURE"] = "1"
    (app / "Contents/Resources/UpdateTest.json").write_text(json.dumps(configuration, indent=2) + "\n")
    identifier = "local.proxyguard.claude"
    with (app / "Contents/Info.plist").open("rb") as handle:
        identifier = plistlib.load(handle)["CFBundleIdentifier"]
    run(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", identifier, str(app)], stdout=subprocess.DEVNULL)


def configured_archive(source, name, expected_version=None):
    app = work / "build" / ("update-" + name + ".app")
    shutil.copytree(source, app, symlinks=True)
    configure(app, name, expected_version)
    archive = work / ("update-" + name + ".zip")
    zip_app(app, archive)
    return archive


def run_scenario(name, installed_app, expected_version=None, expected_codes=None, no_update=False):
    scenario = work / "scenarios" / name
    home = scenario / "home"
    temporary = scenario / "tmp"
    temporary.mkdir(parents=True)
    relative_sentinels = sentinels(home)
    applications = scenario / "Applications"
    applications.mkdir()
    app = applications / "Claude Proxy Guard.app"
    shutil.copytree(installed_app, app, symlinks=True)
    configure(app, name, expected_version)
    result = scenario / "result.json"
    shutdown = scenario / "shutdown.txt"
    log = scenario / "app.log"
    environment = os.environ.copy()
    environment.update({
        "HOME": str(home),
        "CFFIXED_USER_HOME": str(home),
        "TMPDIR": str(temporary),
        "GUARD_UPDATE_TEST_HOME": str(home),
        "GUARD_UPDATE_TEST_FEED": base_url + "/appcast.xml",
        "GUARD_UPDATE_TEST_RESULT": str(result),
        "GUARD_UPDATE_TEST_SHUTDOWN": str(shutdown),
    })
    if expected_version:
        environment["GUARD_UPDATE_TEST_EXPECT_VERSION"] = expected_version
        environment["GUARD_UPDATE_TEST_AUTOINSTALL"] = "1"
    else:
        environment["GUARD_UPDATE_TEST_EXPECT_FAILURE"] = "1"
    with log.open("w") as output:
        process = subprocess.Popen([str(app / "Contents/MacOS/ClaudeProxyGuard")], env=environment,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline and not result.exists():
            if not expected_version and process.poll() is not None and not result.exists():
                raise RuntimeError(name + " exited without result; see " + str(log))
            time.sleep(0.1)
        if not result.exists():
            if process.poll() is None:
                process.terminate()
            subprocess.run(["/usr/bin/pkill", "-TERM", "-f", str(app)], check=False)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
            raise RuntimeError(name + " timed out; see " + str(log))
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.wait(timeout=0)
    outcome = json.loads(result.read_text())
    if bundle_version(app) != (expected_version or bundle_version(installed_app)):
        raise RuntimeError(name + " changed to an unexpected bundle version")
    for item in relative_sentinels:
        if (home / item).read_text() != "preserve-me\n":
            raise RuntimeError(name + " modified a data sentinel")
    if expected_version:
        if outcome.get("outcome") != "installed" or not outcome.get("dataPreserved") or not outcome.get("defaultsPreserved"):
            raise RuntimeError(name + " failed preservation proof: " + repr(outcome))
        if shutdown.read_text() != "shutdown-complete\n":
            raise RuntimeError(name + " installed before model.shutdown completed")
    else:
        if shutdown.exists():
            raise RuntimeError(name + " stopped the model for a rejected update")
        if no_update:
            if outcome.get("outcome") != "no_update":
                raise RuntimeError(name + " did not reject downgrade: " + repr(outcome))
        elif outcome.get("outcome") != "error" or outcome.get("code") not in expected_codes:
            raise RuntimeError(name + " returned an unexpected error: " + repr(outcome))
    report["tests"][name] = outcome
    print("PASS " + name + ": " + json.dumps(outcome, sort_keys=True), flush=True)


try:
    old_app = build("old", 12001, "0.0.1")
    new_app = build("new", 12002, "0.0.2")
    positive_zip = configured_archive(new_app, "installed-A-to-B", "12002")
    feed, _ = make_feed("valid", positive_zip)
    run_scenario("installed-A-to-B", old_app, expected_version="12002")

    bad_signature_zip = configured_archive(new_app, "bad-enclosure-signature")
    feed, _ = make_feed("bad-signature", bad_signature_zip)
    rewrite_feed(feed, signature=base64.b64encode(bytes(64)).decode())
    run_scenario("bad-enclosure-signature", old_app, expected_codes={3001, 3002, 4005})

    corrupt_base_zip = configured_archive(new_app, "corrupt-ZIP-with-valid-signature")
    feed, served = make_feed("corrupt", corrupt_base_zip)
    corrupt = work / "corrupt.zip"
    corrupt.write_bytes(b"not a zip archive\n")
    signature = subprocess.check_output([str(tools / "sign_update"), "-p", str(corrupt)], text=True).strip()
    shutil.copy2(corrupt, served)
    rewrite_feed(feed, signature=signature, length=corrupt.stat().st_size)
    run_scenario("corrupt-ZIP-with-valid-signature", old_app, expected_codes={3000, 3001, 3002})

    wrong_app = work / "build/wrong.app"
    shutil.copytree(new_app, wrong_app, symlinks=True)
    run(["/usr/libexec/PlistBuddy", "-c", "Set :CFBundleIdentifier local.proxyguard.claude.wrong", str(wrong_app / "Contents/Info.plist")])
    configure(wrong_app, "wrong-bundle-identifier")
    wrong_zip = work / "wrong.zip"
    zip_app(wrong_app, wrong_zip)
    feed, _ = make_feed("wrong-bundle", wrong_zip)
    run_scenario("wrong-bundle-identifier", old_app, expected_codes={3002, 4005, 4009})

    unsigned_zip = configured_archive(new_app, "unsigned-required-feed")
    feed, _ = make_feed("unsigned-feed", unsigned_zip)
    rewrite_feed(feed, remove_feed_signature=True)
    run_scenario("unsigned-required-feed", old_app, expected_codes={1000, 1002, 3001, 3002})

    downgrade_zip = configured_archive(old_app, "downgrade-rejected")
    feed, _ = make_feed("downgrade", downgrade_zip)
    run_scenario("downgrade-rejected", new_app, no_update=True)

    report["status"] = "PASS"
except Exception as error:
    report["status"] = "FAIL"
    report["error"] = str(error)
    raise
finally:
    server.shutdown()
    (work / "sparkle-test-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("Report: " + str(work / "sparkle-test-report.json"), flush=True)
