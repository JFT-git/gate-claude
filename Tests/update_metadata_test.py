#!/usr/bin/env python3
import base64
import hashlib
import pathlib
import plistlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
with (root / "Info.plist").open("rb") as handle:
    info = plistlib.load(handle)
assert info["SUFeedURL"] == "https://github.com/JFT-git/gate-claude/releases/latest/download/appcast.xml"
assert info["SURequireSignedFeed"] is True
assert info["SUVerifyUpdateBeforeExtraction"] is True
assert info["SUEnableAutomaticChecks"] is True
assert info["SUScheduledCheckInterval"] == 86_400
assert info["SUAutomaticallyUpdate"] is False
assert info["SUSendProfileInfo"] is False
assert len(base64.b64decode(info["SUPublicEDKey"], validate=True)) == 32
assert info["CFBundleVersion"].isdigit() and int(info["CFBundleVersion"]) > 0
build = (root / "build.sh").read_text()
assert 'SPARKLE_VERSION="2.10.1"' in build
assert 'SPARKLE_SHA256="1a856d2a9edb8e628de88121d7be04cf0e2167f8641650b78fca00b14244cf27"' in build
assert "sparkle-project/Sparkle/releases/download/$SPARKLE_VERSION" in build
archive = root / ".build/sparkle-download/Sparkle-2.10.1.tar.xz"
if archive.exists():
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == "1a856d2a9edb8e628de88121d7be04cf0e2167f8641650b78fca00b14244cf27"
source = (root / "Source/UpdateController.swift").read_text()
assert "SPUStandardUpdaterController" in source
assert "checkForUpdatesInBackground()" in source
assert "86_400" in source
assert "model.shutdown()" in source
assert "automaticallyDownloadsUpdates = true" in source
appcast_script = (root / "packaging/macos/appcast.sh").read_text()
assert 'rm "$FEED_DIR/$(basename "$ZIP")"' in appcast_script
assert 'rmdir "$FEED_DIR"' in appcast_script

signature = base64.b64encode(bytes(64)).decode()
appcast = f'''<?xml version="1.0"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><item>
<title>Guard</title><sparkle:version>{{version}}</sparkle:version>
<enclosure url="https://github.com/JFT-git/gate-claude/releases/latest/download/Guard.zip" length="1" sparkle:edSignature="{signature}"/>
</item></channel></rss>'''
with tempfile.TemporaryDirectory(prefix="guard-update-metadata-") as temporary:
    feed = pathlib.Path(temporary) / "appcast.xml"
    feed.write_text(appcast.format(version=info["CFBundleVersion"]))
    subprocess.run(["python3", str(root / "packaging/scripts/verify-macos-appcast.py"), str(root / "Info.plist"), str(feed)], check=True)
    for invalid in ["0.6.16", "0", str(int(info["CFBundleVersion"]) - 1)]:
        feed.write_text(appcast.format(version=invalid))
        result = subprocess.run(["python3", str(root / "packaging/scripts/verify-macos-appcast.py"), str(root / "Info.plist"), str(feed)], capture_output=True)
        assert result.returncode != 0, invalid
print("PASS update metadata, stable feed, key shape, version policy, and invalid-version rejection")
