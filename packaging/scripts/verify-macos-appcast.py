#!/usr/bin/env python3
import base64
import pathlib
import plistlib
import sys
import urllib.parse
import xml.etree.ElementTree as ET

SPARKLE = "http://www.andymatuschak.org/xml-namespaces/sparkle"
plist_path, appcast_path = map(pathlib.Path, sys.argv[1:3])
with plist_path.open("rb") as handle:
    metadata = plistlib.load(handle)
bundle_version = metadata["CFBundleVersion"]
if not bundle_version.isascii() or not bundle_version.isdigit() or int(bundle_version) < 1:
    raise SystemExit("CFBundleVersion must be a positive monotonic integer")
root = ET.parse(appcast_path).getroot()
items = root.findall("./channel/item")
if not items:
    raise SystemExit("Appcast has no updates")
versions = []
for item in items:
    version = item.findtext(f"{{{SPARKLE}}}version", "")
    if not version.isascii() or not version.isdigit() or int(version) < 1:
        raise SystemExit("sparkle:version must be CFBundleVersion, not a tag version: " + version)
    versions.append(int(version))
    if item.find(f".//{{{SPARKLE}}}deltas") is not None:
        raise SystemExit("Custom delta updates are not used")
    enclosure = item.find("enclosure")
    if enclosure is None:
        raise SystemExit("Appcast item has no full ZIP enclosure")
    signature = enclosure.attrib.get(f"{{{SPARKLE}}}edSignature", "")
    try:
        if len(base64.b64decode(signature, validate=True)) != 64:
            raise ValueError()
    except ValueError:
        raise SystemExit("Invalid EdDSA enclosure signature")
    url = enclosure.attrib.get("url", "")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}):
        raise SystemExit("Update enclosure must use HTTPS (or loopback for local tests)")
if versions[0] != int(bundle_version):
    raise SystemExit("Latest sparkle:version does not equal CFBundleVersion")
if any(newer <= older for newer, older in zip(versions, versions[1:])):
    raise SystemExit("Appcast versions must be unique and monotonically decreasing")
if len(sys.argv) > 3:
    archive = pathlib.Path(sys.argv[3])
    length = int(items[0].find("enclosure").attrib["length"])
    if length != archive.stat().st_size:
        raise SystemExit("Appcast enclosure length does not match full ZIP")
print("PASS appcast: signed full ZIP, numeric CFBundleVersion " + bundle_version + ", no deltas")
