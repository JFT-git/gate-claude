#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-$ROOT/release}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
cd "$ROOT"
bash build.sh
VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' Info.plist)"
APP="$ROOT/Claude Proxy Guard.app"
ZIP="$OUT/ClaudeProxyGuard-macOS-$VERSION-universal.zip"
DMG="$OUT/ClaudeProxyGuard-macOS-$VERSION-universal.dmg"
if [[ -e "$ZIP" || -e "$DMG" ]]; then echo 'Use a fresh output directory.' >&2; exit 1; fi
for BINARY in ClaudeProxyGuard GuardHost; do
  ARCHS="$(lipo -archs "$APP/Contents/MacOS/$BINARY")"
  [[ "$ARCHS" == "x86_64 arm64" || "$ARCHS" == "arm64 x86_64" ]] || { echo "Unexpected architectures: $ARCHS" >&2; exit 1; }
done
codesign --verify --deep --strict "$APP"
ditto -c -k --keepParent "$APP" "$ZIP"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/guard-dmg.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
ditto "$APP" "$STAGE/Claude Proxy Guard.app"
ln -s /Applications "$STAGE/Applications"
cp README.md "$STAGE/README.md"
cp SECURITY.md "$STAGE/SECURITY.md"
hdiutil create -quiet -volname 'Claude Proxy Guard' -srcfolder "$STAGE" -format UDZO "$DMG"
for FILE in "$ZIP" "$DMG"; do
  DIGEST="$(shasum -a 256 "$FILE" | cut -d ' ' -f 1)"
  printf '%s  %s\n' "$DIGEST" "$(basename "$FILE")" > "$FILE.sha256"
done
printf '{"version":"%s","architectures":["arm64","x86_64"],"codesign":"ad-hoc","notarization":"NOT_CONFIGURED","intelExecution":"NOT_RUN_BY_PACKAGING","runtimeTests":"NOT_RUN_BY_PACKAGING","installsService":false}\n' "$VERSION" > "$OUT/macos-build-status.json"
echo "$ZIP"
echo "$DMG"
