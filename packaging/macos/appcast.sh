#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-$ROOT/release}"
cd "$ROOT"
bash packaging/macos/package.sh "$OUT"
OUT="$(cd "$OUT" && pwd)"
VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' Info.plist)"
ZIP="$OUT/ClaudeProxyGuard-macOS-$VERSION-universal.zip"
FEED_DIR="$OUT/sparkle-feed"
APPCAST="$OUT/appcast.xml"
[ ! -e "$FEED_DIR" ] && [ ! -e "$APPCAST" ] || { echo 'Use a fresh output directory.' >&2; exit 1; }
mkdir -p "$FEED_DIR"
cp "$ZIP" "$FEED_DIR/"
TOOLS="$ROOT/.build/Sparkle-2.10.1/bin"
"$TOOLS/generate_appcast" \
  --maximum-deltas 0 \
  --download-url-prefix 'https://github.com/JFT-git/gate-claude/releases/latest/download/' \
  --link 'https://github.com/JFT-git/gate-claude' \
  "$FEED_DIR"
mv "$FEED_DIR/appcast.xml" "$APPCAST"
rm "$FEED_DIR/$(basename "$ZIP")"
rmdir "$FEED_DIR"
"$TOOLS/sign_update" --verify "$APPCAST"
python3 packaging/scripts/verify-macos-appcast.py Info.plist "$APPCAST" "$ZIP"
echo "$APPCAST"
