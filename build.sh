#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
APP="Claude Proxy Guard.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" .build
export CLANG_MODULE_CACHE_PATH="${TMPDIR:-/tmp}/claude-proxyguard-clang"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
for ARCH in arm64 x86_64; do
  xcrun swiftc -swift-version 5 -O -parse-as-library -sdk "$SDK" \
    -target "$ARCH-apple-macosx13.0" -module-cache-path "$CLANG_MODULE_CACHE_PATH" \
    -framework SwiftUI -framework AppKit -framework Network \
    Source/*.swift -o ".build/Guard-$ARCH"
  xcrun clang -O2 -target "$ARCH-apple-macosx13.0" -isysroot "$SDK" Source/GuardHost.c -o ".build/Host-$ARCH"
  xcrun clang -O2 -target "$ARCH-apple-macosx13.0" -isysroot "$SDK" Source/GuardDrop.c -o ".build/Drop-$ARCH"
done
lipo -create .build/Host-arm64 .build/Host-x86_64 -output "$APP/Contents/MacOS/GuardHost"
codesign --force --sign - --identifier local.proxyguard.claude.host "$APP/Contents/MacOS/GuardHost"
lipo -create .build/Drop-arm64 .build/Drop-x86_64 -output "$APP/Contents/MacOS/GuardDrop"
codesign --force --sign - --identifier local.proxyguard.claude.drop "$APP/Contents/MacOS/GuardDrop"
lipo -create .build/Guard-arm64 .build/Guard-x86_64 -output "$APP/Contents/MacOS/ClaudeProxyGuard"
cp Resources/RuntimeBootstrap.cjs "$APP/Contents/Resources/RuntimeBootstrap.cjs"
cp Info.plist "$APP/Contents/Info.plist"
mkdir -p "$APP/Contents/Resources/Documentation"
cp README.md SECURITY.md CHANGELOG.md "$APP/Contents/Resources/Documentation/"
cp -R docs "$APP/Contents/Resources/Documentation/"
if [ -f AppIcon.icns ]; then cp AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"; fi
codesign --force --sign - --identifier local.proxyguard.claude "$APP"
codesign --verify --deep --strict "$APP"
echo "Built: $PWD/$APP"
