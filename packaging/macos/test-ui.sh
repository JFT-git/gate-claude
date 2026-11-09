#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p .build
[ -f .build/BarrierIntegrity.swift ] || printf 'enum BarrierIntegrity { static let guardDropSHA256 = "stub" }\n' > .build/BarrierIntegrity.swift
[ -d .build/Sparkle-2.10.1/Sparkle.framework ] || bash build.sh
xcrun swiftc -swift-version 5 -D PREVIEW -D GUARD_E2E -parse-as-library -target "$(uname -m)-apple-macosx13.0" \
 -module-cache-path "${TMPDIR:-/tmp}/guard-ui-tests" -F "$PWD/.build/Sparkle-2.10.1" \
 -framework SwiftUI -framework AppKit -framework Network -framework Sparkle \
 -Xlinker -rpath -Xlinker "$PWD/.build/Sparkle-2.10.1" \
 Source/*.swift .build/BarrierIntegrity.swift Tests/UIReview.swift -o .build/UIReview
.build/UIReview "${1:-$PWD/.build/macos-ui.png}"

LIFECYCLE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/guard-lifecycle.XXXXXX")"
trap 'rm -rf "$LIFECYCLE_ROOT"' EXIT
LIFECYCLE_APP="$LIFECYCLE_ROOT/Guard Lifecycle Tests.app"
mkdir -p "$LIFECYCLE_APP/Contents/MacOS" "$LIFECYCLE_ROOT/home" "$LIFECYCLE_ROOT/tmp"
xcrun swiftc -swift-version 5 -D PREVIEW -D GUARD_E2E -parse-as-library -target "$(uname -m)-apple-macosx13.0" \
 -module-cache-path "${TMPDIR:-/tmp}/guard-ui-tests" -F "$PWD/.build/Sparkle-2.10.1" \
 -framework SwiftUI -framework AppKit -framework Network -framework Sparkle \
 -Xlinker -rpath -Xlinker "$PWD/.build/Sparkle-2.10.1" \
 Source/*.swift .build/BarrierIntegrity.swift Tests/AppLifecycleTests.swift -o "$LIFECYCLE_APP/Contents/MacOS/ClaudeProxyGuardLifecycleTests"
cat > "$LIFECYCLE_APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>ClaudeProxyGuardLifecycleTests</string>
<key>CFBundleIdentifier</key><string>local.proxyguard.claude.lifecycle-test.$$</string>
<key>CFBundleName</key><string>Guard Lifecycle Tests</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>LSUIElement</key><true/>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
EOF
HOME="$LIFECYCLE_ROOT/home" CFFIXED_USER_HOME="$LIFECYCLE_ROOT/home" TMPDIR="$LIFECYCLE_ROOT/tmp" \
 "$LIFECYCLE_APP/Contents/MacOS/ClaudeProxyGuardLifecycleTests" "$PWD/.build/macos-lifecycle-proof.json"
