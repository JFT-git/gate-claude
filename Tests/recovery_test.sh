#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .build
# Stub for the build-time embedded helper hash; tests never install the barrier.
[ -f .build/BarrierIntegrity.swift ] || \
  printf '// Test stub - do not edit.\nenum BarrierIntegrity { static let guardDropSHA256 = "stub" }\n' > .build/BarrierIntegrity.swift
[ -d .build/Sparkle-2.10.1/Sparkle.framework ] || bash build.sh
xcrun swiftc -swift-version 5 -D PREVIEW -D GUARD_E2E -parse-as-library \
  -target "$(uname -m)-apple-macosx13.0" -module-cache-path "${TMPDIR:-/tmp}/claude-proxyguard-tests" \
  -F "$PWD/.build/Sparkle-2.10.1" -framework SwiftUI -framework AppKit -framework Network -framework Sparkle \
  -Xlinker -rpath -Xlinker "$PWD/.build/Sparkle-2.10.1" \
  Source/*.swift .build/BarrierIntegrity.swift Tests/RecoveryTests.swift -o .build/RecoveryTests
.build/RecoveryTests
