#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .build
xcrun swiftc -swift-version 5 -D PREVIEW -D GUARD_E2E -parse-as-library \
  -target "$(uname -m)-apple-macosx13.0" -module-cache-path "${TMPDIR:-/tmp}/claude-proxyguard-tests" \
  -framework SwiftUI -framework AppKit -framework Network \
  Source/*.swift Tests/RecoveryTests.swift -o .build/RecoveryTests
.build/RecoveryTests
