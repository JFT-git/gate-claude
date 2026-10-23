#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .build
CACHE="${TMPDIR:-/tmp}/claude-proxyguard-tests"
TEST_ARCH="$(uname -m)"
xcrun swiftc -swift-version 5 -target "$TEST_ARCH-apple-macosx13.0" -module-cache-path "$CACHE" -parse-as-library -framework Network \
  Source/Core.swift Source/Policy.swift Tests/RelayTests.swift -o .build/RelayTests
python3 Tests/run.py
xcrun clang -O2 Source/GuardHost.c -o .build/GuardHostTest
xcrun swiftc -swift-version 5 -target "$TEST_ARCH-apple-macosx13.0" -module-cache-path "$CACHE" -parse-as-library -framework Network \
  Source/Core.swift Source/Policy.swift Source/Inspector.swift Source/DeepLink.swift Source/Diagnostics.swift Source/SystemProxy.swift Tests/InspectorTests.swift -o .build/InspectorTests
chmod +x Tests/MockClaude.py
.build/InspectorTests "$PWD/.build/GuardHostTest" "$PWD/Tests/MockClaude.py"

bash Tests/recovery_test.sh
