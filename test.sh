#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .build
CACHE="${TMPDIR:-/tmp}/claude-proxyguard-tests"
TEST_ARCH="$(uname -m)"
shell-check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1 (expected $2, got $3)"; exit 1; fi
}
xcrun swiftc -swift-version 5 -target "$TEST_ARCH-apple-macosx13.0" -module-cache-path "$CACHE" -parse-as-library -framework Network \
  Source/Core.swift Source/Policy.swift Tests/RelayTests.swift -o .build/RelayTests
python3 Tests/run.py
xcrun swiftc -swift-version 5 -target "$TEST_ARCH-apple-macosx13.0" -module-cache-path "$CACHE" -parse-as-library -framework Network \
  Source/Core.swift Source/Policy.swift Tests/IPMemoryTests.swift -o .build/IPMemoryTests
.build/IPMemoryTests
xcrun clang -O2 Source/GuardHost.c -o .build/GuardHostTest
xcrun clang -O2 Source/GuardDrop.c -o .build/GuardDropTest

# GuardDrop must refuse without a target and without root (it only runs via sudo).
set +e
.build/GuardDropTest >/dev/null 2>&1; rc=$?
set -e
shell-check guarddrop-usage 64 "$rc"
set +e
.build/GuardDropTest /bin/true >/dev/null 2>&1; rc=$?
set -e
shell-check guarddrop-no-root 71 "$rc"
set +e
.build/GuardDropTest --env-file /tmp/x /bin/true >/dev/null 2>&1; rc=$?
set -e
shell-check guarddrop-env-arg-no-root 71 "$rc"
set +e
.build/GuardDropTest --env-file >/dev/null 2>&1; rc=$?
set -e
shell-check guarddrop-env-arg-usage 64 "$rc"

# GuardHost restores the session environment only from a private, well-formed file.
ENV_DIR="$(mktemp -d)"
trap 'rm -rf "$ENV_DIR"' EXIT
ENV_FILE="$ENV_DIR/env"
printf 'GUARD_MARK=barrier-ok\nPATH=/usr/bin:/bin\nDYLD_INSERT_LIBRARIES=/tmp/evil.dylib\n' > "$ENV_FILE"
chmod 600 "$ENV_FILE"
OUT="$(GUARD_ENV_FILE="$ENV_FILE" .build/GuardHostTest /usr/bin/python3 -c 'import os; os.write(4, (os.environ.get("GUARD_MARK", "") + "|" + str("DYLD_INSERT_LIBRARIES" in os.environ)).encode())')"
shell-check guardhost-env-load 'barrier-ok|False' "$OUT"
chmod 644 "$ENV_FILE"
set +e
GUARD_ENV_FILE="$ENV_FILE" .build/GuardHostTest /bin/true >/dev/null 2>&1; rc=$?
set -e
shell-check guardhost-env-mode 75 "$rc"
chmod 600 "$ENV_FILE"
set +e
GUARD_ENV_FILE="$ENV_DIR/missing" .build/GuardHostTest /bin/true >/dev/null 2>&1; rc=$?
set -e
shell-check guardhost-env-missing 74 "$rc"
printf 'not-a-variable\n' > "$ENV_FILE"
set +e
GUARD_ENV_FILE="$ENV_FILE" .build/GuardHostTest /bin/true >/dev/null 2>&1; rc=$?
set -e
shell-check guardhost-env-format 78 "$rc"
/usr/bin/python3 -c 'open("'"$ENV_FILE"'", "w").write("A=" + "x" * 70000 + "\n")'
set +e
GUARD_ENV_FILE="$ENV_FILE" .build/GuardHostTest /bin/true >/dev/null 2>&1; rc=$?
set -e
shell-check guardhost-env-size 76 "$rc"

xcrun swiftc -swift-version 5 -target "$TEST_ARCH-apple-macosx13.0" -module-cache-path "$CACHE" -parse-as-library -framework Network \
  Source/Core.swift Source/Policy.swift Source/Inspector.swift Source/DeepLink.swift Source/Diagnostics.swift Source/SystemProxy.swift Tests/InspectorTests.swift -o .build/InspectorTests
chmod +x Tests/MockClaude.py
.build/InspectorTests "$PWD/.build/GuardHostTest" "$PWD/Tests/MockClaude.py"

# Packet-filter barrier: rules, sudoers, pf.conf merge and privileged scripts.
# Stub for the build-time embedded helper hash; tests never install the barrier.
[ -f .build/BarrierIntegrity.swift ] || \
  printf '// Test stub - do not edit.\nenum BarrierIntegrity { static let guardDropSHA256 = "stub" }\n' > .build/BarrierIntegrity.swift
xcrun swiftc -swift-version 5 -target "$TEST_ARCH-apple-macosx13.0" -module-cache-path "$CACHE" -parse-as-library -framework Network \
  Source/Core.swift Source/Policy.swift Source/NetworkBarrier.swift .build/BarrierIntegrity.swift Tests/BarrierTests.swift -o .build/BarrierTests
.build/BarrierTests

# Runtime bootstrap network hardening (needs Node only for the offline harness).
if command -v node >/dev/null 2>&1; then node Tests/bootstrap_test.cjs; else echo "SKIP bootstrap-node (node missing)"; fi

bash Tests/recovery_test.sh
