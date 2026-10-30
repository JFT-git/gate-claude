#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p .build
[ -f .build/BarrierIntegrity.swift ] || printf 'enum BarrierIntegrity { static let guardDropSHA256 = "stub" }\n' > .build/BarrierIntegrity.swift
xcrun swiftc -swift-version 5 -D PREVIEW -D GUARD_E2E -parse-as-library -target "$(uname -m)-apple-macosx13.0" \
 -module-cache-path "${TMPDIR:-/tmp}/guard-ui-tests" -framework SwiftUI -framework AppKit -framework Network \
 Source/*.swift .build/BarrierIntegrity.swift Tests/UIReview.swift -o .build/UIReview
.build/UIReview "${1:-$PWD/.build/macos-ui.png}"
