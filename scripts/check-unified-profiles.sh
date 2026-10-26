#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
check_dir="$(mktemp -d "${TMPDIR:-/tmp}/clash-unified.XXXXXX")"
trap 'rm -rf "$check_dir"' EXIT
swiftc -module-cache-path "$check_dir/swift-cache" apps/ios/ClashPartyShared/Compatibility/UnifiedProfile.swift apps/ios/scripts/check_unified_profile.swift -o "$check_dir/check"
"$check_dir/check" tests/fixtures/unified-profiles.json "$check_dir/results.json"
pnpm exec tsx scripts/check-unified-profiles.ts "$check_dir/results.json"
