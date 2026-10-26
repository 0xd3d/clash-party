#!/usr/bin/env bash
set -euo pipefail
IOS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORE_ROOT="${MIHOMO_CORE_ROOT:-$IOS_ROOT/../../modules/mihomo-ios-core}"
CHECK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/clash-party-ios-check.XXXXXX")"
trap 'rm -rf "$CHECK_ROOT"' EXIT
SHARED=("$IOS_ROOT"/ClashPartyShared/Models/*.swift "$IOS_ROOT"/ClashPartyShared/Compatibility/*.swift "$IOS_ROOT/ClashPartyShared/Store/SharedStore.swift")
swiftc "${SHARED[@]}" "$IOS_ROOT/scripts/check_ios_routing.swift" -o "$CHECK_ROOT/routing-check"
"$CHECK_ROOT/routing-check" "$IOS_ROOT/tests/Fixtures/legacy-service-profile.yaml" "$IOS_ROOT/ClashParty/Resources/RuleResources" "$CHECK_ROOT/runtime"
for check in check_ios_doh_preservation check_ios_dns_route_protection check_ios_proxy_projection check_mobile_runtime; do
  swiftc "${SHARED[@]}" "$IOS_ROOT/scripts/$check.swift" -o "$CHECK_ROOT/$check"
  "$CHECK_ROOT/$check"
done
swiftc -module-cache-path "$CHECK_ROOT/swift-cache" "$IOS_ROOT"/ClashPartyShared/Models/*.swift "$IOS_ROOT/ClashPartyShared/Runtime/EncryptedBootstrapResolver.swift" "$IOS_ROOT/ClashPartyShared/Runtime/PacketTunnelIPv6Policy.swift" "$IOS_ROOT/scripts/check_encrypted_bootstrap.swift" -o "$CHECK_ROOT/check-encrypted-bootstrap"
"$CHECK_ROOT/check-encrypted-bootstrap"
clang -fobjc-arc -fblocks -I "$IOS_ROOT/ClashPartyShared/Runtime" -framework Foundation -framework NetworkExtension "$IOS_ROOT/ClashPartyShared/Runtime/MihomoPacketFlowBridge.m" "$IOS_ROOT/scripts/check_ipv6_packet_policy.m" -o "$CHECK_ROOT/check-ipv6-packet-policy"
"$CHECK_ROOT/check-ipv6-packet-policy"
swiftc -module-cache-path "$CHECK_ROOT/swift-cache" "${SHARED[@]}" "$IOS_ROOT/ClashPartyShared/Runtime/GeoResourceManager.swift" "$IOS_ROOT/scripts/check_georesource_download_context.swift" -o "$CHECK_ROOT/check-georesource-download-context"
"$CHECK_ROOT/check-georesource-download-context"
python3 "$IOS_ROOT/scripts/test_export_ios_desktop_rules.py"
(
  cd "$CORE_ROOT"
  GOTOOLCHAIN="${GOTOOLCHAIN:-go1.20.14+auto}" go test ./adapter/outboundgroup ./component/resolver ./dns ./tunnel ./hub/executor ./config ./listener/inner ./component/http ./component/geodata ./component/mmdb
  IOS_POLICY_RUNTIME_DIR="$CHECK_ROOT/runtime" IOS_RULE_RESOURCE_DIR="$IOS_ROOT/ClashParty/Resources/RuleResources" IOS_GEO_RESOURCE_DIR="$IOS_ROOT/ClashParty/Resources/GeoResources" GOTOOLCHAIN="${GOTOOLCHAIN:-go1.20.14+auto}" go test ./rules -run '^TestIOSPortablePolicy$' -count=1
)
