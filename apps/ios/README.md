# Clash Party iOS

Native SwiftUI application and Packet Tunnel extension in the Clash Party monorepo. Desktop source remains at the repository root; this app uses `ClashParty`, `ClashPartyTunnel` and shared Swift code plus the separately maintained mobile core at `../../modules/mihomo-ios-core`.

## Build locally

Requirements: macOS, Xcode with iOS SDKs, Go 1.20.14 (the legacy mobile core is pinned), and Python 3 with PyYAML for desktop-rule export tests.

```sh
./scripts/update-georesources.sh
./scripts/build-mihomo-mobile.sh
xcodebuild -project ClashParty.xcodeproj -scheme ClashParty -configuration Debug -destination 'generic/platform=iOS' -derivedDataPath /tmp/clash-party-ios-device CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
xcodebuild -project ClashParty.xcodeproj -scheme ClashParty -configuration Debug -destination 'generic/platform=iOS Simulator' -derivedDataPath /tmp/clash-party-ios-simulator CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
```

`MIHOMO_CORE_ROOT` can override the source location. The script builds ARM64 device and simulator slices into ignored `Vendor/MihomoMobile.xcframework`; the simulator slice is for UI/debugging and has no usable TUN. See the core's `SOURCE.md` and `LICENSE` for provenance.

The unsigned CI artifacts are build checks, not installable VPN distributions. Real-device installation requires the developer's own signing identities, provisioning, App Group and Network Extension entitlements. Set personal values in ignored `Config/Local.xcconfig`; never commit keys, certificates, profiles or Team values. The manual `build-install-run-device.sh` is deliberately excluded from CI because it can install and launch on a connected device.

## Policy and supported runtime

Nodes, credentials, subscription URLs and user exceptions are imported configuration, not software defaults. The bundled snapshot is a small public format example, not a personal desktop policy. General routing uses public YAML rule seeds: local discovery stays local, public UDP uses the chosen outbound, non-CN domains are classified before domestic/CDN country shortcuts, and unmatched traffic uses that outbound. Explicit original profile rules remain available.

The legacy mobile core supports YAML rule providers but not MRS. Desktop policy export must convert supported providers or fail clearly; it must never ship MRS into this core or silently discard rules. The existing portable snapshot format includes NETWORK transport rules. Desktop-only process rules are intentionally omitted; node credentials are never part of a policy-only export.

This mobile core is a custom 1.10.0 base. It does not support every current desktop protocol or DNS/TUN option; for example Hysteria2 and desktop JS overrides are absent. Keep capability handling in the existing iOS compatibility layer, not a new policy language. REALITY ML-KEM, Fake-IP persistence, DoH and packet-flow lifetime changes retain their existing regression checks.

## Verification

Run `scripts/check-portable-routing.sh` for Swift overlay/snapshot tests and real mobile-core rule matching. The independent GitHub iOS workflow builds unsigned ARM64 device/simulator apps and uploads build artifacts only. It never accesses an iPhone or changes a desktop VPN.

Actual device DNS/WebRTC leakage, background lifetime, memory footprint, Wi-Fi/cellular changes and normal VPN stop still need user device testing. A simulator build or source-level rule test is not evidence of those network results. Geo resources and public seed attribution are listed in `ClashParty/Resources/RuleResources/SOURCES.txt` and `../../modules/mihomo-ios-core/SOURCE.md`.
