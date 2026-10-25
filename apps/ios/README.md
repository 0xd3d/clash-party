# Clash Party iOS

Native SwiftUI application and Packet Tunnel extension in the Clash Party monorepo. Desktop source remains at the repository root; this app uses `ClashParty`, `ClashPartyTunnel` and shared Swift code plus the separately maintained mobile core at `../../modules/mihomo-ios-core`.

## Build locally

Requirements: macOS, Xcode with iOS SDKs, Go 1.20.14 (the legacy mobile core is pinned), and Python 3 with PyYAML for desktop-rule export tests.

```sh
./scripts/update-georesources.sh
./scripts/build-mihomo-mobile.sh
xcodebuild -project ClashParty.xcodeproj -scheme ClashParty -configuration Debug -destination 'generic/platform=iOS' -derivedDataPath /tmp/clash-party-ios-device CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
xcodebuild -project ClashParty.xcodeproj -scheme ClashParty -configuration Debug -destination 'generic/platform=iOS Simulator' -derivedDataPath /tmp/clash-party-ios-simulator ARCHS=arm64 CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
```

`MIHOMO_CORE_ROOT` can override the source location. The script builds ARM64 device and simulator slices into ignored `Vendor/MihomoMobile.xcframework`; the simulator slice is for UI/debugging and has no usable TUN. See the core's `SOURCE.md` and `LICENSE` for provenance.

The unsigned CI artifacts are build checks, not installable VPN distributions. Real-device installation requires the developer's own signing identities, provisioning, App Group and Network Extension entitlements. Set personal values in ignored `Config/Local.xcconfig`; never commit keys, certificates, profiles or Team values. The manual `build-install-run-device.sh` is deliberately excluded from CI because it can install and launch on a connected device.

## Policy and supported runtime

Nodes, credentials, subscription URLs and user exceptions are imported configuration, not software defaults. The bundled snapshot is a small public format example, not a personal desktop policy. General routing uses public YAML rule seeds: local discovery stays local, public UDP uses the chosen outbound, non-CN domains are classified before domestic/CDN country shortcuts, and unmatched traffic uses that outbound. Original profile business rules remain available below the mandatory privacy prefix. The prefix routes known public DNS endpoints, encrypted-DNS/STUN ports and public UDP through a verified proxy-only target; local services remain DIRECT. Business DNS uses encrypted proxied upstreams except the two explicit QQ Music audio policies and local-name DNS. See `docs/anti-bypass.md` for the lifecycle and unknown TCP443 endpoint boundaries.

The legacy mobile core supports YAML rule providers but not MRS. Desktop policy export must convert supported providers or fail clearly; it must never ship MRS into this core or silently discard rules. The existing portable snapshot format includes NETWORK transport rules. Desktop-only process rules are intentionally omitted; node credentials are never part of a policy-only export.

Portable snapshots support at most 50,000 rules after provider expansion. The current large desktop `cn-domain` provider exceeds that limit, so the complete desktop main configuration cannot be directly synchronized through this exporter; oversized or unsupported policies fail explicitly without truncation. iOS General Routing instead uses the existing compact `GEOSITE,cn` matcher and public YAML providers to retain the same policy goals. Named public traffic, including unknown domains resolving to CN/CDN IPs, uses the selected outbound; country-IP DIRECT fallbacks apply only after named traffic is classified and retain IP-only domestic CDN access. Node profiles and credentials are imported independently.

This mobile core is a custom 1.10.0 base. It does not support every current desktop protocol or DNS/TUN option; for example Hysteria2 and desktop JS overrides are absent. Keep capability handling in the existing iOS compatibility layer, not a new policy language. REALITY ML-KEM, Fake-IP persistence, DoH and packet-flow lifetime changes retain their existing regression checks.

## Verification

Run `scripts/check-portable-routing.sh` for Swift overlay/snapshot tests and real mobile-core rule matching. The independent GitHub iOS workflow builds unsigned ARM64 device/simulator apps and uploads build artifacts only. It never accesses an iPhone or changes a desktop VPN.

Core failures after system capture retain a drop-only tunnel until the user explicitly stops and reconnects. This is personal Packet Tunnel protection, not managed Always On, and cannot guarantee protection before startup or after removal/disable. Actual device DNS/WebRTC leakage, system-killed extension behavior, background lifetime, memory footprint, Wi-Fi/cellular changes and normal VPN stop still need user device testing. A simulator build or source-level rule test is not evidence of those network results. Geo resources and public seed attribution are listed in `ClashParty/Resources/RuleResources/SOURCES.txt` and `../../modules/mihomo-ios-core/SOURCE.md`.
