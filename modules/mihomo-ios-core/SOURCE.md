# iOS mobile core source

This is a source snapshot of the locally maintained iOS core, based on [hiddify/Clash.Meta](https://github.com/hiddify/Clash.Meta) commit `bf3c6a044c38a83c8f54aa322a4b3770ef00acf3` (the module retains `github.com/Dreamacro/clash`). The source here includes the local iOS changes; checking out the base commit alone does not recreate this snapshot.

The imported inventory contains 551 files. `SOURCE-SNAPSHOT.sha256` lists their SHA-256 digests, excluding this provenance text, the inventory itself and monorepo integration tests. Its SHA-256 is `92d412ae813f15324f31f6ee67391c7de94ef5d4555ee3ed96800f29165c5ec9`. This inventory records the initial imported snapshot; later source changes are recorded by the enclosing repository's Git history.

The original `LICENSE` is GPL-3.0. Preserve it, upstream notices and dependency licenses when distributing the linked core. The encompassing desktop fork also uses GPL-3.0. Go dependencies remain identified by `go.mod` and `go.sum`.

The mobile core is a custom 1.10.0 base with the iOS packet-flow bridge, REALITY compatibility, DoH preservation and memory refinements. It is not the desktop 1.19.x core and does not gain desktop-only formats or protocols by sharing this repository. The 24 MiB Go memory budget is not a guarantee that an iOS Network Extension stays below the system's total process limit.

Build it from `apps/ios/scripts/build-mihomo-mobile.sh`. Do not commit generated archives, XCFrameworks, app bundles, device profiles or the former standalone `iosbridge` executable. No server credentials or signing keys belong here.

The iOS build also requires an independent encrypted resolver for proxy endpoint
hostnames. It selects only already configured HTTPS endpoints with literal IP
addresses and an empty/DIRECT adapter from `proxy-server-nameserver` and
`default-nameserver`. Main application DNS, policies, fallbacks and user exceptions
are preserved. Endpoint lookup failures never fall back to application or system
DNS; a literal node IP or a valid static hosts entry still requires no network
DNS. This baseline is internal to the iOS core, not an added configuration DSL.

The four small `component/ebpf/*/bpf_*.o` files are unchanged, tracked upstream
objects required by that source tree's `go:embed` directives, not local iOS build
outputs. Their corresponding sources and generation directives are preserved.
They are excluded by the original platform build tags from the iOS runtime.

On iOS, Geo downloads also enter the existing core HTTP/inner transport and its
rules. A cold start requires bundled/cache resources; it cannot temporarily use
a direct system HTTP/DNS client. Failed downloads retain complete cache files.
The inner transport is initialized before provider warmup and honors request
cancellation while its queue is unavailable or saturated. Other platforms retain
their original Geo download behavior.
