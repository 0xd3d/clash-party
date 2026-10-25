# Three-platform privacy architecture

Desktop and iOS live on the same branch. `apps/ios` contains the Swift app and Packet Tunnel extension; `modules/mihomo-ios-core` contains the reproducible, separately versioned mobile core. Desktop still uses its prepared Mihomo binaries. An iOS source merge does not establish identical core versions or universal profile compatibility.

## Shared protection target

While the user has enabled a protected tunnel, ordinary application DNS and TCP/UDP traffic should follow the effective profile; private/LAN and China/direct decisions happen inside that policy. The profile owns nodes, credentials, upstream DNS, outbound groups and deliberate exceptions. No production node, operator preference or private desktop snapshot belongs in application source.

| Platform | Implementation                                                                                                                        | Important boundary                                                                                                                                                                   |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| macOS    | Verified loopback system DNS plus the installed, fixed-purpose native PF DNS guard                                                    | PF is not Apple's supported product API. Existing external DNS states prevent a confirmed result until they expire. It is not a full traffic kill switch.                            |
| Windows  | Mihomo TUN, strict route, DNS interception and native WFP behavior, with privilege and live startup checks                            | No parallel application firewall or persistent WFP service is installed. Core/app failure is not a promise of permanent OS-wide blocking.                                            |
| iOS      | NetworkExtension `includeAllNetworks`, local DNS, IPv4/IPv6 capture, encrypted node bootstrap and explicit IPv6 discard when disabled | Apple retains system exceptions. Provider transport/bootstrap must be distinguished from client traffic. Physical Wi-Fi/cellular, NAT64 and background behavior need device testing. |

The macOS helper follows the existing automatic system DNS setting. It accepts only fixed start/status/stop operations, authenticates the installed app and bundled core, and maintains only its own PF anchor/reference and root-owned recovery records. It never executes profile scripts or caller-supplied firewall rules. Normal exit restores DNS and releases its guard; failed or interrupted recovery retains evidence rather than pretending success. Core termination starts after a bounded DNS recovery grace period so a slow helper cannot starve process cleanup. See [native guard](../integrations/macos-dns-guard-native/README.md).

On iOS, failed unused hostname candidates do not prevent a working literal-IP node from starting. Actual hostname use stays on independent encrypted IP-endpoint resolvers; failure does not fall back to the system resolver. An imported business DNS policy remains a user policy, so the app must not claim that every arbitrary profile sends all DNS through a Korean node. Supported routing can be exported as a portable policy using the iOS tools; unsupported MRS is converted by the existing desktop core, never approximated by a new rule engine. Expansion is capped at 50,000 rules, so the current large desktop master profile cannot be synchronized in full through that exporter. Oversized profiles fail explicitly; iOS General Routing reuses compact GeoSite data and public YAML providers, while node credentials are imported independently. See the [iOS compatibility limits](../apps/ios/README.md#policy-and-supported-runtime).

## Browser boundary

A browser extension is optional defense in depth. Full routing/DNS interception is a system responsibility. The bundled Chrome/Edge extension additionally controls WebRTC IP handling per browser profile; Electron's setting covers only the app's own pages. Safari/iPhone does not offer the equivalent Chromium privacy API. Neither a visible extension switch nor the country count of recursive resolvers is proof of complete containment.

## Build and validation

Desktop CI builds native Windows/macOS x64 and ARM64 packages and publishes complete, gated Releases. The independent iOS workflow rebuilds its mobile core, runs Swift/Objective-C/Python/Go regressions and compiles unsigned device/simulator apps. Unsigned device artifacts are not installable signed IPAs. Local signing uses ignored `apps/ios/Config/Local.xcconfig`; CI never reads a personal Team, certificate, provisioning profile or node credential.

`apps` and `modules` are excluded from desktop ASARs; the package verifier checks this boundary. Frameworks, derived data, signing materials and downloaded Geo databases are excluded from Git. Source/build tests do not replace physical network validation.

Acceptance evidence must separately cover system DNS ownership, fresh LAN/public UDP/TCP 53 sockets, HTTP and WebRTC egress, real IPv6 transport, expected LAN access, Wi-Fi/cellular or interface changes, core failure/recovery and normal exit. Tests must retain configured DNS exceptions. Do not disable a required VPN or restart an active client merely to obtain a baseline.

References: [Apple VPN routing](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic), [Apple PF limits](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api), [Mihomo TUN](https://wiki.metacubex.one/en/config/inbound/tun/), [Chrome privacy API](https://developer.chrome.com/docs/extensions/reference/api/privacy), [RFC 8828](https://www.rfc-editor.org/rfc/rfc8828.html).
