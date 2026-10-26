# Privacy features and user configuration

The application manages capabilities; profiles manage network policy. The repository now includes an independently built iOS app and mobile core; see [three-platform protection](three-platform-privacy.md). A server move or routing change must not require rebuilding the application.

| Layer                         | Responsibilities                                                                                                                                                             |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| User profile / provider files | Nodes and credentials; outbound groups; China/direct and overseas routing; DNS provider URLs and outbound selectors; domain DNS exceptions; public UDP routing; rule sets    |
| Application                   | Existing TUN/permission UI; macOS local DNS lifecycle and recovery journal; read-only privacy configuration checks; portable resource export; Fork-specific updater identity |
| Browser component             | Optional Chrome/Edge WebRTC IP handling policy, independent of the operating system and node configuration                                                                   |

No production server, credential, Korean node name, Cloudflare endpoint or music exception is compiled into application behavior. Domain/DNS values in tests are fixtures. Keep operational profiles outside the Git repository and import them using the existing local-profile flow. Existing profiles, overrides and rule providers remain the supported policy mechanisms; there is no second rule engine or silent subscription rewrite.

## Existing core features

New TUN defaults enable `strict-route` and both UDP/TCP port 53 interception, using Mihomo's existing implementations. TUN itself stays disabled until the user enables it and grants the required platform permissions. Saved user settings take precedence over new defaults; importing a profile is not authorization to rewrite unrelated system preferences.

On Windows, Mihomo's TUN/strict-route implementation owns the virtual adapter and Windows filtering behavior. The application never runs macOS `networksetup` or the macOS DNS helper there. On macOS, automatic system DNS uses the local resolver only after the owning core and UDP/TCP 53 are ready. The listener is added to the generated runtime without changing the profile's upstreams or domain-specific DNS policies. See [the macOS lifecycle and migration notes](macos-system-dns.md).

A DNS exception such as a domestic music CDN remains an explicit user-profile decision. Updating the application must not remove or broaden it. An encrypted DNS transport alone does not establish its outbound route; that route remains subject to the profile and selected proxy.

## Configuration checks

The TUN page can inspect the last successfully applied profile plus live core TUN/general state. It reports interception, routing, DNS transport and outbound hints, explicit exclusions, IPv6 settings and LAN exposure. It does not read an uncommitted profile candidate and cannot replace a packet capture or BrowserLeaks measurement. Domain DNS exceptions are counted, not changed. The report never returns node credentials to the renderer.

The check does not duplicate the existing TUN/DNS controls or automatically edit the user's rules. Review a finding and use those controls or the profile editor for a deliberate change. Unknown provider contents, complex rules and browser behavior still need runtime verification.

## WebRTC boundary

TUN controls packets. Browser WebRTC settings control the interfaces and candidate addresses exposed to websites. A matching HTTP/WebRTC public address in one test does not establish that every browser profile and future network is protected.

Every WebContents created by the application uses Electron's `disable_non_proxied_udp` policy. This covers only the application's own pages. It does not change Chrome, Edge, Firefox, OS policy or another process.

The TUN page can export the separately bundled [WebRTC Guard](../integrations/webrtc-guard/README.md). Chrome and Edge use the same source on Windows and macOS; install it manually per browser profile. It requests only `privacy`, checks whether another extension or administrator controls the setting, and confirms changes by reading them back. Restoring or disabling it removes only its own control. The extension does not start a proxy, select an outbound, intercept TLS or collect browsing data. This Chromium manifest is not a Firefox installer.

Browser policy can affect media calls and can be overridden by enterprise management. Check ordinary and private-window behavior independently. Use the fixed BrowserLeaks link in the UI for a manual test; the configuration check never labels an unperformed test successful.

## Building and updating

Use [the self-build instructions](self-build.md) for modern Windows/macOS targets. Resources must be prepared on the corresponding OS for the target architecture. Update metadata, checksum lookup, package downloads and Release links use a single build-selected GitHub repository so an upstream package cannot silently replace a custom build.

The self-build workflow produces artifacts only. It does not publish a Release, install a package, change the running application, or validate real TUN/DNS/browser behavior. Unsigned/ad-hoc packages and actual installation remain separate from source build checks.

Official references: [Mihomo TUN](https://wiki.metacubex.one/en/config/inbound/tun/), [Chrome privacy API](https://developer.chrome.com/docs/extensions/reference/api/privacy), [Electron WebContents](https://www.electronjs.org/docs/latest/api/web-contents#contentssetwebrtciphandlingpolicypolicy), [RFC 8828](https://www.rfc-editor.org/rfc/rfc8828.html).

## Windows and macOS verification boundaries

Both platforms share the core's routing policy, UDP/TCP 53 hijack settings, encrypted upstream definitions and optional Chromium WebRTC tool. Windows uses the core's native DNS/WFP implementation; macOS uses per-interface loopback DNS takeover. macOS networksetup/helper code never executes on Windows.

On current Mihomo, Windows with auto-route defaults an unspecified DNS mode to hijack. The inspector separately flags explicit disabled/native mode and missing strict-route/auto-route; port rules alone are not proof of other adapters being intercepted. Existing saved settings are preserved. Windows TUN startup requires administrator rights before stopping a working core or spawning a new one. Missing privileges no longer silently persist tun.enable=false. System proxy activation waits for a live, owned core and the requested TUN state, covering initial mode selection and retries. This is not an operating-system-wide kill switch.

An external app that hardcodes a LAN DNS server can bypass the normal TUN route on macOS. A successful browser leak test does not disprove that route. PKG builds now include an authenticated [native DNS guard](../integrations/macos-dns-guard-native/README.md), activated with automatic system DNS and verified against actual PF state. The older [administrator session script](../integrations/macos-dns-guard/README.md) remains an optional advanced diagnostic tool; it is never represented as automatically active. Neither layer is a permanent OS-wide traffic kill switch.

Privacy inspection now checks the applied configuration revision as well as process identity, rejecting a report that spans an in-place hot reload. Windows startup cleanup never terminates an unknown-path process based only on its name. Packaged native modules always prefer their own resources over a source checkout in the working directory.

See [network validation](network-validation.md) for independent tests and proof limits.

## One-click protection setup

On macOS and Windows the TUN page now offers **Preview protection setup**. It compiles a hypothetical standard/rule-mode configuration with TUN, strict/automatic routing, both DNS hijacks, loopback-only proxy listening, native traffic protection and public UDP proxying. macOS also enables the existing system DNS lifecycle. The preview uses a bounded configuration test and its own temporary work/cache directory; it does not persist settings, reload the running core or arm a native guard.

The selected imported profile remains the owner of nodes, encrypted upstreams, independent literal-IP bootstrap, domestic routing and exact QQ Music DNS exceptions. The setup adds no server or DNS provider defaults and does not edit source profile/override files. Incomplete or unsafe profiles fail preflight instead of silently inventing a provider or accepting a DIRECT fallback.

Confirmation consumes a short-lived preview token, recompiles and rejects changed configurations, checks privileges, writes a private local backup, saves app/control settings without intermediate hot patches, then reconnects the core once through the existing manager. Settings already applied to a live verified core do not trigger another restart. A settings-write failure can roll back before startup; a failed native arm/start retains protection intent and never silently releases a barrier. The existing explicit recovery action remains available.

Preview/compile success is not Windows or macOS packet containment verification. The result checks the applied native guard; browser, interface switching and crash scenarios remain independent runtime tests. This feature is user initiated and never runs automatically on import, installation or build.
