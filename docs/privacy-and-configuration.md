# Privacy features and user configuration

The application manages capabilities; profiles manage network policy. A server move or routing change must not require rebuilding the application.

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
