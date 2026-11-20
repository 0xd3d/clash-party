# macOS boot leak guard

Fixed-purpose LaunchDaemon that arms before login: system DNS is pinned to loopback and PF blocks non-loopback egress except LAN, DHCP, and configured proxy server IPs. When Mihomo loopback listeners are ready, only the boot egress deny is lifted; DNS is not restored to ISP or router DNS. Disabling uses the app’s `macBootLeakGuard` setting via `boot-leak-policy.json`.

Windows does not compile or ship this component. `node scripts/build-macos-boot-leak-guard.mjs` runs pure `--self-test` fixtures only (no live PF).

Apple documents that [Packet Filter is not API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api); treat real-device enforcement as a separate validation step.
