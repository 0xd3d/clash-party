# macOS system DNS lifecycle

This fork adds application-owned local DNS takeover to the existing macOS TUN setting. It reuses the installed Clash Party helper (`POST /dns`) for per-service DNS. The PKG also installs a separate, fixed-purpose native DNS guard; it does not modify the original helper protocol or install a new background daemon. See [the guard security/lifecycle notes](../integrations/macos-dns-guard-native/README.md).

## Behavior

- With automatic system DNS enabled, the effective runtime DNS listener uses the configured loopback address on UDP/TCP port 53 (default `127.0.0.1`). Core DNS and TUN must both be enabled.
- The core API and both local DNS transports must be ready before any network-service DNS is changed. TCP and UDP binding evidence must also come from that exact core process’s stdout, so an unrelated program answering on port 53 cannot satisfy readiness. Public DNS addresses are not accepted as the takeover target.
- Enabled physical `en*` and `bridge*` network services receive separate backups. Disabled and tunnel/VPN services are skipped. The application reconciles service changes every five seconds while its core is running. Decisions use the last successfully applied runtime snapshot, never an uncommitted candidate configuration.
- Each backup is atomically persisted in `system-dns-state.json` with owner-only permissions before changing that service. Records include the service name and device; restoration never uses a different current default interface.
- Normal exit first attempts to restore managed DNS. Core termination starts after a two-second recovery grace period even if DNS recovery is slow; guard release can run alongside core teardown only after successful DNS restoration. Recovery does not require an Internet connection. A restoration failure retains the affected backup; other services can still restore independently.
- Transient DNS/upstream failures and forced automatic core restarts do not switch back to router/public DNS. If automatic core recovery is exhausted, loopback DNS is deliberately retained while the application remains open; normal application exit still restores its saved settings. If an operator changes a service to another DNS while it is managed, restoration respects that new value.
- The upstream configuration and domain DNS policies are preserved. Tests cover Cloudflare DoH routed through an outbound group and the existing QQ Music DNSPod exceptions.

## Settings and migration

In macOS TUN settings, enable automatic system DNS, select the loopback address, and select the exit restoration policy:

- **Previous settings** preserves each service's configured DNS or automatic/DHCP state. This is the default.
- **Automatic (DHCP)** explicitly requests automatic DNS on exit for services newly taken over in that session. Existing recovery records keep their previously saved values until restored.

If the service already points to `127.0.0.1` or `::1` but there is no service-specific recovery record, the application cannot infer its earlier DNS. Previous-settings mode refuses to treat that unowned loopback setting as a usable original value. Restore the known original DNS before first use, or explicitly select automatic/DHCP restoration when that is the intended original state. Legacy `originDNS` has no service identity and is not blindly assigned to another interface.

Saving the listener address or toggling automatic system DNS in the TUN page uses the existing hot-reload flow. The application validates the successfully loaded listener before applying the new system DNS target; it does not silently use an unready address. Normal DNS-policy updates continue to use that same configuration loading flow.

## Boundaries

A forced process kill, system crash or power loss cannot execute Electron exit handlers. The persistent recovery records are retried before the next core startup; this version does not promise immediate crash-time restoration. That requires a separately surviving helper/watchdog.

Application exit cleanup has a twelve-second total budget, including a bounded DNS recovery grace period, SIGINT/SIGKILL fallback and native guard recovery. DNS helper requests and network-service reads are bounded, and per-service restoration runs concurrently. Failed or interrupted recovery keeps its journal instead of reporting a successful restoration.

The existing DNS helper must be available. Failures are recorded in application logs; this feature does not introduce an unbounded administrator prompt during shutdown. A deleted or renamed service is retained for investigation rather than restored to an unrelated service.

A custom build should be tested with a disposable configuration before replacing an installed application. This repository change does not alter, stop, restart or install over an already running Clash Party. Upstream update packages do not contain this fork's changes; use builds from this fork when deploying the feature.

## Validation

The controller and transport tests use injected dependencies or mocked sockets. They never invoke the real DNS helper or change host network settings. They cover per-service backups, DHCP and multiple original addresses, cancellation during an in-flight operation, durable partial recovery, operator changes, migration, UDP/TCP readiness, and preservation of upstream DNS policies.

Real application startup/exit, sleep/wake, physical network switching, BrowserLeaks and music playback still need validation after an authorized installation. Source checks and builds do not substitute for those checks.

## Automatic native DNS guard

Automatic system DNS now requires confirmed native filtering before protected startup is reported ready. Reconciliation first migrates physical services to the verified loopback resolver, then installs/read-checks the guard. If PF cannot confirm filtering, loopback DNS and recovery records remain; the app does not restore a router fallback. This order lets ordinary external DNS states expire without continuously generating new ones. The helper refuses to call existing external port-53 states protected and does not flush them.

The PKG-installed helper accepts only an authenticated installed app and owned bundled core. Development or manually moved app bundles do not silently acquire privileged PF access. A normal explicit stop releases only its own anchor/reference. Controlled core restarts retain protection; an app crash leaves kernel rules and recovery records for a later authenticated session or root-only recovery. This protects plaintext port 53, not arbitrary encrypted DNS or every protocol.
