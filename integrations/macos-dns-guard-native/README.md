# Native macOS DNS guard

This fixed-purpose helper is a separate macOS component. Clash Party ties it to the existing automatic system DNS setting: first verify the owned core's TCP **and** UDP loopback port 53 listeners, successfully switch system DNS to that loopback listener, then acquire PF protection. If PF verification fails, keep the verified loopback DNS and protection journal while reporting protection as unconfirmed; do not restore a router/public DNS fallback. On normal exit, restore system DNS successfully before releasing protection. A controlled core restart can retain the guard. A crashed app leaves the fixed block in place; the next installed app instance of the same UID can recover its recorded PF reference.

The helper blocks outgoing TCP/UDP port 53 on non-loopback interfaces, for IPv4 and IPv6. It preserves HTTPS/DoH, the QQ Music HTTPS DNS exception, multicast DNS on port 5353, and LAN connections on other ports. It does **not** block arbitrary application DoH/DoT, inspect TLS, hide all traffic metadata, or implement a general VPN kill switch. It does not run before login/boot: the rule is not automatically reinstalled after a reboot.

Apple explicitly documents that [Packet Filter is not API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api). This advanced self-use implementation cannot promise compatibility across macOS releases. A broadly distributed managed product should evaluate Network Extension. Windows uses Mihomo's TUN/WFP path and does not install or run this helper.

## Installation and interface

`node scripts/build-macos-dns-guard.mjs` compiles on a matching native macOS arm64 or x64 runner, ad-hoc signs the binary, and runs only its in-memory self-tests. Output is ignored at `build/native/party.mihomo.dns-guard`. Packaging copies it into `Contents/Resources/files/`; PKG postinstall verifies the signature and installs it as root:wheel mode 4755 at:

```
/Library/PrivilegedHelperTools/party.mihomo.dns-guard
```

Installation and reinstallation do not execute guard commands, reload PF, delete recovery files, or alter existing guard rules. The helper requires the installed `/Applications/Clash Party.app` and bundled core to have root-owned, non-writable files and parent directories. The system `/Applications` directory's root:admin group-writable mode is the sole exception; a user-writable application bundle remains rejected. Writable ACL grants and symlinks in the trusted executable paths are rejected. Both running app and core must satisfy the designated code requirements derived from their trusted installed executables. Ad-hoc builds bind to the exact installed code rather than a public Developer ID identity.

The installed main Electron process calls these argument-vector commands directly, without a shell:

```
party.mihomo.dns-guard start <corePid>
party.mihomo.dns-guard status
party.mihomo.dns-guard stop
```

The real caller UID, actual parent PID, process start time and installed executable path establish ownership. A core must be a live direct child of that main process, with the same real UID and one of the three fixed bundled core executable paths. Caller-provided paths, commands, rules, anchor names and environment overrides are not accepted. The setuid entry point validates `issetugid()`, uses a restrictive umask, changes to `/`, and supplies a fixed clean environment to the two allowed absolute system utilities (`/sbin/pfctl` and `/usr/sbin/lsof`). It does not invoke a shell or the legacy HTTP helper.

Successful stdout is one JSON object with fixed keys, for example:

```json
{ "active": false, "ownerUid": 501, "corePid": null, "reason": "DNS guard is not active" }
```

A rejection or failure also emits that schema with a reason and exits nonzero. Errors report `active:false` as an unverified result; they do **not** assert that retained protection was removed. Start/status have a shared 3.4 second command budget and 3.5 second in-process watchdog. Stop uses a 1.4 second budget and 1.5 second watchdog. The watchdog terminates its currently owned utility and exits; Node also applies its own outer timeout.

## PF ownership and recovery

Only the fixed per-UID anchor `com.apple/000.ClashPartyAutoDNS.<uid>` is loaded or cleared. The helper requires the existing unconditional system `com.apple/*` filter anchor, verifies no earlier anchor/quick-pass can override it, requires its child anchor to be first in wildcard order, and rejects skipped non-loopback PF interfaces. It does not edit `/etc/pf.conf`, flush global rules or states, or call `pfctl -d`.

Status reads actual PF enable state, anchor rules, anchor order, interface skip flags and existing external port-53 states. It does not equate a journal entry with active protection. Existing PF states can bypass newly installed filter rules: start installs the fixed anchor and then checks for external port-53 states before reporting active. It reports an error if any remain, and leaves loopback DNS, the anchor and recovery evidence for a later retry after natural expiry. Rejecting such states before installing the anchor would allow ongoing background queries to prevent initial protection forever, so the preflight deliberately does not do that. It never flushes another application's states.

State is root-only under `/private/var/db/party.mihomo.dns-guard`, with `O_NOFOLLOW`, a global `flock`, atomic rename and file/directory `fsync`. Before `pfctl -E` can execute, the helper spawns it suspended, records the child PID and acquisition time durably, and then resumes it with output directed to a root-owned journal. PF reference readback recovers the token belonging to that recorded child if the helper crashes before persisting the token. Only that reference can be released. PF reference parsing is deliberately conservative; incompatible readback fails instead of guessing ownership.

Normal stop persists its intent, clears only its own anchor, verifies that anchor is empty, releases its own enable token if still present, and verifies that token is absent before returning success. Repeated stop is safe. An explicit root administrator can recover a crashed session without a running app:

```
sudo /Library/PrivilegedHelperTools/party.mihomo.dns-guard stop --uid 501
```

Only a real root invocation may select a UID. Ordinary app invocations cannot select another UID. A still-running other installed main process of the same UID retains its lease; root recovery is the deliberate exception. There is no promise against an administrator, malicious code executing inside the trusted app, or another privileged network filter changing PF later.

Before acquisition, `/etc/resolver/*` entries are checked conservatively. Only root-owned, non-writable regular files with numeric loopback nameservers are accepted; multiple resolvers, IPv6, CRLF and optional `.port` syntax are handled. A hostname such as `localhost`, malformed values, public resolvers and custom unreadable entries require explicit review. Entries are never rewritten or removed.

## Validation boundary

`--self-test` exercises pure numeric/ownership, resolver, PF output, state and JSON schema fixtures without root access, PF commands, installation or network changes. A successful build and these self-tests establish source/package behavior only. Real PKG installation, setuid authentication, listener ownership, PF containment, normal exit/crash recovery, Sleep/Wake, Internet Sharing, AirDrop/Continuity, and other network filters need separate authorized testing on each supported macOS version. Do not claim those runtime tests have passed merely because CI compiled the helper.
