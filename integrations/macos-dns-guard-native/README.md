# Native macOS DNS and opt-in traffic guard

This fixed-purpose helper is a separate macOS component. Clash Party ties it to the existing automatic system DNS setting: first verify the owned core's TCP **and** UDP loopback port 53 listeners, successfully switch system DNS to that loopback listener, then acquire PF protection. If PF verification fails, keep the verified loopback DNS and protection journal while reporting protection as unconfirmed; do not restore a router/public DNS fallback. On normal exit, restore system DNS successfully before releasing protection. A controlled core restart can retain the guard. A crashed app leaves the fixed block in place; the next installed app instance of the same UID can recover its recorded PF reference.

In its DNS-only mode the helper blocks outgoing TCP/UDP port 53 on non-loopback interfaces, for IPv4 and IPv6. It preserves HTTPS/DoH, the QQ Music HTTPS DNS exception, multicast DNS on port 5353, and LAN connections on other ports. It does **not** block arbitrary application DoH/DoT, inspect TLS, hide all traffic metadata, or implement a general VPN kill switch. It does not run before login/boot: the rule is not automatically reinstalled after a reboot.

Apple explicitly documents that [Packet Filter is not API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api). This advanced self-use implementation cannot promise compatibility across macOS releases. A broadly distributed managed product should evaluate Network Extension. Windows uses Mihomo's TUN/WFP path and does not install or run this helper.

## Installation and interface

`node scripts/build-macos-dns-guard.mjs` compiles on a matching native macOS arm64 or x64 runner, ad-hoc signs the binary, and runs only its in-memory self-tests. Output is ignored at `build/native/party.mihomo.dns-guard`. Packaging copies it into `Contents/Resources/files/`; PKG postinstall verifies the signature and installs it as root:wheel mode 4755 at:

```
/Library/PrivilegedHelperTools/party.mihomo.dns-guard
```

Installation and reinstallation run only the fixed root-only `install-identity` metadata operation described below. They do not reload PF, delete recovery files, or alter existing guard rules. The helper requires the installed `/Applications/Clash Party.app` and bundled core to have root-owned, non-writable files and parent directories. The system `/Applications` directory's root:admin group-writable mode is the sole exception; a user-writable application bundle remains rejected. Writable ACL grants and symlinks in the trusted executable paths are rejected. Both running app and core must satisfy the designated code requirements derived from their trusted installed executables. Ad-hoc builds bind to the exact installed code rather than a public Developer ID identity.

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

## Opt-in traffic protection

The separate `networkProtection` application option is off by default. Source code and a successful package build do not enable it on the current computer. Enabling it is an explicit request to route ordinary public traffic through the owned TUN first, then let Mihomo apply the existing proxy/DIRECT policy. Domestic traffic and QQ Music continue to use the profile's DIRECT and HTTPS DNS exceptions through the core; they are not converted into OS firewall country-IP exceptions.

The additional fixed commands are:

```
party.mihomo.dns-guard traffic-arm utun<number> [--close-old-public]
party.mihomo.dns-guard traffic-start <corePid> utun<number>
party.mihomo.dns-guard traffic-status
party.mihomo.dns-guard traffic-stop
party.mihomo.dns-guard repair-core
```

`traffic-arm` validates the installed bundle/private identity and installs a fixed deny rule set **before** spawning a new core. It does not permit any unauthenticated TUN interface. The isolated core's effective socket group can establish its transport and encrypted DNS during startup. `traffic-start` then verifies the live core, its real/effective/saved identities, and its kernel utun control socket before permitting that actual TUN device. Neither command accepts physical interface names, arbitrary rules, paths, addresses or firewall arguments.

Traffic mode blocks non-loopback plaintext TCP/UDP port 53 **before** any LAN, TUN or core allowance. It permits loopback, the owned TUN, RFC 1918/ULA/link-local LAN traffic, local multicast/mDNS, DHCP and necessary neighbor/path-MTU control traffic. Only TCP/UDP sockets with the isolated effective group can otherwise reach public interfaces; other public IPv4/IPv6 traffic is denied in both directions. Rules use `no state`, so a later inbound connection cannot create a new PF state that silently bypasses the outgoing guard. It does not whitelist UID 0 or all administrator/root services. A root daemon with a different group is subject to the same public restriction as an ordinary app.

The private group is `_clashpartycore`. A future PKG installation chooses an unused numeric GID and creates an empty local OpenDirectory group atomically with a generated UUID; it never adds users or nested groups. The root-owned `identity.json` records that exact identity. The three fixed, signed, root-owned core executables get mode `6755` and that group. Ordinary installation errors restore their previous inode-specific ownership/modes and remove only the newly owned group. A root-only installer intent supports interrupted transaction recovery; a committed identity is never deleted merely because final journal cleanup failed. A pre-existing unrecorded group is rejected. Installer failure also restores the previous native helper file. No PF rules, traffic leases or DNS records are removed by installation.

`repair-core` can only repair metadata for those same three trusted executables, using the already recorded and empty group; it cannot create a group or execute caller commands. Existing processes retain the group they inherited when launched, so the app must perform a normal protected core restart after repair. Group credentials can also be inherited by descendants of the trusted core. This mechanism is not a sandbox against a malicious local administrator or code deliberately run by that core.

DNS and traffic use two independently recorded leases in the **same** anchor. DNS-only refresh cannot downgrade traffic mode, and DNS-only stop cannot release its traffic lease. Traffic stop returns to DNS-only mode if its DNS lease remains. Replies add `dnsLease`, `trafficLease`, `protection` (`dns`, `traffic`, or `none`) and optional `tunDevice`; `active` confirms the remaining actual mode rather than implying every lease was released. A confirmed pre-spawn arm has `active:true` with `corePid:null`. Consumers must check the requested lease, not infer complete removal from an unrelated stop operation. Existing DNS-only command shapes remain supported.

Start/arm have an eight-second in-process watchdog; traffic status/stop use 5.5 seconds. The root-only installer operation has a 30-second bound. A rejected or timed-out operation retains its journal and any installed barrier rather than quietly restoring a public fallback.

### Existing connections and recovery

A newly installed PF rule does not retroactively cover previously admitted states. First activation audits the complete numeric state output, current-core descriptor/socket group credentials and strict lsof endpoint records. Connected core TCP/UDP states can be recognized; unconnected UDP additionally requires an unambiguous system-wide socket binding. Unknown formats, NAT mappings, ambiguous endpoint ownership and unrelated old public states prevent an active result.

`--close-old-public` is permitted only for an application action that clearly tells the user that enabling protection may interrupt **existing public and old plaintext-DNS connections**. After the new fixed barrier is installed, the helper derives exact numeric local-address/peer pairs from its complete readback and uses Apple's host-pair `pfctl -k` operation. It never accepts an address from the caller, uses a wildcard/network prefix or flushes all states. A LAN resolver pair is eligible only if every state for that pair is port 53; mixed SSH/router-UI pairs are preserved and remain unconfirmed. Shared core connections to a cleaned public peer may need to reconnect. Unsupported or ambiguous cases remain unconfirmed. No old-state cleanup is run by compilation, self-tests, installation or default settings.

Once protection is confirmed, the recorded lease, current boot, owned enable token, exact bidirectional rule readback, anchor ordering and interface skip checks establish continuity. A core crash does not discard that evidence or require a vanished core PID to re-prove its old TIME_WAIT states. Releasing the traffic lease, losing its token, changing the group/boot or losing actual rule evidence requires a new audit. The barrier remains after an abnormal app/core exit; a normal exit or explicit disable releases the appropriate leases. Administrator recovery `stop --uid <uid>` releases both leases after verifying actual removal.

This is a personal-use PF barrier, not a supported Apple Always-On VPN or a universal OS-wide kill switch. It is not loaded before the app starts after reboot, and it does not protect against another privileged network filter altering PF, a malicious administrator, trusted-core policy abuse or every OS/kernel control path. Publicly addressed local subnets outside the listed private/link-local LAN ranges need separate compatibility evaluation. Apple documents Network Extension as the supported product path. Live installation, effective-group/socket behavior, state cleanup, IPv6, core failure/reconnection, LAN/QQ Music, AirDrop/Xcode and interface changes remain separate authorized runtime tests; none are certified by the source tests.
