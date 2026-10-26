# Windows session network guard

This is a fixed-purpose, user-mode Windows Filtering Platform (WFP) owner. It is built with the Windows SDK for native x64 and ARM64. It is not a kernel driver, a Windows service, a browser extension, or a permanent firewall policy. Building and `--self-test` do not install rules or require elevation.

The feature is opt-in. Nothing in this source or build process changes a currently running application or host network. Runtime commands require an elevated process under the same user and Windows session. The app must launch the helper independently with `start`, then explicitly arm it before starting the core.

## Fixed CLI contract

`party.mihomo.network-guard.exe` supports only:

- `start`: launch this exact executable with `CreateProcessW` and explicit job breakaway, support explicit/silent breakaway and verify the suspended child belongs to no job, then resume and confirm readiness through authenticated IPC. Only startup standard handles are inherited. A host job prohibiting breakaway is an explicit native startup error. The desktop app can then use a temporary same-user Task Scheduler task to run this same fixed `start` command outside the app Job; the guard must still pass the unchanged all-ancestor Job check. No service, policy relaxation or existing-guard termination is used. Native startup errors are returned directly.
- `serve`: run the foreground server (used internally by `start`), emit `READY` after reserving ownership and creating the command pipe. A helper inheriting a Windows job refuses to serve instead of claiming crash survival. Running `serve` directly from Windows Terminal may therefore fail; use `start`.
- `status`: report the existing server's state. Only an absent pipe means inactive; authorization, identity, busy and timeout failures return an error.
- `arm --core-path <absolute exe> --tun-name <applied virtual alias>`: install the guard before core startup. The PID and TUN identity are null. No interface permit is installed, even if a matching interface already exists; public egress remains blocked until verified acquisition.
- `acquire --core-path <absolute exe> --core-pid <pid> --tun-name <applied virtual alias>`: verify a live elevated core process and the actual Wintun adapter, then atomically replace the session's rules and status.
- `release` or `recover`: remove this server's dynamic rules and exit it. An already absent server is an idempotent inactive result.
- `--self-test`: run only in-memory protocol and address-scope fixtures. This branch does not open BFE, inspect network adapters, start IPC, install anything, or request elevation.

Successful status/arm/acquire/release responses are one JSON object on stdout:

```json
{
  "protocolVersion": 1,
  "active": true,
  "guardPid": 100,
  "corePid": 200,
  "coreAlive": true,
  "corePath": "C:\\App\\resources\\sidecar\\mihomo.exe",
  "tunName": "Configured Virtual Alias",
  "tunLuid": "123456",
  "tunIndex": 20,
  "filterCount": 48
}
```

`guardPid` is null when no server exists. `corePid`, `tunLuid`, and `tunIndex` may be null while armed before startup; `coreAlive` is then false. `tunLuid` is a decimal string, avoiding JavaScript integer precision loss. Errors exit nonzero with `{"protocolVersion":1,"error":"..."}` on stdout. A successful `release` response has `active:false`; it can still contain the server PID immediately before the server exits.

The helper derives its local message-pipe name from its SID and Windows session. Both ends verify the peer PID, elevated token, same SID/session and canonical helper image path. The pipe rejects remote clients, has a protected same-user/System DACL, allows one instance, limits messages to 64 KiB, validates field lengths/opcodes and bounds connected I/O to three seconds. A machine-wide owner mutex prevents different users/sessions from stacking conflicting global guard policies. These rules cover system traffic and may affect other logged-on users; this is an OS protection mode. The helper never executes a path supplied over IPC or accepts a shell command.

Core exceptions are restricted to `resources/sidecar/mihomo.exe`, `mihomo-alpha.exe` or `mihomo-smart.exe` beside this helper's own `resources/files` directory. Canonical paths and a held file handle prevent replacing the whitelisted file during a guard session. Core updates therefore require explicit guard release first. Acquisition also checks the process image, user, elevation and live process handle. A reused numeric PID cannot silently replace that held process identity.

TUN lookup uses the configured alias, obtains its actual LUID/index, requires `IF_TYPE_PROP_VIRTUAL`, rejects hardware/connector interfaces, and matches the adapter GUID to the `Wintun` device service. A profile cannot substitute a Wi-Fi/Ethernet alias. No physical interface name or index is hardcoded.

## Desktop fallback for restrictive parent Jobs

When native `start` specifically rejects inherited Job ownership, the app registers one uniquely named on-demand task (`ClashParty-NetworkGuard-<UUID>`) with the current elevated user's interactive token and current session. It invokes only the bundled helper's fixed `start` command. There are no automatic triggers, stored passwords, SYSTEM-account execution, or user-supplied commands. The temporary task's DACL permits only administrators and SYSTEM; registration uses create-only, never replacement. The launcher registration is deleted after completion or failure, without stopping a running guard. A launch timeout preserves any already-running protection.

Task completion is followed by the existing authenticated `status` protocol before arming. Scheduler failure, blocked Job escape, failed cleanup, absent helper or peer mismatch remain startup failures. No `serve` exception or relaxation of native Job checks is used. App/core launch errors are written to the application log as well as shown in the UI. CI additionally exercises this path with an unarmed helper, checks it survives its launcher exiting and then recovers only that fixture; it does not open WFP or change network settings.

## Filtering and recovery

The helper owns one dynamic WFP session, a fresh provider and a fresh sublayer. It adds filters at the IPv4/IPv6 ALE connect and receive/accept layers. Within its own sublayer it permits the exact core AppID, loopback, the verified TUN LUID and narrow LAN/link-local scopes. Physical port 53 is blocked before LAN exceptions. DHCP is restricted to the actual Windows `svchost.exe` AppID and its DHCPv4/v6 client/server ports; local IPv6 discovery also remains possible. All remaining IPv4/IPv6 traffic is blocked, including arbitrary-port UDP and application HTTPS connections bypassing the TUN. Domestic direct traffic and QQ Music continue through the core's existing routing rules; they are not globally changed into proxy traffic.

Exceptions use default **soft permits**, with no clearing of action rights. The final filter uses the default **hard block**. Other providers' firewall blocks can still veto these exceptions. The helper never disables Windows Firewall, changes another provider's rules, installs persistent/boot filters, or enumerates/deletes arbitrary filter IDs. Policy replacement uses a single WFP transaction; any candidate validation or transaction failure retains the old rules and state.

The helper remains alive and retains rules after a core or app crash. Automatic core restarts replace policy atomically; they must not call `release`. Normal user stop, disabling this feature, or explicit recovery calls `release`. If the app has crashed, run this exact installed helper's `recover` command from an elevated terminal under the same user. Ending this helper process also ends its dynamic session and removes its rules. This is an intentional recovery path and a protection boundary: helper failure, BFE/OS shutdown and reboot do not retain protection. There is no claim of kernel/service persistence.

This helper prevents egress bypassing the TUN. It does not inspect STUN payloads, force all core-routed traffic through a proxy, or change external browser settings. Browser WebRTC controls and the app's selected DoH/UDP policy are separate requirements: a core deliberately routing STUN directly could still expose the direct exit address.

## Build and validation

On a matching native Windows x64/ARM64 host with Visual Studio C++ tools and the Windows SDK:

```sh
node scripts/build-windows-network-guard.mjs --x64
```

Use `--arm64` on ARM64. The script discovers MSVC, compiles with warnings as errors, checks the PE architecture, and runs `--self-test` plus a separate unprivileged process-launch fixture. The fixture verifies escape from explicit/silent synthetic app jobs, survival after those jobs close, rejection when breakaway is prohibited, startup error preservation and the production all-ancestor check. Hosted CI can retain a restrictive root job: the fixture records `restricted-parent-job` and verifies rejection before execution rather than claiming the runner has certified an independent production guard. It cannot open WFP or start the real guard. The result is generated under `build/native/windows/<arch>/`; electron-builder copies it only into Windows resources as `files/party.mihomo.network-guard.exe`.

Portable policy fixtures also compile with a C++17 compiler on macOS/Linux. Source checks, successful compilation and self-tests establish neither WFP filter acceptance nor real traffic containment. Privileged Windows VM validation still needs startup/arm, core crash, app crash, adapter replacement, arbitrary-port UDP, IPv6, DNS, LAN, domestic direct/QQ Music and explicit recovery tests. Do not perform those tests on a machine whose active app/network must remain untouched.

References: [WFP object lifetimes](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management), [filter arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration), [filter addition](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilteradd0), [ALE reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization), [Wintun adapter type](https://github.com/WireGuard/wintun/blob/master/driver/wintun.c).
