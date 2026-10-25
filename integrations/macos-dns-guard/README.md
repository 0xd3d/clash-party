# macOS administrator session DNS guard

This is an optional, administrator-operated advanced tool. It is **not** enabled automatically by Clash Party, and it is not a Windows component. Its lifetime is bound to the explicitly supplied, currently running installed app PID. Ctrl-C or that app exiting removes only its own PF anchor and enable reference. Starting the app again does not silently restart this tool.

First enable the app's loopback DNS listener and system DNS takeover. Review `guard.sh`, then run it with `sudo /bin/sh /path/to/guard.sh <current-app-pid>` from a Terminal that remains open. Do not paste an old PID. The script verifies the executable path and user, checks local DNS readiness, requires the existing system `com.apple/*` anchor, and checks the rule syntax before loading its unique child anchor.

The fixed rule blocks outgoing TCP/UDP 53 on every non-loopback interface. It keeps localhost DNS, HTTPS/DoH, multicast DNS port 5353 and LAN services on other ports. Apps that insist on an external or LAN plaintext resolver will fail instead of bypassing the resolver. Existing PF states are preserved; verify with fresh sockets. Interface skip flags and interference from other network tools still need checking.

It never edits `pf.conf`, flushes the main ruleset/state table, or globally disables PF. `-E` acquires its own reference and `-X` releases only that reference. No permanent privileged service or setuid executable is installed. The regular macOS DNS journal is a separate layer; this tool does not replace it or restore adapter DNS.

Apple explicitly documents that [Packet Filter is not API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api). This personal-use tool does not establish long-term macOS compatibility. Internet Sharing, AirDrop, Continuity and Xcode device connectivity require separate compatibility testing. For a broadly distributed, permanently managed product, evaluate Network Extension rather than extending this script into a privileged shell service.

Windows uses Mihomo's own DNS/TUN/WFP behavior and must not run this tool. On either platform, source checks and a successful package build are not proof of real network containment.

Before activation, the guard refuses conflicting `/etc/resolver/*` entries pointing outside loopback. Such entries take precedence over adapter DNS and can break domain resolution once plaintext DNS is blocked. Review each entry with its owner and back it up before intentionally removing it; never delete an entire enterprise resolver directory.
