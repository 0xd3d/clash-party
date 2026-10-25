# Runtime integration

The Packet Tunnel owns Network Extension settings and packetFlow. The existing Swift compatibility layer produces supported mobile YAML; the C bridge starts, reloads and stops the source-built mobile core. Desktop networksetup/PF/WFP code is never used on iOS.

Keep app signing and user policy outside source control. See the app README and mobile core SOURCE.md for build and verification boundaries. Simulator slices validate UI/build plumbing only; real tunnel behavior requires a signed device build and explicit user testing.
