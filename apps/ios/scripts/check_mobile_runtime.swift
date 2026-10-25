import Foundation
@main struct MobileChecks {
 static func main() throws {
   let service = CompatibilityService()
   let profile = """
   proxies:
     - name: Native
       type: vless
       server: 198.51.100.10
       port: 443
       uuid: 00000000-0000-0000-0000-000000000001
       tls: true
       reality-opts:
         support-x25519mlkem768: true
   proxy-groups:
     - name: Internet
       type: select
       proxies:
         - Native
   rules:
     - MATCH,Internet
   """
   let controlled = """
   mode: rule
   mixed-port: 7890
   dns:
     enable: true
     enhanced-mode: fake-ip
     fake-ip-range: 198.19.0.1/16
     fake-ip-filter:
       - '*.lan'
       - '*.local'
     direct-nameserver:
     - 1.2.3.4
     respect-rules: true
     fake-ip-filter-mode: rule
     proxy-server-nameserver-policy:
       'example.com': 1.1.1.1
     nameserver:
       - 223.5.5.5
     proxy-server-nameserver:
       - 223.5.5.5
   tun:
     enable: true
     stack: system
     auto-route: false
     strict-route: true
     include-uid:
       - 1000
     dns-hijack:
       - any:53
       - tcp://any:53
   """
   let original = CompatibilityInput(profileYaml: profile, controlledConfigYaml: controlled,
     appConfigJson: "{\"subStore\":{},\"showFloatingWindow\":true,\"iosRoutingPolicy\":\"profile\",\"customKeep\":23}", overrideJavaScript: "module.exports = () => {}")
   let cleaned = service.sanitizedMobileInput(original)
   precondition(!cleaned.controlledConfigYaml.contains("mixed-port"))
   precondition(cleaned.profileYaml.contains("port: 443"))
   precondition(!cleaned.controlledConfigYaml.contains("direct-nameserver"))
   precondition(!cleaned.controlledConfigYaml.contains("1.2.3.4"))
   precondition(!cleaned.controlledConfigYaml.contains("respect-rules"))
   precondition(!cleaned.controlledConfigYaml.contains("fake-ip-filter-mode"))
   precondition(!cleaned.controlledConfigYaml.contains("proxy-server-nameserver-policy"))
   precondition(cleaned.controlledConfigYaml.contains("proxy-server-nameserver:"))
   precondition(cleaned.appConfigJson.contains("customKeep") && !cleaned.appConfigJson.contains("subStore"))
   precondition(cleaned.overrideJavaScript.isEmpty)
   precondition(!cleaned.controlledConfigYaml.contains("strict-route"))
   precondition(!cleaned.controlledConfigYaml.contains("include-uid"))
   precondition(!cleaned.controlledConfigYaml.contains("auto-route"))
   precondition(service.sanitizedMobileInput(cleaned) == cleaned)
   let generated = service.buildRuntimeConfig(from: original)
   let plan = service.makePacketTunnelNetworkPlan(from: generated)
   precondition(plan.effectiveMTU == 1500)
   precondition(plan.ipv6Address == "fdfe:dcba:9876::1")
   precondition(plan.dnsServers.count == 2)
   precondition(generated.contains("store-fake-ip: true"))
   precondition(generated.contains("support-x25519mlkem768: true"))
   precondition(service.parseTunSummary(from: generated).effectiveStack == "lwIP")
   var custom = cleaned
   custom.controlledConfigYaml += "\n  mtu: 1380\n"
   let customResult = service.buildRuntimeConfig(from: custom)
   precondition(service.makePacketTunnelNetworkPlan(from: customResult).effectiveMTU == 1380)
   var invalid = cleaned
   invalid.controlledConfigYaml += "\n  mtu: 1000\n"
   precondition(!service.validate(invalid).isValid)
   invalid.controlledConfigYaml = cleaned.controlledConfigYaml + "\n  mtu: nonsense\n"
   precondition(!service.validate(invalid).isValid)
   var explicit = cleaned
   explicit.profileYaml += "\nprofile:\n  store-fake-ip: false\n"
   explicit.controlledConfigYaml = "ipv6: false\n" + cleaned.controlledConfigYaml
   let explicitResult = service.buildRuntimeConfig(from: explicit)
   precondition(explicitResult.contains("store-fake-ip: false"))
   precondition(!explicitResult.contains("store-fake-ip: true"))
   precondition(service.makePacketTunnelNetworkPlan(from: explicitResult).ipv6Address == nil)
   let legacyPlan = "{\"tunnelRemoteAddress\":\"172.31.255.2\",\"ipv4Address\":\"172.31.255.1\",\"ipv4SubnetMask\":\"255.255.255.252\",\"dnsServers\":[\"172.31.255.2\"]}"
   let decodedPlan = try JSONDecoder().decode(PacketTunnelNetworkPlan.self, from: Data(legacyPlan.utf8))
   precondition(decodedPlan.effectiveMTU == 1500)
   let now = Date()
   precondition(AppActivityLease(isActive: true, updatedAt: now).isFresh(at: now))
   precondition(!AppActivityLease(isActive: true, updatedAt: now.addingTimeInterval(-40)).isFresh(at: now))
   precondition(!AppActivityLease(isActive: false, updatedAt: now).isFresh(at: now))
   precondition(PacketTunnelPollingPolicy.interval(ready: true, foreground: false, recentTraffic: false) == 30)
   precondition(PacketTunnelPollingPolicy.interval(ready: true, foreground: false, recentTraffic: true) == 5)
   precondition(PacketTunnelPollingPolicy.interval(ready: true, foreground: true, recentTraffic: false) == 2)
   precondition(PacketTunnelPollingPolicy.interval(ready: false, foreground: false, recentTraffic: false) < 1)
   if CommandLine.arguments.count > 1 { try generated.write(toFile: CommandLine.arguments[1], atomically: true, encoding: .utf8) }
   print("PASS: unsupported fields removed, MTU defaults/custom/validation, IPv6 alignment, Fake-IP persistence/opt-out, old JSON and adaptive polling leases.")
 }
}
