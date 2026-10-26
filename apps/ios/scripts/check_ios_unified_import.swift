import Foundation
@main
struct UnifiedImportChecks {
  static func main() throws {
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<4 { root.deleteLastPathComponent() }
    let source = try String(contentsOf: root.appendingPathComponent("examples/unified-profile.json"), encoding: .utf8)
    let service = CompatibilityService()
    let current = CompatibilityInput(profileYaml: "proxies: []", controlledConfigYaml: "dns:\n  listen: 127.0.0.1:1053\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  fake-ip-filter: []\n  nameserver: [https://1.1.1.1/dns-query]", appConfigJson: "{\"iosRoutingPolicy\":\"general\",\"custom\":true}")
    let candidate = try service.prepareUnifiedImport(source, current: current)!
    precondition(RoutingPolicyService.preference(in: candidate.appConfigJson) == .profile)
    precondition(candidate.appConfigJson.contains("custom"))
    precondition(current.profileYaml == "proxies: []", "Import preparation must not change the old workspace")
    let runtime = service.buildRuntimeConfig(from: candidate)
    precondition(service.protectedDNSProxyTarget(in: runtime) == "Overseas")
    precondition(service.extractProxyNodes(from: runtime) == service.extractProxyNodes(from: candidate.profileYaml))
    let rules = RoutingPolicyService.ruleStrings(in: candidate.profileYaml)
    let effective = RoutingPolicyService.ruleStrings(in: runtime)
    precondition(rules.allSatisfy(effective.contains), "Common rules must survive privacy-prefix deduplication")
    let business = rules.filter { $0.hasPrefix("GEOSITE,") || $0.hasPrefix("GEOIP,") || $0.hasPrefix("MATCH,") }
    precondition(effective.filter(business.contains) == business, "Business rule precedence must survive")
    precondition(effective.firstIndex(of: "IP-CIDR,255.255.255.255/32,DIRECT,no-resolve")! < effective.firstIndex(of: "NETWORK,udp,Overseas")!)
    let dns = service.parseDnsSummary(from: runtime)
    precondition(dns.nameservers == ["https://1.1.1.1/dns-query#Overseas"])
    precondition(runtime.components(separatedBy: "https://doh.pub/dns-query#DIRECT").count == 3, "The two music exceptions must survive")
    precondition(runtime.contains("NETWORK,udp,Overseas"))
    precondition(candidate.controlledConfigYaml.contains("listen: 127.0.0.1:1053"), "Local DNS listener settings stay local")
    var overridden = current
    overridden.overrideYaml = "dns:\n  nameserver: [192.0.2.53]"
    precondition((try? service.prepareUnifiedImport(source, current: overridden)) == nil, "An old override must not silently replace shared DNS")
    let invalid = source.replacingOccurrences(of: "\"version\": 1", with: "\"version\": 999")
    precondition((try? service.prepareUnifiedImport(invalid, current: current)) == nil)
    print("PASS: unified import validation, previous workspace, existing node/DNS/routing protections and mobile preset selection.")
  }
}
