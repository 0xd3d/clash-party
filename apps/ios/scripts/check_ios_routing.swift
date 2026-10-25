import Foundation

@main
struct RoutingChecks {
  static func check(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else { fatalError(message) }
  }
  static func main() throws {
    guard CommandLine.arguments.count == 4 else { fatalError("Usage: routing-check profile.yaml resource-directory output-directory") }
    let profile = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)
    let resources = URL(fileURLWithPath: CommandLine.arguments[2])
    let output = URL(fileURLWithPath: CommandLine.arguments[3])
    try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
    let service = CompatibilityService()
    check(RoutingPolicyService.effectivePolicy(for: .automatic, runtimeConfig: profile) == .general, "Former GPT-only profile must migrate automatically")
    let unchanged = try RoutingPolicyService.rewrite(profile, policy: .profile)
    check(unchanged == profile, "Explicit profile policy must preserve all bytes")
    let custom = profile.replacingOccurrences(of: "MATCH,DIRECT", with: "DOMAIN-SUFFIX,example.com,DIRECT\n  - MATCH,DIRECT")
    check(RoutingPolicyService.effectivePolicy(for: .automatic, runtimeConfig: custom) == .profile, "Custom rules must survive automatic policy")
    let general = try RoutingPolicyService.rewrite(profile, policy: .automatic)
    check(service.extractProxyGroups(from: general).contains { $0.name == RoutingPolicyService.managedGroupName }, "Managed group must be visible before the VPN starts")
    let rules = service.extractRules(from: general)
    check(rules.last?.target == RoutingPolicyService.managedGroupName, "Unmatched traffic must use the proxy")
    for domain in ["google.com", "github.com", "youtube.com", "telegram.org"] {
      check(rules.contains { $0.payload == domain && $0.target == RoutingPolicyService.managedGroupName }, "Missing external routing: " + domain)
    }
    for domain in ["qq.com", "qpic.cn", "baidu.com", "lan"] {
      check(rules.contains { $0.payload == domain && $0.target == "DIRECT" }, "Domestic/local direct route missing")
    }
    check(rules.contains { $0.payload == "chatgpt.com" && $0.target == "OpenAI" }, "Original OpenAI choice must survive")
    check(rules.contains { $0.payload == "challenges.cloudflare.com" && $0.target == "OpenAI" }, "Authentication routing must survive")
    check(rules.contains { $0.payload == "127.0.0.0/8" && $0.target == "DIRECT" }, "no-resolve must not become the displayed target")
    let strings = RoutingPolicyService.ruleStrings(in: general)
    let udpIndex = strings.firstIndex(of: "NETWORK,udp,\(RoutingPolicyService.managedGroupName)")!
    let nonCNIndex = strings.firstIndex(of: "RULE-SET,ios-non-cn,\(RoutingPolicyService.managedGroupName)")!
    check(udpIndex < strings.firstIndex(of: "GEOIP,CN,DIRECT")!, "Public UDP must precede country DIRECT")
    check(nonCNIndex < strings.firstIndex(of: "DOMAIN-SUFFIX,qq.com,DIRECT")!, "Non-CN classification must precede domestic shortcuts")
    check(strings.contains("DOMAIN-SUFFIX,claude.ai,\(RoutingPolicyService.managedGroupName)"), "General routing must cover Claude alongside other external services")
    let cnDomainIndex = strings.firstIndex(of: "GEOSITE,cn,DIRECT")!
    let namedPublicIndex = strings.firstIndex(of: "GEOSITE,!private,\(RoutingPolicyService.managedGroupName)")!
    let namedPrivateIndex = strings.firstIndex(of: "GEOSITE,private,\(RoutingPolicyService.managedGroupName)")!
    let cnIPIndex = strings.firstIndex(of: "RULE-SET,ios-cncidr,DIRECT")!
    check(cnDomainIndex < namedPublicIndex && namedPublicIndex < namedPrivateIndex && namedPrivateIndex < cnIPIndex, "Named traffic must not reach the CN-IP DIRECT fallback")
    let beforeNodes = service.extractProxyNodes(from: profile)
    let afterNodes = service.extractProxyNodes(from: general)
    check(beforeNodes == afterNodes, "Routing changes must preserve proxy credentials and REALITY options")
    check(general.contains("support-x25519mlkem768: true"), "ML-KEM option must survive")
    let changedMode = try RoutingPolicyService.rewrite(profile.replacingOccurrences(of: "mode: rule", with: "mode: global"), policy: .general)
    check(changedMode.contains("mode: rule") && !changedMode.contains("mode: global"), "Managed rules must actually run in rule mode")
    let snapshot = RoutingPolicyService.loadDesktopSnapshot(resourceRoot: resources)!
    check(snapshot.rules.count < 100 && snapshot.skippedProcessRuleCount == 0, "Bundled snapshot must be a public format example, not a personal desktop export")
    let desktop = try RoutingPolicyService.rewrite(profile, policy: .desktopSnapshot, snapshot: snapshot)
    check(service.extractRules(from: desktop).count == snapshot.rules.count, "All compatible snapshot rules must appear in the final runtime")
    check(!desktop.contains(RoutingPolicyService.proxyPlaceholder), "Desktop policy placeholders must resolve")
    check(service.extractProxyNodes(from: desktop) == beforeNodes, "Desktop import must retain iOS nodes")
    var invalid = snapshot
    invalid.rules.insert("MATCH,DIRECT", at: 0)
    check((try? invalid.validate()) == nil, "Early MATCH must be rejected")
    invalid = snapshot; invalid.rules[0] = "IP-CIDR,999.1.2.3/32,DIRECT"
    check((try? invalid.validate()) == nil, "Invalid CIDR must be rejected")
    invalid = snapshot; invalid.rules[0] = "DOMAIN,example.com,untrusted-node"
    check((try? invalid.validate()) == nil, "Unknown policy must be rejected")
    invalid = snapshot; invalid.rules.insert("NETWORK,sctp,\(RoutingPolicyService.proxyPlaceholder)", at: 0)
    check((try? invalid.validate()) == nil, "Unknown transport must be rejected")
    invalid = snapshot; invalid.rules.insert("NETWORK,udp,\(RoutingPolicyService.proxyPlaceholder),no-resolve", at: 0)
    check((try? invalid.validate()) == nil, "NETWORK must not accept CIDR-only flags")
    let cache = output.appendingPathComponent("cache-test-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: cache) }
    let seeded = try RoutingRuleResources.seedIfNeeded(runtimeConfig: general, homeURL: cache, resourceRoot: resources)
    check(seeded == RoutingRuleResources.sources.count, "First use must seed every provider offline")
    let reseeded = try RoutingRuleResources.seedIfNeeded(runtimeConfig: general, homeURL: cache, resourceRoot: resources)
    check(reseeded == 0, "Valid downloaded caches must not be overwritten")
    let corruptCache = cache.appendingPathComponent("ruleset/ios-gfw.yaml")
    try Data("<html>gateway failure</html>".utf8).write(to: corruptCache)
    let repaired = try RoutingRuleResources.seedIfNeeded(runtimeConfig: general, homeURL: cache, resourceRoot: resources)
    check(repaired == 1, "Corrupt cache must recover from bundled seeds")
    for source in RoutingRuleResources.sources {
      let seedData = try Data(contentsOf: resources.appendingPathComponent(source.name + ".yaml"))
      check(RoutingRuleResources.isValidPayload(seedData), "Bundled payload must be valid")
    }
    check(!RoutingRuleResources.isValidPayload(Data("payload:\n - 999.0.0.1/24\n".utf8)), "Invalid update must be rejected")
    check(!RoutingRuleResources.isValidPayload(Data("payload:\n - example.com,DIRECT\n".utf8)), "Policy injection must be rejected")
    let json = try RoutingPolicyService.setting(.general, in: "{\"custom\":\"preserve\"}")
    check(json.contains("preserve") && RoutingPolicyService.preference(in: json) == .general, "Settings update must retain unrelated fields")
    try general.write(to: output.appendingPathComponent("general-runtime.yaml"), atomically: true, encoding: .utf8)
    try desktop.write(to: output.appendingPathComponent("desktop-runtime.yaml"), atomically: true, encoding: .utf8)
    print("PASS: GPT-only migration, general routing, portable NETWORK rules, preserved nodes/ML-KEM, invalid imports, offline seeds and cache recovery.")
  }
}
