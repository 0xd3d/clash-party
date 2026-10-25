import Foundation

@main
struct IOSDNSRouteProtectionChecks {
  static func main() throws {
    let service = CompatibilityService()
    let profile = """
    mode: rule
    proxies:
      - name: Node
        type: vless
        server: 198.51.100.10
        port: 443
    proxy-groups:
      - name: OpenAI
        type: select
        proxies: [Node]
      - name: Unsafe
        type: select
        proxies: [DIRECT, Node]
    rules:
      - DOMAIN-SUFFIX,qq.com,DIRECT
      - MATCH,OpenAI
    """
    let controlled = """
    dns:
      enable: true
      enhanced-mode: fake-ip
      fake-ip-range: 198.19.0.1/16
      nameserver: ['https://custom.example.org:4443/query?v=1,2#DIRECT&h3=false', 'tls://dns.google']
      fallback: ['https://1.1.1.1/dns-query#Unsafe'] # keep the endpoint, replace only its adapter
      default-nameserver: [223.5.5.5]
      proxy-server-nameserver: ['https://223.5.5.5/dns-query']
      nameserver-policy:
        # A policy comment is not a resolver policy.
        '+.example.com': https://9.9.9.9/dns-query#DIRECT # replace the adapter, not the HTTPS address
        '+.untrusted.org': [192.0.2.53]
        'aqqmusic.tc.qq.com': ['https://doh.pub/dns-query#DIRECT']
        '+.stream.qqmusic.qq.com':
          - https://doh.pub/dns-query#DIRECT
        '+.qq.com': ['https://doh.pub/dns-query#DIRECT']
        '+.lan': [192.168.1.1]
    tun:
      enable: true
      inet4-address: [198.18.0.1/30]
    """
    let input = CompatibilityInput(profileYaml: profile, controlledConfigYaml: controlled, appConfigJson: "{\"iosRoutingPolicy\":\"profile\"}")
    let runtime = service.buildRuntimeConfig(from: input)
    let summary = service.parseDnsSummary(from: runtime)
    precondition(service.protectedDNSProxyTarget(in: runtime) == "OpenAI", "Groups containing DIRECT must not carry business DNS")
    precondition(service.protectedDNSProxyTarget(in: profile.replacingOccurrences(of: "MATCH,OpenAI", with: "MATCH,Node")) == "Node", "DNS must follow the verified final outbound before other safe groups")
    precondition(service.protectedDNSProxyTarget(in: profile.replacingOccurrences(of: "OpenAI", with: "GLOBAL")) == "Node", "The core regenerates GLOBAL with DIRECT; it must never be trusted as a proxy-only target")
    precondition(summary.nameservers == ["https://custom.example.org:4443/query?v=1,2#h3=false&OpenAI", "tls://dns.google#OpenAI"])
    precondition(summary.fallbackServers == ["https://1.1.1.1/dns-query#OpenAI"])
    precondition(!runtime.contains("192.0.2.53"), "An invalid business policy must not retain plaintext DNS")
    precondition(runtime.components(separatedBy: "https://doh.pub/dns-query#DIRECT").count == 3, "Only the two authorized QQ audio policies may stay DIRECT")
    precondition(runtime.contains("https://doh.pub/dns-query#OpenAI"), "A broad QQ policy is not an authorized DNS exception")
    precondition(runtime.contains("'192.168.1.1'"), "Explicit local-name DNS remains local")
    precondition(summary.proxyServerNameservers == ["https://223.5.5.5/dns-query"])
    precondition(runtime.contains("default-nameserver:\n    - 'https://223.5.5.5/dns-query'"), "DoH/DoT hostname bootstrap must also remain encrypted")
    precondition(runtime.contains("custom.example.org:4443/query?v=1,2#h3=false&OpenAI"), "URL port/path/query/options must survive adapter binding")
    precondition(runtime.contains("DST-PORT,53/853,OpenAI"))
    precondition(runtime.contains("DST-PORT,3478-3481/5349/19302-19309,OpenAI"))
    precondition(runtime.contains("DOMAIN-SUFFIX,dns.alidns.com,OpenAI"))
    precondition(runtime.contains("IP-CIDR6,2400:3200::1/128,OpenAI,no-resolve"))
    let dynamicProfile = profile.replacingOccurrences(of: "proxies: [Node]", with: "proxies: [Node]\n    use: [Remote]")
    precondition(service.protectedDNSProxyTarget(in: dynamicProfile) == "Node", "Unknown provider members are not a verified proxy-only group")
    for fragment in ["h3=true%26DIRECT", "h3=true%2526DIRECT", "%44IRECT&h3=false", "h3=true&DIRECT&Unsafe", "h3=%252526DIRECT"] {
      var encodedInput = input
      encodedInput.controlledConfigYaml = controlled.replacingOccurrences(of: "DIRECT&h3=false", with: fragment)
      let encodedRuntime = service.buildRuntimeConfig(from: encodedInput)
      let upstream = service.parseDnsSummary(from: encodedRuntime).nameservers[0]
      let decoded = URLComponents(string: upstream)!.fragment!
      let adapters = decoded.split(separator: "&").filter { !$0.contains("=") }
      precondition(adapters == ["OpenAI"], "Go's decoded fragment must have exactly one verified adapter: \(upstream)")
      precondition(decoded.split(separator: "&").last == "OpenAI", "The protected adapter must be the last token")
    }
    for fragment in ["DIRECT&Unsafe", "Unsafe&DIRECT", "h3=true%26Unsafe&DIRECT", "%44IRECT&%55nsafe", "h3=true%2526Unsafe&DIRECT"] {
      var bootstrapInput = input
      bootstrapInput.controlledConfigYaml = controlled.replacingOccurrences(of: "https://223.5.5.5/dns-query", with: "https://192.0.2.53/dns-query#" + fragment)
      let upstreams = service.parseDnsSummary(from: service.buildRuntimeConfig(from: bootstrapInput)).proxyServerNameservers
      let components = URLComponents(string: upstreams[0])!
      let adapters = (components.fragment ?? "").split(separator: "&").filter { !$0.contains("=") }
      precondition(adapters.isEmpty || adapters == ["DIRECT"], "Every decoded bootstrap adapter must be independent DIRECT")
      if fragment != "h3=true%2526Unsafe&DIRECT" {
        precondition(components.host == "223.5.5.5", "Unsafe bootstrap tokens must trigger the encrypted default")
      }
    }
    let rules = RoutingPolicyService.ruleStrings(in: runtime)
    precondition(rules.firstIndex(of: "DOMAIN-SUFFIX,doh.pub,OpenAI")! < rules.firstIndex(of: "DOMAIN-SUFFIX,qq.com,DIRECT")!)
    for localRule in ["IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", "IP-CIDR6,fc00::/7,DIRECT,no-resolve", "DOMAIN-SUFFIX,local,DIRECT"] {
      precondition(rules.firstIndex(of: "DST-PORT,53/853,OpenAI")! < rules.firstIndex(of: localRule)!, "Router/ULA/local DNS must be protected before LAN DIRECT")
      precondition(rules.firstIndex(of: "DOMAIN-SUFFIX,doh.pub,OpenAI")! < rules.firstIndex(of: localRule)!, "Known resolvers must precede local-IP shortcuts")
      precondition(rules.firstIndex(of: localRule)! < rules.firstIndex(of: "NETWORK,udp,OpenAI")!, "LAN non-DNS UDP discovery must remain direct")
    }
    precondition(service.buildRuntimeConfig(from: input) == runtime, "Repeated generation must be deterministic")
    var noProxy = input
    noProxy.profileYaml = "rules:\n  - MATCH,DIRECT"
    precondition(!service.validate(noProxy).isValid, "No trusted proxy target must fail validation, not fall back to direct DNS")
    precondition(service.buildRuntimeConfig(from: noProxy).contains("#REJECT"), "Bypassing validation must still fail closed")
    if CommandLine.arguments.count == 2 {
      try runtime.write(toFile: CommandLine.arguments[1], atomically: true, encoding: .utf8)
    }
    print("PASS: proxy-only business DNS, preserved HTTPS/DoT parameters, no plaintext fallback, exact QQ/LAN exceptions, resolver/STUN prefix, missing-proxy rejection.")
  }
}
