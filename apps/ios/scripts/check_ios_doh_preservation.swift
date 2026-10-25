import Foundation

@main
struct IOSDoHPreservationChecks {
  static func main() throws {
    let service = CompatibilityService()
    let profile = """
    ipv6: false
    proxies:
      - name: Native
        type: vless
        server: 198.51.100.10
        port: 443
        reality-opts:
          support-x25519mlkem768: true
    proxy-groups:
      - name: OpenAI
        type: select
        proxies:
          - Native
    rules:
      - MATCH,OpenAI
    dns:
      enable: true
      nameserver:
      - https://doh.pub/dns-query
      - https://dns.alidns.com/dns-query
      proxy-server-nameserver:
      - https://doh.pub/dns-query
      default-nameserver:
      - 223.5.5.5
      - 119.29.29.29
    """
    let controlled = """
    mode: rule
    dns:
      enable: true
      enhanced-mode: fake-ip
      fake-ip-range: 198.19.0.1/16
      fake-ip-filter:
        - '*.lan'
        - '*.local'
      nameserver:
        - 223.5.5.5
        - 119.29.29.29
      proxy-server-nameserver:
        - 223.5.5.5
        - 119.29.29.29
      default-nameserver:
        - 223.5.5.5
        - 119.29.29.29
      fallback-filter:
        geoip: false
    tun:
      enable: true
      stack: system
      mtu: 1500
      dns-hijack:
        - any:53
        - tcp://any:53
    """
    var input = CompatibilityInput(profileYaml: profile, controlledConfigYaml: controlled,
      appConfigJson: "{\"iosRoutingPolicy\":\"profile\",\"customKeep\":23}")
    let migrated = service.sanitizedMobileInput(input)
    precondition(migrated.controlledConfigYaml.contains("https://doh.pub/dns-query"))
    precondition(service.sanitizedMobileInput(migrated) == migrated)
    let runtime = service.buildRuntimeConfig(from: input)
    let dns = service.parseDnsSummary(from: runtime)
    precondition(dns.nameservers == ["https://1.1.1.1/dns-query#OpenAI", "https://8.8.8.8/dns-query#OpenAI"])
    precondition(dns.proxyServerNameservers == ["https://223.5.5.5/dns-query"])
    precondition(runtime.contains("fake-ip-range: 198.19.0.1/16"))
    precondition(runtime.contains("support-x25519mlkem768: true"))
    precondition(runtime.contains("ipv6: false"))
    precondition(service.makePacketTunnelNetworkPlan(from: runtime).ipv6Address == nil)
    precondition(service.makePacketTunnelNetworkPlan(from: runtime).effectiveMTU == 1500)
    precondition(migrated.appConfigJson == input.appConfigJson)
    precondition(!runtime.contains("direct-nameserver:"))
    let bootstrap = service.extractBootstrapDNSEndpointHosts(from: runtime)
    precondition(Set(bootstrap) == Set(["223.5.5.5"]))

    let routeExclusions = service.extractBootstrapDNSEndpointHosts(from: """
    dns:
      nameserver:
        - https://1.1.1.1/dns-query#OpenAI
        - https://8.8.8.8/dns-query#%F0%9F%8C%90%20Overseas&h3=false
        - https://9.9.9.9/dns-query#DIRECT
        - https://149.112.112.112/dns-query#h3=false
      default-nameserver:
        - 223.5.5.5
    """)
    precondition(routeExclusions == ["9.9.9.9", "149.112.112.112", "223.5.5.5"])
    let completeBootstrap = service.extractBootstrapDNSUpstreams(from: """
    dns:
      proxy-server-nameserver:
        - https://192.0.2.1:4443/custom/dns-query?version=1#DIRECT
      default-nameserver: ['https://[2001:db8::1]/dns-query']
      nameserver:
        - https://1.1.1.1/dns-query#OpenAI
    """)
    precondition(completeBootstrap == ["https://192.0.2.1:4443/custom/dns-query?version=1#DIRECT",
      "https://[2001:db8::1]/dns-query"])
    let pinnedHosts = service.injectingResolvedProxyServerHosts(in: """
    hosts:
      unrelated.example: 192.0.2.2
      proxy.example:
        - 192.0.2.3
    dns:
      enable: true
    """, resolvedHosts: ["proxy.example": ["203.0.113.8"]])
    precondition(service.injectingResolvedProxyServerHosts(in: pinnedHosts,
      resolvedHosts: ["proxy.example": ["203.0.113.8"]]) == pinnedHosts)
    precondition(pinnedHosts.contains("unrelated.example: 192.0.2.2") && !pinnedHosts.contains("192.0.2.3"))

    input.overrideYaml = """
    dns:
        enable: true
        enhanced-mode: fake-ip
        fake-ip-range: 198.19.0.1/16
        nameserver: ['https://custom.example/dns-query#OpenAI']
        proxy-server-nameserver:
            - https://dns.alidns.com/dns-query
        fallback:
            - https://1.1.1.1/dns-query
        fallback-filter:
            geoip: true
    """
    let overridden = service.buildRuntimeConfig(from: input)
    precondition(overridden.contains("https://custom.example/dns-query#OpenAI"))
    precondition(overridden.contains("https://1.1.1.1/dns-query"))
    precondition(overridden.contains("geoip: true"))
    precondition(!overridden.contains("nameserver:\n    - 223.5.5.5"))
    let delay = service.buildDelayTestRuntimeConfig(fromRuntimeConfig: overridden)
    precondition(delay.contains("https://custom.example/dns-query#OpenAI"))
    precondition(delay.contains("https://1.1.1.1/dns-query"))
    precondition(delay.contains("enhanced-mode: redir-host"))
    precondition(!delay.contains("fake-ip-range:"))
    precondition(!delay.contains("geoip: true"))
    precondition(delay.contains("enable: false"))

    input.overrideYaml = ""
    input.controlledConfigYaml = controlled.replacingOccurrences(of: "223.5.5.5", with: "9.9.9.9")
    let customPlaintext = service.sanitizedMobileInput(input)
    precondition(customPlaintext.controlledConfigYaml == input.controlledConfigYaml)
    precondition(!service.parseDnsSummary(from: service.buildRuntimeConfig(from: input)).nameservers.contains { $0.hasPrefix("https://") })
    let absentUpstreams = input.controlledConfigYaml
      .replacingOccurrences(of: "  nameserver:\n    - 9.9.9.9\n    - 119.29.29.29\n", with: "")
      .replacingOccurrences(of: "  proxy-server-nameserver:\n    - 9.9.9.9\n    - 119.29.29.29\n", with: "")
    input.controlledConfigYaml = absentUpstreams
    precondition(service.buildRuntimeConfig(from: input).contains("https://1.1.1.1/dns-query#OpenAI"))
    if CommandLine.arguments.count == 2 {
      try runtime.write(toFile: CommandLine.arguments[1], atomically: true, encoding: .utf8)
    }
    print("PASS: legacy DNS defaults migrate to imported DoH; custom upstreams, fallback, proxy fragments and overlay precedence survive; IPv6/MTU/Fake-IP/nodes unchanged; speed-test core keeps DoH.")
  }
}
