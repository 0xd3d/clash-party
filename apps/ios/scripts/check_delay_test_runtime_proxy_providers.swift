import Foundation

@main
struct DelayTestRuntimeProxyProvidersCheck {
  static func main() {
    let profileYaml = """
    proxy-providers:
      local:
        type: http
        url: http://127.0.0.1:18081/provider.yaml
        path: ./providers/local.yaml
        interval: 3600

    proxy-groups:
      - name: GLOBAL
        type: select
        use:
          - local

    rule-providers:
      cn:
        type: http
        behavior: classical
        url: http://127.0.0.1:18081/cn-rules.yaml
        path: ./providers/cn-rules.yaml
        interval: 3600

    rules:
      - GEOIP,CN,DIRECT
      - RULE-SET,cn,DIRECT
      - MATCH,GLOBAL
    """

    let overrideYaml = """
    proxy-providers:
      airport:
        type: http
        url: https://example.com/airport.yaml
        path: ./providers/airport.yaml
        interval: 3600
    """

    let service = CompatibilityService()
    let input = CompatibilityInput(
      profileYaml: profileYaml,
      controlledConfigYaml: "",
      appConfigJson: "{}",
      overrideYaml: overrideYaml,
      overrideJavaScript: ""
    )

    let runtimeConfig = service.buildDelayTestRuntimeConfig(from: input)
    let proxyProvidersSectionCount = runtimeConfig.components(separatedBy: "\nproxy-providers:").count - 1

    guard runtimeConfig.contains("proxy-providers:") else {
      fputs("Expected delay-test runtime config to keep proxy-providers, but the section was missing.\n", stderr)
      exit(1)
    }

    guard proxyProvidersSectionCount == 1 else {
      fputs("Expected delay-test runtime config to contain exactly one merged proxy-providers section.\n", stderr)
      exit(1)
    }

    guard runtimeConfig.contains("local:\n    type: http") else {
      fputs("Expected delay-test runtime config to keep the profile-defined proxy provider 'local'.\n", stderr)
      exit(1)
    }

    guard !runtimeConfig.contains("rule-providers:") else {
      fputs("Expected delay-test runtime config to drop rule-providers so app-side speed tests do not warm remote routing providers.\n", stderr)
      exit(1)
    }

    guard !runtimeConfig.contains("GEOIP,") else {
      fputs("Expected delay-test runtime config to drop GEOIP rules so app-side speed tests do not initialize MMDB/geodata.\n", stderr)
      exit(1)
    }

    guard runtimeConfig.contains("rules:\n  - MATCH,DIRECT") else {
      fputs("Expected delay-test runtime config to install a minimal safe MATCH,DIRECT rule set.\n", stderr)
      exit(1)
    }

    let runtimeConfigWithEncryptedDNS = service.buildDelayTestRuntimeConfig(
      from: CompatibilityInput(
        profileYaml: profileYaml,
        controlledConfigYaml: """
        dns:
          enable: true
          enhanced-mode: fake-ip
          fake-ip-range: 198.18.0.1/16
          nameserver:
            - https://dns.alidns.com/dns-query
          proxy-server-nameserver:
            - https://dns.alidns.com/dns-query
          fallback:
            - https://1.1.1.1/dns-query
          fallback-filter:
            geoip: true
        """,
        appConfigJson: "{}",
        overrideYaml: "",
        overrideJavaScript: ""
      )
    )

    guard runtimeConfigWithEncryptedDNS.contains("https://dns.alidns.com/dns-query") else {
      fputs("Expected delay-test runtime config to preserve hostname DoH.\n", stderr)
      exit(1)
    }

    guard runtimeConfigWithEncryptedDNS.contains("https://1.1.1.1/dns-query") else {
      fputs("Expected delay-test runtime config to preserve fallback DoH.\n", stderr)
      exit(1)
    }

    guard runtimeConfigWithEncryptedDNS.contains("enhanced-mode: redir-host") else {
      fputs("Expected delay-test runtime config to use plain resolver metadata instead of Fake DNS.\n", stderr)
      exit(1)
    }

    guard !runtimeConfigWithEncryptedDNS.contains("fake-ip-range:") else {
      fputs("Expected delay-test runtime config to avoid fake-ip ranges entirely so speed tests stay off the Packet Tunnel data plane.\n", stderr)
      exit(1)
    }

    guard !runtimeConfigWithEncryptedDNS.contains("geoip: true") else {
      fputs("Expected delay-test runtime config to disable DNS fallback-filter geoip so missing MMDB cannot crash offline speed tests.\n", stderr)
      exit(1)
    }

    guard runtimeConfigWithEncryptedDNS.contains("proxy-server-nameserver:\n    - https://dns.alidns.com/dns-query") else {
      fputs("Expected delay-test runtime config to retain encrypted proxy-server nameservers.\n", stderr)
      exit(1)
    }

    let bootstrappedRuntimeConfig = """
    proxies:
      - name: hk
        type: trojan
        server: okanc.iepl.cac.cab
        port: 30401
    hosts:
      okanc.iepl.cac.cab: 203.0.113.7
    rules:
      - MATCH,hk
    dns:
      enable: true
      nameserver:
        - https://dns.example.invalid/dns-query
    tun:
      enable: true
    """
    let delayConfigFromBootstrappedRuntime = service.buildDelayTestRuntimeConfig(
      fromRuntimeConfig: bootstrappedRuntimeConfig
    )
    guard delayConfigFromBootstrappedRuntime.contains("okanc.iepl.cac.cab: 203.0.113.7") else {
      fputs("Expected delay-test runtime config to preserve Packet Tunnel injected proxy host overrides so VPN-active speed tests use the same direct proxy endpoint.\n", stderr)
      exit(1)
    }
    guard delayConfigFromBootstrappedRuntime.contains("https://dns.example.invalid/dns-query") else {
      fputs("Expected delay-test runtime config from bootstrapped runtime input to keep configured DoH.\n", stderr)
      exit(1)
    }
    guard delayConfigFromBootstrappedRuntime.contains("tun:\n  enable: false") else {
      fputs("Expected delay-test runtime config from bootstrapped runtime input to disable tun.\n", stderr)
      exit(1)
    }

    let profileWithTopLevelSequenceRules = """
    proxy-groups:
      - name: GLOBAL
        type: select
        proxies:
          - DIRECT

    rule-providers:
      cn:
        type: http
        behavior: classical
        url: http://127.0.0.1:18081/cn-rules.yaml
        path: ./providers/cn-rules.yaml
        interval: 3600

    rules:
    - DOMAIN,example.com,DIRECT
    - RULE-SET,cn,DIRECT
    - MATCH,GLOBAL
    """
    let runtimeConfigWithTopLevelSequenceRules = service.buildDelayTestRuntimeConfig(
      from: CompatibilityInput(
        profileYaml: profileWithTopLevelSequenceRules,
        controlledConfigYaml: "",
        appConfigJson: "{}",
        overrideYaml: "",
        overrideJavaScript: ""
      )
    )

    guard !runtimeConfigWithTopLevelSequenceRules.contains("- DOMAIN,") else {
      fputs("Expected delay-test runtime config to drop top-level sequence DOMAIN rules after removing the rules section.\n", stderr)
      exit(1)
    }

    guard !runtimeConfigWithTopLevelSequenceRules.contains("- RULE-SET,") else {
      fputs("Expected delay-test runtime config to drop top-level sequence RULE-SET rules after removing the rules section.\n", stderr)
      exit(1)
    }

    guard !runtimeConfigWithTopLevelSequenceRules.contains("rule-providers:") else {
      fputs("Expected delay-test runtime config to drop rule-providers even when profile rules use top-level sequence indentation.\n", stderr)
      exit(1)
    }

    guard runtimeConfigWithTopLevelSequenceRules.contains("rules:\n  - MATCH,DIRECT") else {
      fputs("Expected delay-test runtime config with top-level sequence input rules to install only the safe MATCH,DIRECT rule set.\n", stderr)
      exit(1)
    }

    let profileWithProviderFollowedByTopLevelScalar = """
    proxy-providers:
      local:
        type: http
        url: http://127.0.0.1:18081/provider.yaml
        path: ./providers/local.yaml
        interval: 3600
    mode: global
    rules:
      - MATCH,DIRECT
    """
    let runtimeConfigWithProviderFollowedByTopLevelScalar = service.buildRuntimeConfig(
      from: CompatibilityInput(
        profileYaml: profileWithProviderFollowedByTopLevelScalar,
        controlledConfigYaml: "",
        appConfigJson: "{}",
        overrideYaml: "",
        overrideJavaScript: ""
      )
    )
    let modeGlobalCount = runtimeConfigWithProviderFollowedByTopLevelScalar
      .components(separatedBy: "mode: global")
      .count - 1

    guard modeGlobalCount == 1 else {
      fputs("Expected provider merging to stop before a following top-level scalar key instead of duplicating it into the merged provider block.\n", stderr)
      exit(1)
    }

    guard !runtimeConfig.contains("airport:\n    type: http") else {
      fputs("Expected delay-test runtime config to drop placeholder override proxy providers that point at example.com.\n", stderr)
      exit(1)
    }

    let profileWithAirport = """
    proxy-providers:
      airport:
        type: http
        url: http://127.0.0.1:18081/provider.yaml
        path: ./providers/airport.yaml
        interval: 3600
    """
    let runtimeConfigWithRealAirport = service.buildDelayTestRuntimeConfig(
      from: CompatibilityInput(
        profileYaml: profileWithAirport,
        controlledConfigYaml: "",
        appConfigJson: "{}",
        overrideYaml: overrideYaml,
        overrideJavaScript: ""
      )
    )

    guard runtimeConfigWithRealAirport.contains("url: http://127.0.0.1:18081/provider.yaml") else {
      fputs("Expected a real profile-defined provider named 'airport' to survive placeholder override merging.\n", stderr)
      exit(1)
    }

    let realOverrideYaml = """
    proxy-providers:
      fallback:
        type: http
        url: https://provider.example.org/fallback.yaml
        path: ./providers/fallback.yaml
        interval: 3600
    """

    let runtimeConfigWithRealOverride = service.buildDelayTestRuntimeConfig(
      from: CompatibilityInput(
        profileYaml: profileYaml,
        controlledConfigYaml: "",
        appConfigJson: "{}",
        overrideYaml: realOverrideYaml,
        overrideJavaScript: ""
      )
    )

    guard runtimeConfigWithRealOverride.contains("fallback:\n    type: http") else {
      fputs("Expected delay-test runtime config to keep non-placeholder override proxy providers.\n", stderr)
      exit(1)
    }

    print("Delay-test runtime config preserved real proxy providers and dropped placeholder example.com entries.")
  }
}
