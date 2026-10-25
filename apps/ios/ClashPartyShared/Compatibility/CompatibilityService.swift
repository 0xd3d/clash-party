import Darwin
import Foundation

public struct CompatibilityService {
  public static let defaultDelayTestURL = "https://www.gstatic.com/generate_204"
  public static let defaultDelayTestTimeoutMilliseconds = 5_000
  public static let defaultGeoIPURL = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat"
  public static let defaultGeoSiteURL = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"
  public static let defaultMMDBURL = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb"
  public static let defaultASNURL = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"

  public init() {}

  public func sanitizedMobileInput(_ input: CompatibilityInput) -> CompatibilityInput {
    var result = input
    result.profileYaml = removingUnavailableMobileKeys(in: input.profileYaml)
    result.controlledConfigYaml = removingUnavailableMobileKeys(in: input.controlledConfigYaml)
    result.overrideYaml = removingUnavailableMobileKeys(in: input.overrideYaml)
    result.overrideJavaScript = ""
    result.controlledConfigYaml = restoringImportedEncryptedDNS(
      profileYaml: result.profileYaml,
      controlledYaml: result.controlledConfigYaml
    )
    if let data = input.appConfigJson.data(using: .utf8),
       var config = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
      let keys = ["core", "enableSmartCore", "enableSmartOverride", "subStore", "showFloatingWindow", "disableTray", "swapTrayClick", "trayProxyGroupStyle", "showDockIcon", "envType", "pauseSSID", "webdavServerUrl", "globalShortcut", "systemProxy"]
      if keys.contains(where: { config[$0] != nil }) {
        for key in keys { config.removeValue(forKey: key) }
        if let encoded = try? JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys]) {
          result.appConfigJson = String(decoding: encoded, as: UTF8.self)
        }
      }
    }
    return result
  }

  private func removingUnavailableMobileKeys(in yaml: String) -> String {
    let removed = Set(["direct-nameserver", "direct-nameserver-follow-policy", "respect-rules", "proxy-server-nameserver-policy", "fake-ip-filter-mode", "fake-ip-range6", "fake-ip-ttl", "cache-algorithm", "use-system-hosts", "fallback-lazy-query"])
    let removedTun = Set(["auto-route", "auto-redirect", "strict-route", "endpoint-independent-nat", "include-uid", "exclude-uid", "include-android-user", "include-package", "exclude-package", "inet4-route-address", "inet6-route-address", "inet4-route-exclude-address", "inet6-route-exclude-address"])
    let removedRoot = Set(["port", "socks-port", "mixed-port", "redir-port", "tproxy-port", "allow-lan", "bind-address"])
    var activeSection: String?
    var skipIndent: Int?
    var result: [String] = []
    for line in yaml.components(separatedBy: .newlines) {
      let trimmed = line.trimmingCharacters(in: .whitespaces)
      let indent = leadingSpaceCount(in: line)
      if isTopLevelMappingLine(line) {
        if let colon = trimmed.firstIndex(of: ":"), removedRoot.contains(String(trimmed[..<colon])) { continue }
        activeSection = ["dns:", "tun:"].contains(trimmed) ? trimmed : nil
        skipIndent = nil
      }
      if let activeSection, indent == 2, !trimmed.hasPrefix("- "), let colon = trimmed.firstIndex(of: ":") {
        skipIndent = nil
        let keys = activeSection == "dns:" ? removed : removedTun
        if keys.contains(String(trimmed[..<colon])) { skipIndent = indent; continue }
      }
      if let skipIndent, !isTopLevelMappingLine(line), (trimmed.isEmpty || indent >= skipIndent) { continue }
      result.append(line)
    }
    return result.joined(separator: "\n")
  }

  public func validate(_ input: CompatibilityInput) -> CompatibilityValidationReport {
    let input = sanitizedMobileInput(input)
    var report = CompatibilityValidationReport()

    if input.profileYaml.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      report.blockingErrors.append(L10n.string("validation.profile.empty", "Profile YAML is empty."))
    }

    if input.controlledConfigYaml.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      report.blockingErrors.append(
        L10n.string("validation.controlled.empty", "Controlled Mihomo YAML is empty.")
      )
    }

    if !containsKey("dns:", in: input.controlledConfigYaml) {
      report.blockingErrors.append(
        L10n.string(
          "validation.controlled.missing_dns",
          "Controlled Mihomo YAML is missing a dns section."
        )
      )
    }

    if !containsKey("enhanced-mode: fake-ip", in: input.controlledConfigYaml) {
      report.blockingErrors.append(
        L10n.string(
          "validation.dns.missing_fake_ip_mode",
          "Fake DNS requires dns.enhanced-mode to be fake-ip."
        )
      )
    }

    if !containsKey("fake-ip-range:", in: input.controlledConfigYaml) {
      report.blockingErrors.append(
        L10n.string(
          "validation.dns.missing_fake_ip_range",
          "Fake DNS requires dns.fake-ip-range."
        )
      )
    }

    if !containsKey("fake-ip-filter:", in: input.controlledConfigYaml) {
      report.warnings.append(
        L10n.string(
          "validation.dns.missing_fake_ip_filter",
          "dns.fake-ip-filter is missing; behavior may diverge from desktop defaults."
        )
      )
    }

    if !containsKey("nameserver-policy:", in: input.controlledConfigYaml) {
      report.warnings.append(
        L10n.string("validation.dns.missing_nameserver_policy", "dns.nameserver-policy is missing.")
      )
    }

    if !containsKey("proxy-server-nameserver:", in: input.controlledConfigYaml) {
      report.warnings.append(
        L10n.string(
          "validation.dns.missing_proxy_nameserver",
          "dns.proxy-server-nameserver is missing."
        )
      )
    }

    if !containsKey("fallback:", in: input.controlledConfigYaml) {
      report.warnings.append(L10n.string("validation.dns.missing_fallback", "dns.fallback is missing."))
    }

    if !input.profileYaml.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      do {
        _ = try RoutingPolicyService.rewrite(
          buildIOSRuntimeConfig(from: input),
          policy: RoutingPolicyService.preference(in: input.appConfigJson)
        )
      } catch {
        report.blockingErrors.append(error.localizedDescription)
      }
    }

    let generated = buildIOSRuntimeConfig(from: input)
    let rawMTU = firstValue(forAnyOf: ["mtu"], in: section(named: "tun", in: generated)) ?? "1500"
    if Int(rawMTU).map({ (1280...9000).contains($0) }) != true {
      report.blockingErrors.append(L10n.string("validation.tun.mtu", "TUN MTU must be between 1280 and 9000 bytes."))
    }
    return report
  }

  @discardableResult
  public func persist(_ input: CompatibilityInput) throws -> CompatibilityValidationReport {
    let input = sanitizedMobileInput(input)
    let report = validate(input)
    guard report.isValid else {
      return report
    }

    let runtimeConfig = buildRuntimeConfig(from: input)
    let previousStatus = SharedStore.readRuntimeStatus()
    let dnsSummary = parseDnsSummary(from: input.controlledConfigYaml)
    try SharedStore.publishConfigurationBundle(input: input, runtimeConfig: runtimeConfig)
    let currentProxySelectionPreferences = SharedStore.readProxySelectionPreferences()
    if !currentProxySelectionPreferences.isEmpty {
      try SharedStore.writeProxySelectionPreferences(currentProxySelectionPreferences)
    }
    try SharedStore.writeRuntimeStatus(
      RuntimeStatus(
        state: persistedRuntimeState(previous: previousStatus),
        mode: parseMode(from: runtimeConfig),
        vpnConnected: previousStatus.vpnConnected,
        fakeDnsEnabled: dnsSummary.enabled && dnsSummary.enhancedMode == "fake-ip",
        activeProfileId: "default",
        dnsMode: dnsSummary.enhancedMode,
        backend: "embedded-mihomo",
        dataPlaneReady: previousStatus.dataPlaneReady,
        startupPhase: persistedStartupPhase(previous: previousStatus),
        startupMessage: persistedStartupMessage(previous: previousStatus),
        lastFailureReason: previousStatus.state == .running ? nil : previousStatus.lastFailureReason,
        lastFailurePhase: previousStatus.state == .running ? nil : previousStatus.lastFailurePhase,
        lastStopReason: previousStatus.state == .running ? nil : previousStatus.lastStopReason
      )
    )
    try SharedStore.writeProxyGroups(extractProxyGroups(from: runtimeConfig))
    return report
  }

  private func persistedRuntimeState(previous: RuntimeStatus) -> RuntimeConnectionState {
    switch previous.state {
    case .running, .starting, .stopping:
      return previous.state
    case .idle, .stopped, .failed:
      return .idle
    }
  }

  private func persistedStartupPhase(previous: RuntimeStatus) -> String {
    switch previous.state {
    case .running, .starting, .stopping:
      return previous.startupPhase
    case .idle, .stopped, .failed:
      return "idle"
    }
  }

  private func persistedStartupMessage(previous: RuntimeStatus) -> String {
    switch previous.state {
    case .running, .starting, .stopping:
      return previous.startupMessage
    case .idle, .stopped, .failed:
      return ""
    }
  }

  public func buildRuntimeConfig(from input: CompatibilityInput) -> String {
    let config = buildIOSRuntimeConfig(from: input)
    let routed = (try? RoutingPolicyService.rewrite(config, policy: RoutingPolicyService.preference(in: input.appConfigJson))) ?? config
    return securingDefaultDNSUpstreams(in: routed)
  }

  public func effectiveRoutingPolicy(from input: CompatibilityInput) -> IOSRoutingPolicy {
    RoutingPolicyService.effectivePolicy(for: RoutingPolicyService.preference(in: input.appConfigJson), runtimeConfig: buildIOSRuntimeConfig(from: input))
  }

  private func buildIOSRuntimeConfig(from input: CompatibilityInput) -> String {
    let input = sanitizedMobileInput(input)
    let iosDisabledTopLevelKeys = Self.iOSDisabledTopLevelKeys
    let overrideTopLevelKeys = topLevelKeys(in: input.overrideYaml)
    let controlledTopLevelKeys = topLevelKeys(in: input.controlledConfigYaml)
    let mergedMappingKeys: Set<String> = ["rule-providers", "proxy-providers"]

    let sanitizedProfile = removingTopLevelKeys(
      from: input.profileYaml,
      keys: controlledTopLevelKeys
        .union(overrideTopLevelKeys)
        .union(iosDisabledTopLevelKeys)
        .union(mergedMappingKeys)
    )
    let sanitizedControlled = removingTopLevelKeys(
      from: input.controlledConfigYaml,
      keys: overrideTopLevelKeys
        .union(iosDisabledTopLevelKeys)
        .union(mergedMappingKeys)
    )
    let sanitizedOverride = removingTopLevelKeys(
      from: input.overrideYaml,
      keys: iosDisabledTopLevelKeys.union(mergedMappingKeys)
    )
    let mergedProviderSections = [
      mergedNamedMappingSection(
        named: "rule-providers",
        from: [input.profileYaml, input.controlledConfigYaml, input.overrideYaml]
      ),
      mergedNamedMappingSection(
        named: "proxy-providers",
        from: [input.profileYaml, input.controlledConfigYaml, input.overrideYaml]
      )
    ]
      .filter { !$0.isEmpty }
      .joined(separator: "\n\n")

    let mergedConfig = """
    # Generated by Clash Party iOS compatibility service.
    # The real Mihomo-compatible runtime should consume this file path directly.

    \(sanitizedProfile)

    # Controlled config overlay
    \(sanitizedControlled)

    # Override YAML
    \(sanitizedOverride.trimmingCharacters(in: .whitespacesAndNewlines))

    \(mergedProviderSections.isEmpty ? "" : "\n# Merged provider sections\n\(mergedProviderSections)")

    # iOS Packet Tunnel overlay
    # Disable desktop-style inbound listeners inside the Network Extension process.
    geodata-mode: false
    port: 0
    socks-port: 0
    mixed-port: 0
    redir-port: 0
    tproxy-port: 0
    allow-lan: false

    """

    let configWithDNS = preservingDNSUpstreams(
      in: mergedConfig,
      from: [input.profileYaml, input.controlledConfigYaml, input.overrideYaml]
    )
    let configWithDynamicTunAddress = ensuringMobileTunDefaults(in: ensuringIOSTunIPv4Address(in: configWithDNS))
    let runtimeConfig = injectingIOSProxyServerFakeIPFilters(
      in: ensuringIOSTunMetadataAttribution(in: ensuringMetaCubeXGeoResources(in: configWithDynamicTunAddress)),
      proxyHosts: extractProxyServerHosts(
        from: [input.profileYaml, input.controlledConfigYaml, input.overrideYaml]
      )
    )
    return ensuringStoreSelectedEnabled(in: runtimeConfig)
  }

  public func injectingResolvedProxyServerHosts(
    in yaml: String,
    resolvedHosts: [String: [String]]
  ) -> String {
    let entries = resolvedHosts.compactMap { rawHost, rawAddresses -> (host: String, addresses: [String])? in
      guard let host = normalizedProxyServerHost(rawHost) else { return nil }
      let addresses = uniquePreservingOrder(
        rawAddresses
          .map(normalizedListValue)
          .filter(isIPLiteral)
      )
      guard !addresses.isEmpty else { return nil }
      return (host, addresses)
    }
      .sorted { $0.host.localizedCompare($1.host) == .orderedAscending }

    guard !entries.isEmpty else { return yaml }

    let injectedLines = entries.flatMap { entry -> [String] in
      if entry.addresses.count == 1, let address = entry.addresses.first {
        return ["  \(entry.host): \(address)"]
      }
      return ["  \(entry.host):"] + entry.addresses.map { "    - \($0)" }
    }

    var lines = yaml.components(separatedBy: .newlines)
    if let hostsIndex = lines.firstIndex(where: { rawLine in
      rawLine.trimmingCharacters(in: .whitespaces) == "hosts:"
        && leadingSpaceCount(in: rawLine) == 0
    }) {
      var insertionIndex = hostsIndex + 1
      while insertionIndex < lines.count,
            !isTopLevelMappingLine(lines[insertionIndex]) {
        insertionIndex += 1
      }
      let replacedHosts = Set(entries.map(\.host))
      let existing = Array(lines[(hostsIndex + 1)..<insertionIndex])
      let childIndent = existing.filter {
        let trimmed = $0.trimmingCharacters(in: .whitespaces)
        return !trimmed.isEmpty && !trimmed.hasPrefix("#") && !trimmed.hasPrefix("- ") && mappingKey(in: trimmed) != nil
      }.map(leadingSpaceCount(in:)).min() ?? 2
      var kept: [String] = []
      var replacingEntry = false
      for line in existing {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("# iOS bootstrap resolves proxy server hosts") { continue }
        if !trimmed.isEmpty, !trimmed.hasPrefix("#"), leadingSpaceCount(in: line) <= childIndent {
          let host = mappingKey(in: trimmed).map(normalizedListValue)?.lowercased()
          replacingEntry = host.map(replacedHosts.contains) ?? false
        }
        if !replacingEntry { kept.append(line) }
      }
      while kept.last?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == true { kept.removeLast() }
      lines.replaceSubrange((hostsIndex + 1)..<insertionIndex, with: kept)
      insertionIndex = hostsIndex + 1 + kept.count
      lines.insert(
        contentsOf: [
          String(repeating: " ", count: childIndent) + "# iOS bootstrap resolves proxy server hosts before Packet Tunnel routing is applied."
        ] + injectedLines.map { String(repeating: " ", count: max(0, childIndent - 2)) + $0 },
        at: insertionIndex
      )
      return lines.joined(separator: "\n")
    }

    let trimmedYaml = yaml.trimmingCharacters(in: .whitespacesAndNewlines)
    let prefix = trimmedYaml.isEmpty ? "" : "\(trimmedYaml)\n\n"
    return """
    \(prefix)# iOS bootstrap resolves proxy server hosts before Packet Tunnel routing is applied.
    hosts:
    \(injectedLines.joined(separator: "\n"))
    """
  }

  public func buildDelayTestRuntimeConfig(from input: CompatibilityInput) -> String {
    buildDelayTestRuntimeConfig(fromRuntimeConfig: buildRuntimeConfig(from: input))
  }

  private func ensuringMetaCubeXGeoResources(in yaml: String) -> String {
    let resources = [
      ("geoip", Self.defaultGeoIPURL),
      ("geosite", Self.defaultGeoSiteURL),
      ("mmdb", Self.defaultMMDBURL),
      ("asn", Self.defaultASNURL)
    ]
    let resourceLines = resources.map { "  \($0.0): \($0.1)" }

    if containsTopLevelKey("geox-url", in: yaml) {
      let section = section(named: "geox-url", in: yaml)
      let missingResources = resources.filter { firstValue(forAnyOf: [$0.0], in: section) == nil }
      guard !missingResources.isEmpty else { return yaml }

      var lines = yaml.components(separatedBy: .newlines)
      guard let sectionIndex = lines.firstIndex(where: { rawLine in
        leadingSpaceCount(in: rawLine) == 0
          && rawLine.trimmingCharacters(in: .whitespaces) == "geox-url:"
      }) else {
        return yaml
      }

      var insertionIndex = sectionIndex + 1
      while insertionIndex < lines.count,
            !isTopLevelMappingLine(lines[insertionIndex]) {
        insertionIndex += 1
      }
      lines.insert(
        contentsOf: missingResources.map { "  \($0.0): \($0.1)" },
        at: insertionIndex
      )
      return lines.joined(separator: "\n")
    }

    let trimmedYaml = yaml.trimmingCharacters(in: .whitespacesAndNewlines)
    let prefix = trimmedYaml.isEmpty ? "" : "\(trimmedYaml)\n\n"
    return """
    \(prefix)# MetaCubeX rule databases used by iOS route matching and diagnostics.
    geox-url:
    \(resourceLines.joined(separator: "\n"))
    """
  }

  private func ensuringIOSTunMetadataAttribution(in yaml: String) -> String {
    guard !containsTopLevelKey("sniffer", in: yaml) else {
      return yaml.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    let trimmedYaml = yaml.trimmingCharacters(in: .whitespacesAndNewlines)
    let prefix = trimmedYaml.isEmpty ? "" : "\(trimmedYaml)\n\n"
    return """
    \(prefix)# iOS TUN metadata attribution.
    # Fake DNS remains the first source of domain truth; TCP sniffing fills gaps for
    # IP-only TLS/HTTP flows without adding app-specific platform rules.
    sniffer:
      enable: true
      force-dns-mapping: true
      parse-pure-ip: true
      override-destination: true
      sniff:
        TLS:
          ports:
            - 443
        HTTP:
          ports:
            - 80
    """
  }

  private func containsTopLevelKey(_ key: String, in yaml: String) -> Bool {
    yaml
      .components(separatedBy: .newlines)
      .contains { rawLine in
        let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
        return leadingSpaceCount(in: rawLine) == 0 && trimmed == "\(key):"
      }
  }

  private func extractGeoXResources(from yaml: String) -> [ResourceRecord] {
    let section = section(named: "geox-url", in: yaml)
    let entries: [(name: String, path: String, source: String)] = [
      ("GeoIP Lite", "geoip-lite.dat", firstValue(forAnyOf: ["geoip"], in: section) ?? Self.defaultGeoIPURL),
      ("GeoSite", "geosite.dat", firstValue(forAnyOf: ["geosite"], in: section) ?? Self.defaultGeoSiteURL),
      ("Country Lite MMDB", "country-lite.mmdb", firstValue(forAnyOf: ["mmdb"], in: section) ?? Self.defaultMMDBURL),
      ("ASN MMDB", "GeoLite2-ASN.mmdb", firstValue(forAnyOf: ["asn"], in: section) ?? Self.defaultASNURL)
    ]

    return entries.map { entry in
      ResourceRecord(
        name: entry.name,
        kind: "geodata",
        behavior: "route database",
        source: entry.source,
        path: entry.path,
        interval: "manual/background"
      )
    }
  }

  public func buildDelayTestRuntimeConfig(fromRuntimeConfig runtimeConfig: String) -> String {
    let sanitizedRuntimeConfig = removingTopLevelKeys(
      from: runtimeConfig,
      keys: ["dns", "tun", "rule-providers", "rules", "sub-rules"]
    )
    var delayDNS = "dns:\n" + section(named: "dns", in: runtimeConfig)
    // Keep configured encrypted upstreams. The temporary speed-test core only
    // disables its DNS listener/Fake-IP data plane and GeoIP dependency.
    for key in ["listen", "fake-ip-range", "fake-ip-filter"] {
      delayDNS = replacingDNSChild(key, with: [], in: delayDNS)
    }
    delayDNS = replacingDNSChild("enable", with: ["  enable: true"], in: delayDNS)
    delayDNS = replacingDNSChild("enhanced-mode", with: ["  enhanced-mode: redir-host"], in: delayDNS)
    delayDNS = replacingDNSChild("fallback-filter", with: ["  fallback-filter:", "    geoip: false"], in: delayDNS)
    delayDNS = preservingDNSUpstreams(in: delayDNS, from: [runtimeConfig])

    return """
    \(sanitizedRuntimeConfig)

    # App-side delay-test overlay
    rules:
      - MATCH,DIRECT

    \(delayDNS)

    tun:
      enable: false
    """.trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private static let defaultEncryptedNameservers = [
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/dns-query"
  ]
  private static let legacyDNSDefaults: [[String]] = [
    ["223.5.5.5", "119.29.29.29"],
    ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
    ["https://doh.pub/dns-query"]
  ]

  // Only migrate known generated defaults. Custom upstreams/fragments remain
  // explicit. Run after routing adds its groups, so DNS uses an existing adapter.
  private func securingDefaultDNSUpstreams(in yaml: String) -> String {
    var result = yaml
    let groups = extractProxyGroups(from: yaml)
    let usable = groups.filter { $0.all.contains { !["DIRECT", "REJECT"].contains($0) } }
    let preferred = usable.first { $0.name == "iOS 外网" }
      ?? usable.first { $0.name == "OpenAI" }
      ?? usable.first { $0.name == "GLOBAL" }
      ?? usable.first
    let fragment = preferred?.name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed)
    let main = dnsChildBlock("nameserver", in: result)
    let values = listValue(for: "nameserver", in: main.joined(separator: "\n"))
    if values.isEmpty || Self.legacyDNSDefaults.contains(values) || values == Self.defaultEncryptedNameservers {
      let upstreams = Self.defaultEncryptedNameservers.map { $0 + (fragment.map { "#" + $0 } ?? "") }
      result = replacingDNSChild("nameserver", with: ["  nameserver:"] + upstreams.map { "    - \($0)" }, in: result)
    }
    let proxy = listValue(for: "proxy-server-nameserver", in: dnsChildBlock("proxy-server-nameserver", in: result).joined(separator: "\n"))
    if proxy.isEmpty || Self.legacyDNSDefaults.contains(proxy) {
      // This resolver bootstraps the proxy itself: it must not depend on that
      // same proxy. Its IP endpoint needs no initial cleartext DNS query.
      result = replacingDNSChild("proxy-server-nameserver", with: ["  proxy-server-nameserver:", "    - https://223.5.5.5/dns-query"], in: result)
    }
    let bootstrap = listValue(for: "default-nameserver", in: dnsChildBlock("default-nameserver", in: result).joined(separator: "\n"))
    if bootstrap.isEmpty || bootstrap == Self.legacyDNSDefaults[0] {
      result = replacingDNSChild("default-nameserver", with: ["  default-nameserver:", "    - https://223.5.5.5/dns-query"], in: result)
    }
    return result
  }

  private func restoringImportedEncryptedDNS(profileYaml: String, controlledYaml: String) -> String {
    guard containsTopLevelKey("dns", in: controlledYaml) else { return controlledYaml }
    var result = controlledYaml
    let templateDefaults = [
      ["223.5.5.5", "119.29.29.29"],
      ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
      Self.defaultEncryptedNameservers
    ]
    // Old generated controls shadowed imported DoH. Migrate only the known
    // template values (or missing keys); keep every other explicit DNS choice.
    for key in ["nameserver", "proxy-server-nameserver"] {
      let imported = dnsChildBlock(key, in: profileYaml)
      let values = listValue(for: key, in: imported.joined(separator: "\n"))
      guard values.contains(where: { $0.lowercased().hasPrefix("https://") }) else { continue }
      let controlled = dnsChildBlock(key, in: result)
      let current = listValue(for: key, in: controlled.joined(separator: "\n"))
      if controlled.isEmpty || templateDefaults.contains(current) {
        result = replacingDNSChild(key, with: imported, in: result)
      }
    }
    return result
  }

  private func preservingDNSUpstreams(in yaml: String, from sources: [String]) -> String {
    guard containsTopLevelKey("dns", in: yaml) else { return yaml }
    var result = yaml
    for key in ["nameserver", "proxy-server-nameserver", "default-nameserver", "fallback"] {
      guard dnsChildBlock(key, in: result).isEmpty else { continue }
      if let block = sources.reversed().map({ dnsChildBlock(key, in: $0) }).first(where: { !$0.isEmpty }) {
        result = replacingDNSChild(key, with: block, in: result)
      }
    }
    if dnsChildBlock("nameserver", in: result).isEmpty {
      result = replacingDNSChild("nameserver", with: ["  nameserver:"] + Self.defaultEncryptedNameservers.map { "    - \($0)" }, in: result)
    }
    if dnsChildBlock("default-nameserver", in: result).isEmpty {
      // Literal bootstrap servers resolve the DoH hostname; they are not a
      // fallback for application DNS queries after an HTTPS failure.
      result = replacingDNSChild("default-nameserver", with: ["  default-nameserver:", "    - https://223.5.5.5/dns-query"], in: result)
    }
    return result
  }

  private func dnsChildRange(_ key: String, in lines: [String]) -> Range<Int>? {
    guard let root = lines.firstIndex(where: { isTopLevelMappingLine($0) && $0.trimmingCharacters(in: .whitespaces) == "dns:" }) else { return nil }
    let end = lines.indices.dropFirst(root + 1).first(where: { isTopLevelMappingLine(lines[$0]) }) ?? lines.count
    let candidates = ((root + 1)..<end).filter {
      let text = lines[$0].trimmingCharacters(in: .whitespaces)
      return !text.isEmpty && !text.hasPrefix("#") && !text.hasPrefix("- ") && mappingKey(in: text) != nil
    }
    guard let indent = candidates.map({ leadingSpaceCount(in: lines[$0]) }).min(),
          let start = candidates.first(where: { leadingSpaceCount(in: lines[$0]) == indent && mappingKey(in: lines[$0]) == key }) else { return nil }
    let next = candidates.first(where: { $0 > start && leadingSpaceCount(in: lines[$0]) == indent }) ?? end
    return start..<next
  }

  private func dnsChildBlock(_ key: String, in yaml: String) -> [String] {
    let lines = yaml.components(separatedBy: .newlines)
    guard let range = dnsChildRange(key, in: lines) else { return [] }
    var block = Array(lines[range])
    while block.last?.trimmingCharacters(in: .whitespaces).isEmpty == true { block.removeLast() }
    return block
  }

  private func replacingDNSChild(_ key: String, with block: [String], in yaml: String) -> String {
    var lines = yaml.components(separatedBy: .newlines)
    guard let root = lines.firstIndex(where: { isTopLevelMappingLine($0) && $0.trimmingCharacters(in: .whitespaces) == "dns:" }) else { return yaml }
    let end = lines.indices.dropFirst(root + 1).first(where: { isTopLevelMappingLine(lines[$0]) }) ?? lines.count
    let indent = ((root + 1)..<end).compactMap { index -> Int? in
      let text = lines[index].trimmingCharacters(in: .whitespaces)
      return text.isEmpty || text.hasPrefix("#") || text.hasPrefix("- ") || mappingKey(in: text) == nil ? nil : leadingSpaceCount(in: lines[index])
    }.min() ?? 2
    let sourceIndent = block.first.map(leadingSpaceCount(in:)) ?? indent
    let normalized = block.map { line -> String in
      guard !line.trimmingCharacters(in: .whitespaces).isEmpty else { return "" }
      return String(repeating: " ", count: max(0, leadingSpaceCount(in: line) - sourceIndent + indent)) + line.trimmingCharacters(in: .whitespaces)
    }
    if let range = dnsChildRange(key, in: lines) {
      lines.replaceSubrange(range, with: normalized)
    } else if !normalized.isEmpty {
      lines.insert(contentsOf: normalized, at: end)
    }
    return lines.joined(separator: "\n")
  }

  private func injectingIOSProxyServerFakeIPFilters(in yaml: String, proxyHosts: [String]) -> String {
    let filters = uniquePreservingOrder(proxyHosts)
    guard !filters.isEmpty else {
      return yaml.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    let lines = yaml.components(separatedBy: .newlines)
    var result: [String] = []
    var insideDNS = false
    var insideFakeIPFilter = false
    var sawFakeIPFilter = false
    var insertedFilters = Set<String>()

    func appendMissingFilters() {
      for filter in filters where insertedFilters.insert(filter).inserted {
        result.append("    - \(filter)")
      }
    }

    func finishDNSSectionIfNeeded() {
      if insideFakeIPFilter {
        appendMissingFilters()
        insideFakeIPFilter = false
      }
      if !sawFakeIPFilter {
        result.append("  fake-ip-filter:")
        appendMissingFilters()
      }
    }

    for rawLine in lines {
      let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
      let indent = leadingSpaceCount(in: rawLine)
      let isTopLevelMapping = isTopLevelMappingLine(rawLine)

      if insideDNS, isTopLevelMapping, trimmed != "dns:" {
        finishDNSSectionIfNeeded()
        insideDNS = false
        result.append(rawLine)
        continue
      }

      if !insideDNS, trimmed == "dns:", isTopLevelMapping {
        insideDNS = true
        insideFakeIPFilter = false
        sawFakeIPFilter = false
        insertedFilters.removeAll(keepingCapacity: true)
        result.append(rawLine)
        continue
      }

      guard insideDNS else {
        result.append(rawLine)
        continue
      }

      if insideFakeIPFilter {
        if !trimmed.isEmpty, indent > 2 {
          if trimmed.hasPrefix("- ") {
            let filter = normalizedListValue(String(trimmed.dropFirst(2)))
            if !filter.isEmpty {
              insertedFilters.insert(filter)
            }
          }
          result.append(rawLine)
          continue
        }

        appendMissingFilters()
        insideFakeIPFilter = false
      }

      if indent == 2, let key = mappingKey(in: trimmed), key == "fake-ip-filter" {
        sawFakeIPFilter = true
        let value = value(afterMappingKeyIn: trimmed)
        if value.isEmpty {
          insideFakeIPFilter = true
          result.append(rawLine)
        } else {
          result.append("  fake-ip-filter:")
          for filter in inlineListValues(from: value) where insertedFilters.insert(filter).inserted {
            result.append("    - \(filter)")
          }
          appendMissingFilters()
        }
        continue
      }

      result.append(rawLine)
    }

    if insideDNS {
      finishDNSSectionIfNeeded()
    }

    return result
      .joined(separator: "\n")
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private func ensuringIOSTunIPv4Address(in yaml: String) -> String {
    let dnsSummary = parseDnsSummary(from: yaml)
    let tunSummary = parseTunSummary(from: yaml)
    let ipv4Layout = packetTunnelIPv4Layout(from: tunSummary, avoidingFakeIPRange: dnsSummary.fakeIPRange)
    let desiredPrefix = "\(ipv4Layout.interfaceAddress)/30"
    let lines = yaml.components(separatedBy: .newlines)

    guard let tunIndex = lines.firstIndex(where: { rawLine in
      leadingSpaceCount(in: rawLine) == 0
        && rawLine.trimmingCharacters(in: .whitespaces) == "tun:"
    }) else {
      let trimmedYaml = yaml.trimmingCharacters(in: .whitespacesAndNewlines)
      let prefix = trimmedYaml.isEmpty ? "" : "\(trimmedYaml)\n\n"
      return """
      \(prefix)tun:
        enable: true
        inet4-address:
          - \(desiredPrefix)
      """
    }

    var sectionEndIndex = tunIndex + 1
    while sectionEndIndex < lines.count,
          !isTopLevelMappingLine(lines[sectionEndIndex]) {
      sectionEndIndex += 1
    }

    var result: [String] = []
    result.reserveCapacity(lines.count + 2)
    result.append(contentsOf: lines[..<(tunIndex + 1)])

    var index = tunIndex + 1
    var inserted = false
    while index < sectionEndIndex {
      let rawLine = lines[index]
      let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
      let indent = leadingSpaceCount(in: rawLine)
      if indent == 2, mappingKey(in: trimmed) == "inet4-address" {
        result.append("  inet4-address:")
        result.append("    - \(desiredPrefix)")
        inserted = true
        index += 1
        while index < sectionEndIndex {
          let nestedLine = lines[index]
          let nestedTrimmed = nestedLine.trimmingCharacters(in: .whitespaces)
          if !nestedTrimmed.isEmpty, leadingSpaceCount(in: nestedLine) > 2 {
            index += 1
            continue
          }
          break
        }
        continue
      }

      result.append(rawLine)
      index += 1
    }

    if !inserted {
      result.append("  inet4-address:")
      result.append("    - \(desiredPrefix)")
    }

    if sectionEndIndex < lines.count {
      result.append(contentsOf: lines[sectionEndIndex...])
    }
    return result
      .joined(separator: "\n")
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private func extractProxyServerHosts(from yamls: [String]) -> [String] {
    uniquePreservingOrder(yamls.flatMap { extractProxyServerHosts(from: $0) })
  }

  private func extractProxyServerHosts(from yaml: String) -> [String] {
    var hosts: [String] = []
    var insideProxies = false

    for rawLine in yaml.components(separatedBy: .newlines) {
      let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
      let indent = leadingSpaceCount(in: rawLine)

      if trimmed == "proxies:", indent == 0 {
        insideProxies = true
        continue
      }

      if insideProxies, isTopLevelMappingLine(rawLine), trimmed != "proxies:" {
        insideProxies = false
      }

      guard insideProxies else { continue }

      if let server = value(for: "server", in: trimmed),
         let host = normalizedProxyServerHost(server) {
        hosts.append(host)
      }

      let inlineObject = trimmed.hasPrefix("- ")
        ? String(trimmed.dropFirst(2))
        : trimmed
      if inlineObject.contains("{"),
         let server = inlineObjectValue(for: "server", in: inlineObject),
         let host = normalizedProxyServerHost(server) {
        hosts.append(host)
      }
    }

    return uniquePreservingOrder(hosts)
  }

  public func extractProxyServerEndpointHosts(from yaml: String) -> [String] {
    var hosts: [String] = []
    var insideProxies = false

    for rawLine in yaml.components(separatedBy: .newlines) {
      let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
      let indent = leadingSpaceCount(in: rawLine)

      if trimmed == "proxies:", indent == 0 {
        insideProxies = true
        continue
      }

      if insideProxies, isTopLevelMappingLine(rawLine), trimmed != "proxies:" {
        insideProxies = false
      }

      guard insideProxies else { continue }

      if let server = value(for: "server", in: trimmed),
         let host = normalizedProxyServerEndpointHost(server) {
        hosts.append(host)
      }

      let inlineObject = trimmed.hasPrefix("- ")
        ? String(trimmed.dropFirst(2))
        : trimmed
      if inlineObject.contains("{"),
         let server = inlineObjectValue(for: "server", in: inlineObject),
         let host = normalizedProxyServerEndpointHost(server) {
        hosts.append(host)
      }
    }

    return uniquePreservingOrder(hosts)
  }

  public func extractBootstrapDNSEndpointHosts(from yaml: String) -> [String] {
    let bootstrapDNSKeys: Set<String> = [
      "nameserver",
      "proxy-server-nameserver",
      "default-nameserver",
      "direct-nameserver"
    ]
    var hosts: [String] = []
    var insideDNS = false
    var activeListKey: String?

    for rawLine in yaml.components(separatedBy: .newlines) {
      let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
      let indent = leadingSpaceCount(in: rawLine)

      if trimmed == "dns:", indent == 0 {
        insideDNS = true
        activeListKey = nil
        continue
      }

      if insideDNS, isTopLevelMappingLine(rawLine), trimmed != "dns:" {
        insideDNS = false
        activeListKey = nil
      }

      guard insideDNS else { continue }

      if indent <= 2, let (key, value) = keyValue(from: trimmed) {
        activeListKey = bootstrapDNSKeys.contains(key) ? key : nil
        guard bootstrapDNSKeys.contains(key) else { continue }

        for item in inlineListValues(from: value) {
          if let host = normalizedBootstrapDNSIPAddress(item) {
            hosts.append(host)
          }
        }
        continue
      }

      guard let activeListKey,
            bootstrapDNSKeys.contains(activeListKey),
            trimmed.hasPrefix("- ") else {
        continue
      }

      let item = String(trimmed.dropFirst(2)).trimmingCharacters(in: .whitespaces)
      if let host = normalizedBootstrapDNSIPAddress(item) {
        hosts.append(host)
      }
    }

    return uniquePreservingOrder(hosts)
  }

  /// Preserve the transport, path and query of bootstrap DNS endpoints. The
  /// Packet Tunnel validates independent literal-IP HTTPS URLs before use;
  /// converting these values into bare IPs would turn DoH into UDP port 53.
  public func extractBootstrapDNSUpstreams(from yaml: String) -> [String] {
    let values = ["proxy-server-nameserver", "default-nameserver"].flatMap { key in
      listValue(for: key, in: dnsChildBlock(key, in: yaml).joined(separator: "\n"))
        .map(normalizedListValue)
    }
    return uniquePreservingOrder(values)
  }

  public func extractProxyGroups(from profileYaml: String) -> [ProxyGroupSnapshot] {
    var groups: [ProxyGroupSnapshot] = []
    var insideProxyGroups = false
    var currentGroupStarted = false
    var currentName = ""
    var currentSelected: String?
    var currentOptions: [String] = []
    var currentType: String?
    var currentTestURL: String?
    var collectingMembers = false
    var membersIndent = 0

    func flushCurrentGroup() {
      guard currentGroupStarted else {
        currentSelected = nil
        currentOptions = []
        currentType = nil
        currentTestURL = nil
        collectingMembers = false
        membersIndent = 0
        return
      }
      guard !currentName.isEmpty else {
        currentGroupStarted = false
        currentSelected = nil
        currentOptions = []
        currentType = nil
        currentTestURL = nil
        collectingMembers = false
        membersIndent = 0
        return
      }

      let options = uniquePreservingOrder(
        currentOptions
          .map(normalizedListValue)
          .filter { !$0.isEmpty }
      )
      groups.append(
        ProxyGroupSnapshot(
          name: currentName,
          selected: currentSelected ?? options.first,
          all: options,
          type: currentType,
          testURL: currentTestURL
        )
      )
      currentGroupStarted = false
      currentName = ""
      currentSelected = nil
      currentOptions = []
      currentType = nil
      currentTestURL = nil
      collectingMembers = false
      membersIndent = 0
    }

    func applyGroupField(key: String, value: String, indent: Int) {
      switch key {
      case "name":
        if currentName.isEmpty {
          currentName = value
        }
      case "type":
        currentType = value
      case "url", "test-url", "testUrl":
        let testURL = value.trimmingCharacters(in: .whitespacesAndNewlines)
        currentTestURL = testURL.isEmpty ? currentTestURL : testURL
      case "now", "selected":
        let selected = normalizedListValue(value)
        currentSelected = selected.isEmpty ? currentSelected : selected
      case "proxies":
        if value.isEmpty {
          collectingMembers = true
          membersIndent = indent
        } else {
          currentOptions.append(contentsOf: inlineListValues(from: value))
          collectingMembers = false
          membersIndent = 0
        }
      default:
        return
      }
    }

    profileYaml.enumerateLines { rawLine, _ in
      let indent = leadingSpaceCount(in: rawLine)
      let line = rawLine.trimmingCharacters(in: .whitespaces)

      if line == "proxy-groups:" {
        flushCurrentGroup()
        insideProxyGroups = true
        return
      }

      if insideProxyGroups, !line.isEmpty, indent == 0 {
        flushCurrentGroup()
        insideProxyGroups = false
      }

      guard insideProxyGroups else { return }

      if indent == 2, line.hasPrefix("- ") {
        flushCurrentGroup()
        currentGroupStarted = true
        let entry = String(line.dropFirst(2)).trimmingCharacters(in: .whitespaces)
        if let (key, value) = keyValue(from: entry), key == "name" {
          currentName = value
        } else if entry.hasPrefix("{"), entry.hasSuffix("}") {
          let values = inlineObjectValues(in: entry)
          currentName = values["name"] ?? ""
          currentSelected = values["now"].map(normalizedListValue)
          currentType = values["type"]
          currentTestURL = values["url"] ?? values["test-url"] ?? values["testUrl"]
        } else if let (key, value) = keyValue(from: entry) {
          applyGroupField(key: key, value: value, indent: indent)
        }
        return
      }

      guard currentGroupStarted else { return }

      if collectingMembers, !line.isEmpty, indent <= membersIndent {
        collectingMembers = false
        membersIndent = 0
      }

      if collectingMembers, line.hasPrefix("- ") {
        currentOptions.append(String(line.dropFirst(2)))
        return
      }

      guard let (key, value) = keyValue(from: line) else { return }
      applyGroupField(key: key, value: value, indent: indent)
    }

    flushCurrentGroup()

    if groups.isEmpty {
      let fallback = extractProxyNames(from: profileYaml)
      return [
        ProxyGroupSnapshot(
          name: "GLOBAL",
          selected: fallback.first,
          all: fallback,
          type: "select"
        )
      ]
    }
    return groups
  }

  public func extractProxyNames(from profileYaml: String) -> [String] {
    var insideProxies = false
    var currentName: String?
    var names: [String] = []

    func flushCurrentName() {
      guard let currentName, !currentName.isEmpty else {
        return
      }
      names.append(currentName)
    }

    profileYaml.enumerateLines { rawLine, _ in
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      if line == "proxies:" {
        insideProxies = true
        currentName = nil
        return
      }

      if insideProxies, !line.isEmpty, !line.hasPrefix("-"), !rawLine.hasPrefix("  ") {
        flushCurrentName()
        insideProxies = false
      }

      guard insideProxies else { return }

      if line.hasPrefix("- ") {
        flushCurrentName()
        currentName = nil

        let firstEntry = String(line.dropFirst(2)).trimmingCharacters(in: .whitespaces)
        if firstEntry.hasPrefix("{"), firstEntry.hasSuffix("}") {
          currentName = inlineObjectValue(for: "name", in: firstEntry)
        } else if let (key, value) = keyValue(from: firstEntry), key == "name" {
          currentName = value
        }
        return
      }

      guard currentName == nil, let (key, value) = keyValue(from: line), key == "name" else {
        return
      }
      currentName = value
    }

    flushCurrentName()

    if !names.contains("DIRECT") {
      names.append("DIRECT")
    }
    return uniquePreservingOrder(names)
  }

  public func extractRuleCount(from profileYaml: String) -> Int {
    let lines = profileYaml.components(separatedBy: .newlines)
    var insideRules = false
    var count = 0

    for rawLine in lines {
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      if line == "rules:" {
        insideRules = true
        continue
      }

      if insideRules, !line.hasPrefix("-"), !line.isEmpty {
        insideRules = false
      }

      if insideRules, line.hasPrefix("- ") {
        count += 1
      }
    }

    return count
  }

  public func extractProxyNodes(from profileYaml: String) -> [ProxyNodeRecord] {
    var insideProxies = false
    var currentProxy: [String: String] = [:]
    var records: [ProxyNodeRecord] = []

    func flushCurrentProxy() {
      guard let name = currentProxy["name"], !name.isEmpty else {
        currentProxy = [:]
        return
      }

      let security = [currentProxy["cipher"], currentProxy["flow"], currentProxy["servername"], currentProxy["sni"]]
        .compactMap { value -> String? in
          guard let value, !value.isEmpty else { return nil }
          return value
        }
        .joined(separator: " · ")

      records.append(
        ProxyNodeRecord(
          id: "proxy-\(records.count)-\(name)",
          name: name,
          type: currentProxy["type"] ?? "",
          server: currentProxy["server"] ?? "",
          port: currentProxy["port"] ?? "",
          network: currentProxy["network"] ?? "",
          security: security,
          udp: (currentProxy["udp"] ?? "").lowercased() == "true",
          tls: (currentProxy["tls"] ?? "").lowercased() == "true"
        )
      )
      currentProxy = [:]
    }

    profileYaml.enumerateLines { rawLine, _ in
      let trimmed = rawLine.trimmingCharacters(in: .whitespaces)

      if trimmed == "proxies:" {
        insideProxies = true
        currentProxy = [:]
        return
      }

      if insideProxies, !trimmed.isEmpty, !trimmed.hasPrefix("-"), !rawLine.hasPrefix("  ") {
        flushCurrentProxy()
        insideProxies = false
      }

      guard insideProxies else { return }

      if trimmed.hasPrefix("- ") {
        flushCurrentProxy()

        let firstEntry = String(trimmed.dropFirst(2)).trimmingCharacters(in: .whitespaces)
        if firstEntry.hasPrefix("{"), firstEntry.hasSuffix("}") {
          currentProxy.merge(inlineObjectValues(in: firstEntry), uniquingKeysWith: { _, new in new })
        } else if let (key, value) = keyValue(from: firstEntry) {
          currentProxy[key] = value
        }
        return
      }

      guard !currentProxy.isEmpty, let (key, value) = keyValue(from: trimmed) else { return }

      switch key {
      case "type", "server", "port", "network", "cipher", "flow", "udp", "tls", "servername", "sni":
        currentProxy[key] = value
      case "name":
        currentProxy[key] = value
      default:
        return
      }
    }

    flushCurrentProxy()
    return records
  }

  public func parseDnsSummary(from yaml: String) -> DnsSummary {
    var summary = DnsSummary()
    let lines = yaml.components(separatedBy: .newlines)
    var sectionStack: [String] = []

    for rawLine in lines {
      let indent = rawLine.prefix { $0 == " " }.count
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      guard !line.isEmpty, !line.hasPrefix("#") else { continue }

      if line == "dns:" {
        sectionStack = ["dns"]
        continue
      }

      if sectionStack.first == "dns", isTopLevelMappingLine(rawLine), line != "dns:" {
        sectionStack = []
      }

      if sectionStack.first != "dns" {
        continue
      }

      if indent <= 2, line.hasSuffix(":") && line != "dns:" {
        sectionStack = ["dns", String(line.dropLast())]
        continue
      }

      if let value = value(for: "enable", in: line) {
        summary.enabled = value == "true"
      }
      if let value = value(for: "enhanced-mode", in: line) {
        summary.enhancedMode = value
      }
      if let value = value(for: "fake-ip-range", in: line) {
        summary.fakeIPRange = value
      }

      if line.hasPrefix("- ") {
        let item = line.replacingOccurrences(of: "- ", with: "").trimmingCharacters(in: .whitespaces)
        switch sectionStack.last {
        case "fake-ip-filter":
          summary.fakeIPFilter.append(item)
        case "nameserver":
          summary.nameservers.append(item)
        case "proxy-server-nameserver":
          summary.proxyServerNameservers.append(item)
        case "direct-nameserver":
          summary.directNameservers.append(item)
        case "fallback":
          summary.fallbackServers.append(item)
        default:
          break
        }
      }

      if sectionStack.last == "nameserver-policy", indent == 4, !line.hasPrefix("- "), line.contains(":") {
        let key = line.components(separatedBy: ":").first?.trimmingCharacters(in: CharacterSet(charactersIn: "\" ")) ?? ""
        if !key.isEmpty && key != "nameserver-policy" {
          summary.nameserverPolicyKeys.append(key)
        }
      }
    }

    return summary
  }

  public func extractRules(from profileYaml: String) -> [RuleMatchRecord] {
    RoutingPolicyService.ruleStrings(in: profileYaml).map { raw in
      var parts = raw.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
      if parts.last == "no-resolve" { parts.removeLast() }
      let type = parts.first ?? "MATCH"
      let payload = type == "MATCH" ? "*" : parts.dropFirst().dropLast().joined(separator: ",")
      return RuleMatchRecord(type: type, payload: payload, target: parts.last ?? "DIRECT", raw: raw)
    }
  }

  public func extractResources(
    profileYaml: String,
    controlledConfigYaml: String,
    overrideYaml: String
  ) -> [ResourceRecord] {
    let merged = [profileYaml, controlledConfigYaml, overrideYaml].joined(separator: "\n")
    let providers = extractProviderSection(named: "rule-providers", kind: "rule-provider", from: merged)
    let proxyProviders = extractProviderSection(named: "proxy-providers", kind: "proxy-provider", from: merged)
    let geoResources = extractGeoXResources(from: merged)

    let urls = merged
      .components(separatedBy: .newlines)
      .map { $0.trimmingCharacters(in: .whitespaces) }
      .filter { $0.contains("http://") || $0.contains("https://") }
      .enumerated()
      .map { index, line in
        ResourceRecord(
          name: "remote-\(index + 1)",
          kind: "remote-url",
          source: line.replacingOccurrences(of: "url:", with: "").trimmingCharacters(in: .whitespaces),
          interval: ""
        )
      }

    let mergedResources = geoResources + providers + proxyProviders + urls
    var seen = Set<String>()
    return mergedResources.filter { resource in
      seen.insert(resource.id + resource.source + resource.path).inserted
    }
  }

  public func parseTunSummary(from yaml: String) -> TunSummary {
    let section = section(named: "tun", in: yaml)
    return TunSummary(
      enabled: boolValue(for: "enable", in: section) ?? false,
      stack: firstValue(forAnyOf: ["stack"], in: section) ?? "system",
      autoRoute: boolValue(for: "auto-route", in: section) ?? false,
      autoDetectInterface: boolValue(for: "auto-detect-interface", in: section) ?? false,
      dnsHijack: listValue(for: "dns-hijack", in: section),
      inet4Addresses: listValue(for: "inet4-address", in: section),
      inet6Addresses: listValue(for: "inet6-address", in: section),
      ipv6Enabled: topLevelBoolValue(for: "ipv6", in: yaml) ?? true,
      mtu: Int(firstValue(forAnyOf: ["mtu"], in: section) ?? "")
    )
  }

  public func makePacketTunnelNetworkPlan(from yaml: String) -> PacketTunnelNetworkPlan {
    let dnsSummary = parseDnsSummary(from: yaml)
    let tunSummary = parseTunSummary(from: yaml)
    if tunSummary.inet4Addresses.isEmpty {
      return makePacketTunnelNetworkPlan(from: ensuringIOSTunIPv4Address(in: yaml))
    }

    let ipv4Layout = packetTunnelIPv4Layout(from: tunSummary, avoidingFakeIPRange: dnsSummary.fakeIPRange)

    let ipv6Layout = packetTunnelIPv6Layout(from: tunSummary)
    var dnsServers = [ipv4Layout.dnsServerAddress]
    if let dnsServerIPv6Address = ipv6Layout?.dnsServerAddress {
      dnsServers.append(dnsServerIPv6Address)
    }

    return PacketTunnelNetworkPlan(
      tunnelRemoteAddress: ipv4Layout.dnsServerAddress,
      ipv4Address: ipv4Layout.interfaceAddress,
      ipv4SubnetMask: subnetMask(prefixLength: 30) ?? "255.255.255.252",
      dnsServers: dnsServers,
      ipv6Address: ipv6Layout?.interfaceAddress,
      ipv6PrefixLength: ipv6Layout?.prefixLength,
      mtu: tunSummary.effectiveMTU
    )
  }

  public func parseMihomoSummary(from yaml: String) -> MihomoSummary {
    MihomoSummary(
      mode: parseMode(from: yaml),
      mixedPort: firstValue(forAnyOf: ["mixed-port", "mixedPort"], in: yaml) ?? "",
      socksPort: firstValue(forAnyOf: ["socks-port", "socksPort"], in: yaml) ?? "",
      redirPort: firstValue(forAnyOf: ["redir-port", "redirPort"], in: yaml) ?? "",
      tproxyPort: firstValue(forAnyOf: ["tproxy-port", "tproxyPort"], in: yaml) ?? "",
      allowLan: boolValue(forAnyOf: ["allow-lan", "allowLan"], in: yaml) ?? false,
      logLevel: firstValue(forAnyOf: ["log-level", "logLevel"], in: yaml) ?? "info"
    )
  }

  public func parseSubStoreSummary(from appConfigJson: String) -> SubStoreSummary {
    guard let data = appConfigJson.data(using: .utf8),
          let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      return SubStoreSummary()
    }

    let subStore = (raw["subStore"] as? [String: Any]) ?? [:]
    let remoteURL = stringValue(forAnyOf: ["url", "remoteURL", "remote"], in: subStore) ?? ""
    let artifact = stringValue(forAnyOf: ["artifact", "artifactName"], in: subStore) ?? ""
    let interval = intValue(forAnyOf: ["syncIntervalMinutes", "intervalMinutes"], in: subStore) ?? 0
    let enabled = boolValue(forAnyOf: ["enabled", "enable"], in: subStore) ?? !remoteURL.isEmpty

    return SubStoreSummary(
      enabled: enabled,
      remoteURL: remoteURL,
      artifact: artifact,
      syncIntervalMinutes: interval
    )
  }

  public func parseDelayTestSettings(from appConfigJson: String) -> DelayTestSettings {
    guard let data = appConfigJson.data(using: .utf8),
          let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      return DelayTestSettings(timeoutMilliseconds: Self.defaultDelayTestTimeoutMilliseconds)
    }

    let url = stringValue(forAnyOf: ["delayTestUrl", "proxyDelayTestURL"], in: raw)?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let timeout = intValue(forAnyOf: ["delayTestTimeout", "proxyDelayTimeout"], in: raw)
      ?? Self.defaultDelayTestTimeoutMilliseconds

    return DelayTestSettings(
      url: url,
      timeoutMilliseconds: timeout > 0 ? timeout : Self.defaultDelayTestTimeoutMilliseconds
    )
  }

  public func resolveDelayTestSettings(
    preferredURL: String?,
    appConfigJson: String
  ) -> DelayTestSettings {
    let appConfigSettings = parseDelayTestSettings(from: appConfigJson)
    let preferredProbeURL = preferredURL?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let fallbackProbeURL = appConfigSettings.url.trimmingCharacters(in: .whitespacesAndNewlines)

    return DelayTestSettings(
      url: !preferredProbeURL.isEmpty
        ? preferredProbeURL
        : (!fallbackProbeURL.isEmpty ? fallbackProbeURL : Self.defaultDelayTestURL),
      timeoutMilliseconds: appConfigSettings.timeoutMilliseconds > 0
        ? appConfigSettings.timeoutMilliseconds
        : Self.defaultDelayTestTimeoutMilliseconds
    )
  }

  private func parseMode(from yaml: String) -> String {
    yaml
      .components(separatedBy: .newlines)
      .first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("mode:") })?
      .components(separatedBy: ":")
      .dropFirst()
      .joined(separator: ":")
      .trimmingCharacters(in: .whitespaces) ?? "rule"
  }

  private func topLevelKeys(in yaml: String) -> Set<String> {
    Set(
      yaml
        .components(separatedBy: .newlines)
        .compactMap { line -> String? in
          let trimmed = line.trimmingCharacters(in: .whitespaces)
          guard !trimmed.isEmpty, !trimmed.hasPrefix("#"), !line.hasPrefix(" "), let separatorIndex = trimmed.firstIndex(of: ":") else {
            return nil
          }
          return String(trimmed[..<separatorIndex]).trimmingCharacters(in: .whitespaces)
        }
    )
  }

  private func ensuringMobileTunDefaults(in yaml: String) -> String {
    var result = yaml
    let tunSection = section(named: "tun", in: result)
    var additions: [String] = []
    let configuredMTU = firstValue(forAnyOf: ["mtu"], in: tunSection)
    if configuredMTU == nil { additions.append("  mtu: 1500") }
    else if configuredMTU == "0" {
      result = result.replacingOccurrences(of: "(?m)^  mtu: 0\\s*$", with: "  mtu: 1500", options: .regularExpression)
    }
    if topLevelBoolValue(for: "ipv6", in: result) != false,
       !containsKey("inet6-address:", in: tunSection) {
      additions += ["  inet6-address:", "    - fdfe:dcba:9876::1/126"]
    }
    guard !additions.isEmpty else { return result }
    var lines = result.components(separatedBy: .newlines)
    guard let index = lines.firstIndex(of: "tun:") else { return result }
    lines.insert(contentsOf: additions, at: index + 1)
    return lines.joined(separator: "\n")
  }

  private func ensuringStoreSelectedEnabled(in yaml: String) -> String {
    let lines = yaml.components(separatedBy: .newlines)
    var result: [String] = []
    var sawProfileSection = false
    var insideProfileSection = false
    var insertedStoreSelected = false
    var sawStoreFakeIP = false

    func flushProfileSectionIfNeeded() {
      guard insideProfileSection else { return }
      if !insertedStoreSelected {
        result.append("  store-selected: true")
      }
      if !sawStoreFakeIP { result.append("  store-fake-ip: true") }
      insideProfileSection = false
      insertedStoreSelected = false
      sawStoreFakeIP = false
    }

    for rawLine in lines {
      let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
      let indent = leadingSpaceCount(in: rawLine)
      let isTopLevelSection = !trimmed.isEmpty && indent == 0

      if insideProfileSection, isTopLevelSection, trimmed != "profile:" {
        flushProfileSectionIfNeeded()
      }

      if trimmed == "profile:", indent == 0 {
        flushProfileSectionIfNeeded()
        sawProfileSection = true
        insideProfileSection = true
        result.append(rawLine)
        continue
      }

      if insideProfileSection, indent == 2, trimmed.hasPrefix("store-fake-ip:") { sawStoreFakeIP = true }
      if insideProfileSection, indent == 2, trimmed.hasPrefix("store-selected:") {
        if !insertedStoreSelected {
          result.append("  store-selected: true")
          insertedStoreSelected = true
        }
        continue
      }

      result.append(rawLine)
    }

    flushProfileSectionIfNeeded()

    if !sawProfileSection {
      let trimmedResult = result.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
      if trimmedResult.isEmpty {
        return """
        profile:
          store-selected: true
          store-fake-ip: true
        """
      }
      return """
      \(trimmedResult)

      profile:
        store-selected: true
        store-fake-ip: true
      """
    }

    return result.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private func removingTopLevelKeys(from yaml: String, keys: Set<String>) -> String {
    guard !keys.isEmpty else {
      return yaml.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    let lines = yaml.components(separatedBy: .newlines)
    var result: [String] = []
    var skippingKey: String?

    for rawLine in lines {
      let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
      let isTopLevelMapping = isTopLevelMappingLine(rawLine)

      if skippingKey != nil {
        guard isTopLevelMapping else {
          continue
        }
        skippingKey = nil
      }

      if isTopLevelMapping, let separatorIndex = trimmed.firstIndex(of: ":") {
        let key = String(trimmed[..<separatorIndex]).trimmingCharacters(in: .whitespaces)
        if keys.contains(key) {
          let value = trimmed[trimmed.index(after: separatorIndex)...].trimmingCharacters(in: .whitespaces)
          if value.isEmpty {
            skippingKey = key
          }
          continue
        }
      }

      result.append(rawLine)
    }

    return result
      .joined(separator: "\n")
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private func isTopLevelMappingLine(_ rawLine: String) -> Bool {
    let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
    return leadingSpaceCount(in: rawLine) == 0
      && !trimmed.isEmpty
      && !trimmed.hasPrefix("#")
      && !trimmed.hasPrefix("- ")
      && trimmed.contains(":")
  }

  private func mappingKey(in line: String) -> String? {
    guard let separatorIndex = line.firstIndex(of: ":") else {
      return nil
    }
    return String(line[..<separatorIndex])
      .trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
  }

  private func containsKey(_ key: String, in yaml: String) -> Bool {
    yaml.range(of: key, options: [.caseInsensitive]) != nil
  }

  private func value(for key: String, in line: String) -> String? {
    guard line.hasPrefix("\(key):") else { return nil }
    return line
      .components(separatedBy: ":")
      .dropFirst()
      .joined(separator: ":")
      .trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
  }

  private func value(afterMappingKeyIn line: String) -> String {
    guard let separatorIndex = line.firstIndex(of: ":") else {
      return ""
    }
    let valueStart = line.index(after: separatorIndex)
    return String(line[valueStart...])
      .trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
  }

  private func keyValue(from line: String) -> (String, String)? {
    guard let separatorIndex = line.firstIndex(of: ":") else { return nil }
    let key = String(line[..<separatorIndex]).trimmingCharacters(in: .whitespaces)
    guard !key.isEmpty else { return nil }
    let valueStart = line.index(after: separatorIndex)
    let value = String(line[valueStart...]).trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
    return (key, value)
  }

  private func inlineObjectValue(for key: String, in object: String) -> String? {
    inlineObjectValues(in: object)[key]
  }

  private func inlineObjectValues(in object: String) -> [String: String] {
    let trimmed = object
      .trimmingCharacters(in: .whitespaces)
      .trimmingCharacters(in: CharacterSet(charactersIn: "{}"))

    guard !trimmed.isEmpty else { return [:] }

    var values: [String: String] = [:]
    for pair in trimmed.split(separator: ",") {
      guard let (key, value) = keyValue(from: String(pair).trimmingCharacters(in: .whitespaces)) else {
        continue
      }
      values[key] = value
    }
    return values
  }

  private func uniquePreservingOrder(_ values: [String]) -> [String] {
    var seen = Set<String>()
    return values.filter { seen.insert($0).inserted }
  }

  private func leadingSpaceCount(in line: String) -> Int {
    line.prefix { $0 == " " }.count
  }

  private func inlineListValues(from value: String) -> [String] {
    let trimmed = value.trimmingCharacters(in: .whitespaces)
    guard !trimmed.isEmpty else { return [] }
    guard trimmed.hasPrefix("["),
          trimmed.hasSuffix("]") else {
      let normalized = normalizedListValue(trimmed)
      return normalized.isEmpty ? [] : [normalized]
    }

    let content = String(trimmed.dropFirst().dropLast())
    return content
      .split(separator: ",")
      .map { normalizedListValue(String($0)) }
      .filter { !$0.isEmpty }
  }

  private func normalizedListValue(_ value: String) -> String {
    value.trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
  }

  private func normalizedProxyServerHost(_ value: String) -> String? {
    var host = normalizedListValue(value)
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
      .trimmingCharacters(in: CharacterSet(charactersIn: ","))

    if let url = URL(string: host),
       url.scheme != nil,
       let urlHost = url.host {
      host = urlHost
    } else if let colonIndex = host.lastIndex(of: ":") {
      let beforeColon = String(host[..<colonIndex])
      let afterColon = String(host[host.index(after: colonIndex)...])
      if !beforeColon.contains(":"),
         !afterColon.isEmpty,
         afterColon.allSatisfy(\.isNumber) {
        host = beforeColon
      }
    }

    host = host
      .trimmingCharacters(in: CharacterSet(charactersIn: "."))
      .lowercased()

    guard !host.isEmpty,
          host != "localhost",
          !host.contains(":"),
          !isIPv4Literal(host) else {
      return nil
    }
    return host
  }

  private func normalizedProxyServerEndpointHost(_ value: String) -> String? {
    var host = normalizedListValue(value)
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .trimmingCharacters(in: CharacterSet(charactersIn: ","))

    if let url = URL(string: host),
       url.scheme != nil,
       let urlHost = url.host {
      host = urlHost
    } else if host.hasPrefix("["),
              let closingBracket = host.firstIndex(of: "]") {
      let start = host.index(after: host.startIndex)
      host = String(host[start..<closingBracket])
    } else if let colonIndex = host.lastIndex(of: ":") {
      let beforeColon = String(host[..<colonIndex])
      let afterColon = String(host[host.index(after: colonIndex)...])
      if !beforeColon.contains(":"),
         !afterColon.isEmpty,
         afterColon.allSatisfy(\.isNumber) {
        host = beforeColon
      }
    }

    host = host
      .trimmingCharacters(in: CharacterSet(charactersIn: "."))
      .lowercased()

    guard !host.isEmpty,
          host != "localhost" else {
      return nil
    }
    return host
  }

  private func normalizedBootstrapDNSIPAddress(_ value: String) -> String? {
    var host = normalizedListValue(value)
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .trimmingCharacters(in: CharacterSet(charactersIn: ","))

    // An upstream explicitly assigned to a proxy must remain inside the
    // tunnel. Only direct bootstrap endpoints need a system route exclusion.
    if let hash = host.firstIndex(of: "#") {
      let fragment = String(host[host.index(after: hash)...]).removingPercentEncoding
        ?? String(host[host.index(after: hash)...])
      let route = fragment.split(separator: "&")
        .last(where: { !$0.contains("=") })
        .map(String.init) ?? ""
      if !route.isEmpty && route.uppercased() != "DIRECT" {
        return nil
      }
      host = String(host[..<hash])
    }

    if let url = URL(string: host),
       url.scheme != nil,
       let urlHost = url.host {
      host = urlHost
    } else if host.hasPrefix("["),
              let closingBracket = host.firstIndex(of: "]") {
      let start = host.index(after: host.startIndex)
      host = String(host[start..<closingBracket])
    } else if let colonIndex = host.lastIndex(of: ":") {
      let beforeColon = String(host[..<colonIndex])
      let afterColon = String(host[host.index(after: colonIndex)...])
      if !beforeColon.contains(":"),
         !afterColon.isEmpty,
         afterColon.allSatisfy(\.isNumber) {
        host = beforeColon
      }
    }

    host = host
      .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
      .trimmingCharacters(in: CharacterSet(charactersIn: "."))
      .lowercased()

    guard isIPLiteral(host) else {
      return nil
    }
    return host
  }

  private func isIPv4Literal(_ value: String) -> Bool {
    let parts = value.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return false }
    return parts.allSatisfy { part in
      guard let number = Int(part), (0...255).contains(number) else {
        return false
      }
      return String(number) == String(part)
    }
  }

  private func isIPLiteral(_ value: String) -> Bool {
    var ipv4Address = in_addr()
    if value.withCString({ inet_pton(AF_INET, $0, &ipv4Address) }) == 1 {
      return true
    }

    var ipv6Address = in6_addr()
    return value.withCString { inet_pton(AF_INET6, $0, &ipv6Address) } == 1
  }

  private func firstValue(forAnyOf keys: [String], in yaml: String) -> String? {
    let lines = yaml.components(separatedBy: .newlines)
    for rawLine in lines {
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      for key in keys {
        if let result = value(for: key, in: line) {
          return result
        }
      }
    }
    return nil
  }

  private func boolValue(for key: String, in yaml: String) -> Bool? {
    firstValue(forAnyOf: [key], in: yaml).map { $0.lowercased() == "true" }
  }

  private func boolValue(forAnyOf keys: [String], in yaml: String) -> Bool? {
    firstValue(forAnyOf: keys, in: yaml).map { $0.lowercased() == "true" }
  }

  private func topLevelValue(for key: String, in yaml: String) -> String? {
    let lines = yaml.components(separatedBy: .newlines)
    for rawLine in lines {
      let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
      guard !trimmed.isEmpty,
            !trimmed.hasPrefix("#"),
            leadingSpaceCount(in: rawLine) == 0 else {
        continue
      }

      if let result = value(for: key, in: trimmed) {
        return result
      }
    }

    return nil
  }

  private func topLevelBoolValue(for key: String, in yaml: String) -> Bool? {
    topLevelValue(for: key, in: yaml).map { $0.lowercased() == "true" }
  }

  private func section(named name: String, in yaml: String) -> String {
    let lines = yaml.components(separatedBy: .newlines)
    var collected: [String] = []
    var inside = false

    for rawLine in lines {
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      if line == "\(name):" {
        inside = true
        continue
      }

      if inside, isTopLevelMappingLine(rawLine), line != "\(name):" {
        break
      }

      if inside {
        collected.append(rawLine)
      }
    }

    return collected.joined(separator: "\n")
  }

  private func listValue(for key: String, in yamlSection: String) -> [String] {
    let lines = yamlSection.components(separatedBy: .newlines)
    var collecting = false
    var values: [String] = []

    for rawLine in lines {
      let indent = rawLine.prefix { $0 == " " }.count
      let line = rawLine.trimmingCharacters(in: .whitespaces)

      if let inlineValue = value(for: key, in: line) {
        let inlineValues = inlineListValues(from: inlineValue)
        if !inlineValues.isEmpty {
          return inlineValues
        }

        collecting = true
        continue
      }

      if collecting, indent <= 2, line.hasSuffix(":"), !line.hasPrefix("- ") {
        collecting = false
      }

      if collecting, line.hasPrefix("- ") {
        values.append(line.replacingOccurrences(of: "- ", with: "").trimmingCharacters(in: .whitespaces))
      }
    }

    return values
  }

  private func packetTunnelIPv6Layout(from tunSummary: TunSummary) -> (interfaceAddress: String, dnsServerAddress: String, prefixLength: Int)? {
    guard tunSummary.ipv6Enabled else { return nil }

    let inet6Address = tunSummary.inet6Addresses.first?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard !inet6Address.isEmpty else { return nil }
    let prefixLength = prefixLength(fromCIDR: inet6Address) ?? 126
    let interfaceAddress = ipv6Address(fromCIDR: inet6Address) ?? "fdfe:dcba:9876::1"
    let dnsServerAddress = nextIPv6Address(after: interfaceAddress) ?? "fdfe:dcba:9876::2"

    return (interfaceAddress, dnsServerAddress, prefixLength)
  }

  private func packetTunnelIPv4Layout(
    from tunSummary: TunSummary,
    avoidingFakeIPRange fakeIPRange: String
  ) -> (interfaceAddress: String, dnsServerAddress: String) {
    if let configuredTunAddress = tunSummary.inet4Addresses.first?
      .trimmingCharacters(in: .whitespacesAndNewlines),
       let interfaceAddress = ipv4Address(fromCIDR: configuredTunAddress),
       let dnsServerAddress = nextIPv4Address(after: interfaceAddress),
       !ipv4CIDR(fakeIPRange, contains: interfaceAddress),
       !ipv4CIDR(fakeIPRange, contains: dnsServerAddress) {
      return (interfaceAddress, dnsServerAddress)
    }

    let candidates = [
      ("172.31.255.1", "172.31.255.2"),
      ("10.255.255.1", "10.255.255.2"),
      ("192.0.2.1", "192.0.2.2"),
      ("198.18.0.1", "198.18.0.2")
    ]

    for candidate in candidates {
      if !ipv4CIDR(fakeIPRange, contains: candidate.0),
         !ipv4CIDR(fakeIPRange, contains: candidate.1) {
        return (candidate.0, candidate.1)
      }
    }

    return ("172.31.255.1", "172.31.255.2")
  }

  private func ipv4Address(fromCIDR value: String) -> String? {
    guard let address = cidrAddress(from: value), isIPv4Address(address) else { return nil }
    return address
  }

  private func ipv6Address(fromCIDR value: String) -> String? {
    guard let address = cidrAddress(from: value), isIPv6Address(address) else { return nil }
    return address
  }

  private func prefixLength(fromCIDR value: String) -> Int? {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }

    let components = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
    guard components.count == 2, let prefixLength = Int(components[1]) else { return nil }
    return prefixLength
  }

  private func cidrAddress(from value: String) -> String? {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }

    return trimmed
      .split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
      .first
      .map(String.init)?
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private func subnetMask(prefixLength: Int) -> String? {
    guard (0...32).contains(prefixLength) else { return nil }
    let mask = prefixLength == 0 ? UInt32.zero : UInt32.max << (32 - UInt32(prefixLength))
    return [
      String((mask >> 24) & 0xff),
      String((mask >> 16) & 0xff),
      String((mask >> 8) & 0xff),
      String(mask & 0xff),
    ].joined(separator: ".")
  }

  private func ipv4CIDR(_ cidr: String, contains address: String) -> Bool {
    guard let networkAddress = ipv4Address(fromCIDR: cidr),
          let prefixLength = prefixLength(fromCIDR: cidr),
          (0...32).contains(prefixLength),
          let networkValue = ipv4AddressValue(networkAddress),
          let addressValue = ipv4AddressValue(address) else {
      return false
    }

    let mask = prefixLength == 0 ? UInt32.zero : UInt32.max << (32 - UInt32(prefixLength))
    return (networkValue & mask) == (addressValue & mask)
  }

  private func ipv4AddressValue(_ address: String) -> UInt32? {
    let octets = address
      .split(separator: ".")
      .compactMap { UInt32($0) }
    guard octets.count == 4, octets.allSatisfy({ $0 <= 255 }) else { return nil }

    return (octets[0] << 24)
      | (octets[1] << 16)
      | (octets[2] << 8)
      | octets[3]
  }

  private func nextIPv4Address(after address: String) -> String? {
    let octets = address
      .split(separator: ".")
      .compactMap { Int($0) }
    guard octets.count == 4, octets.allSatisfy({ (0...255).contains($0) }) else { return nil }

    var next = octets
    for index in stride(from: next.count - 1, through: 0, by: -1) {
      if next[index] < 255 {
        next[index] += 1
        return next.map(String.init).joined(separator: ".")
      }

      next[index] = 0
    }

    return nil
  }

  private func nextIPv6Address(after address: String) -> String? {
    var ipv6 = in6_addr()
    let parsed = address.withCString { pointer in
      inet_pton(AF_INET6, pointer, &ipv6)
    }
    guard parsed == 1 else { return nil }

    var bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
    for index in stride(from: bytes.count - 1, through: 0, by: -1) {
      if bytes[index] < .max {
        bytes[index] += 1
        break
      }

      bytes[index] = 0
      if index == 0 {
        return nil
      }
    }

    var nextIPv6 = in6_addr()
    withUnsafeMutableBytes(of: &nextIPv6) { destination in
      bytes.withUnsafeBytes { source in
        destination.copyBytes(from: source)
      }
    }

    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    let rendered = withUnsafePointer(to: &nextIPv6) { pointer in
      pointer.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<in6_addr>.size) { bytesPointer in
        inet_ntop(AF_INET6, bytesPointer, &buffer, socklen_t(INET6_ADDRSTRLEN))
      }
    }
    guard rendered != nil else { return nil }
    return String(cString: buffer)
  }

  private func isIPv4Address(_ value: String) -> Bool {
    var ipv4 = in_addr()
    return value.withCString { pointer in
      inet_pton(AF_INET, pointer, &ipv4) == 1
    }
  }

  private func isIPv6Address(_ value: String) -> Bool {
    var ipv6 = in6_addr()
    return value.withCString { pointer in
      inet_pton(AF_INET6, pointer, &ipv6) == 1
    }
  }

  private func extractProviderSection(named sectionName: String, kind: String, from yaml: String) -> [ResourceRecord] {
    let lines = yaml.components(separatedBy: .newlines)
    var insideSection = false
    var currentName = ""
    var currentBehavior = ""
    var currentSource = ""
    var currentPath = ""
    var currentInterval = ""
    var resources: [ResourceRecord] = []

    func flushCurrent() {
      guard !currentName.isEmpty else { return }
      resources.append(
        ResourceRecord(
          name: currentName,
          kind: kind,
          behavior: currentBehavior,
          source: currentSource,
          path: currentPath,
          interval: currentInterval
        )
      )
      currentName = ""
      currentBehavior = ""
      currentSource = ""
      currentPath = ""
      currentInterval = ""
    }

    for rawLine in lines {
      let indent = rawLine.prefix { $0 == " " }.count
      let line = rawLine.trimmingCharacters(in: .whitespaces)

      if line == "\(sectionName):" {
        insideSection = true
        continue
      }

      if insideSection, isTopLevelMappingLine(rawLine), line != "\(sectionName):" {
        flushCurrent()
        insideSection = false
      }

      guard insideSection else { continue }

      if indent == 2, line.hasSuffix(":") {
        flushCurrent()
        currentName = String(line.dropLast())
        continue
      }

      if let value = value(for: "behavior", in: line) {
        currentBehavior = value
      }
      if let value = value(for: "url", in: line) {
        currentSource = value
      }
      if let value = value(for: "path", in: line) {
        currentPath = value
      }
      if let value = value(for: "interval", in: line) {
        currentInterval = value
      }
    }

    flushCurrent()
    return resources
  }

  private func mergedNamedMappingSection(named sectionName: String, from yamls: [String]) -> String {
    struct SectionEntry {
      var blockLines: [String]
    }

    var orderedNames: [String] = []
    var entriesByName: [String: SectionEntry] = [:]

    func collectEntries(from yaml: String) {
      let lines = yaml.components(separatedBy: .newlines)
      var insideSection = false
      var currentName = ""
      var currentBlockLines: [String] = []

      func flushCurrent() {
        guard !currentName.isEmpty, !currentBlockLines.isEmpty else {
          currentName = ""
          currentBlockLines = []
          return
        }
        if shouldDropPlaceholderProviderEntry(
          named: sectionName,
          blockLines: currentBlockLines
        ) {
          currentName = ""
          currentBlockLines = []
          return
        }
        if entriesByName[currentName] == nil {
          orderedNames.append(currentName)
        }
        entriesByName[currentName] = SectionEntry(blockLines: currentBlockLines)
        currentName = ""
        currentBlockLines = []
      }

      for rawLine in lines {
        let indent = leadingSpaceCount(in: rawLine)
        let trimmed = rawLine.trimmingCharacters(in: .whitespaces)

        if trimmed == "\(sectionName):", indent == 0 {
          flushCurrent()
          insideSection = true
          continue
        }

        if insideSection, isTopLevelMappingLine(rawLine), trimmed != "\(sectionName):" {
          flushCurrent()
          insideSection = false
        }

        guard insideSection else { continue }

        if indent == 2, trimmed.hasSuffix(":") {
          flushCurrent()
          currentName = String(trimmed.dropLast()).trimmingCharacters(in: .whitespaces)
          currentBlockLines = [rawLine]
          continue
        }

        guard !currentName.isEmpty else { continue }
        currentBlockLines.append(rawLine)
      }

      flushCurrent()
    }

    for yaml in yamls {
      collectEntries(from: yaml)
    }

    guard !orderedNames.isEmpty else { return "" }

    let body = orderedNames.compactMap { name in
      entriesByName[name]?.blockLines.joined(separator: "\n")
    }
      .joined(separator: "\n")

    return """
    \(sectionName):
    \(body)
    """
  }

  private func shouldDropPlaceholderProviderEntry(
    named sectionName: String,
    blockLines: [String]
  ) -> Bool {
    guard sectionName == "rule-providers" || sectionName == "proxy-providers" else {
      return false
    }

    for rawLine in blockLines {
      let trimmedLine = rawLine.trimmingCharacters(in: .whitespaces)
      guard let urlValue = value(for: "url", in: trimmedLine) else { continue }

      let normalizedURL = urlValue
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
      guard let parsedURL = URL(string: normalizedURL),
            let host = parsedURL.host?.lowercased() else {
        continue
      }

      if host == "example.com" || host == "www.example.com" {
        return true
      }
    }

    return false
  }

  private func stringValue(forAnyOf keys: [String], in dictionary: [String: Any]) -> String? {
    for key in keys {
      if let value = dictionary[key] as? String {
        return value
      }
    }
    return nil
  }

  private func intValue(forAnyOf keys: [String], in dictionary: [String: Any]) -> Int? {
    for key in keys {
      if let value = dictionary[key] as? Int {
        return value
      }
      if let value = dictionary[key] as? String, let intValue = Int(value) {
        return intValue
      }
    }
    return nil
  }

  private func boolValue(forAnyOf keys: [String], in dictionary: [String: Any]) -> Bool? {
    for key in keys {
      if let value = dictionary[key] as? Bool {
        return value
      }
      if let value = dictionary[key] as? String {
        return value.lowercased() == "true"
      }
    }
    return nil
  }


}

private extension CompatibilityService {
  static let iOSDisabledTopLevelKeys: Set<String> = [
    "allow-lan",
    "geodata-mode",
    "listeners",
    "mixed-port",
    "port",
    "redir-port",
    "socks-port",
    "tproxy-port"
  ]

}
