import Foundation
import Darwin

public enum IOSRoutingPolicy: String, CaseIterable, Identifiable, Sendable {
  case automatic, profile, general, desktopSnapshot
  public var id: String { rawValue }
  public var title: String {
    switch self {
    case .automatic: return L10n.string("routing.mode.automatic", "Automatic")
    case .profile: return L10n.string("routing.mode.profile", "Profile Rules")
    case .general: return L10n.string("routing.mode.general", "General Routing")
    case .desktopSnapshot: return L10n.string("routing.mode.desktop", "Custom Rules")
    }
  }
}

public struct DesktopRoutingSnapshot: Codable, Equatable, Sendable {
  public var version: Int
  public var generatedAt: String
  public var sourceRuleCount: Int
  public var skippedProcessRuleCount: Int
  public var policyMap: [String: String]
  public var rules: [String]

  public func validate() throws {
    guard version == 1, !rules.isEmpty, rules.count <= 50_000,
          sourceRuleCount >= rules.count, skippedProcessRuleCount >= 0,
          rules.last?.hasPrefix("MATCH,") == true else {
      throw RoutingPolicyError.invalidSnapshot
    }
    let allowed = Set(["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "GEOIP", "NETWORK", "MATCH"])
    for (index, rule) in rules.enumerated() {
      let parts = rule.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
      guard let kind = parts.first, allowed.contains(kind), !rule.contains("\n"),
            parts.count >= (kind == "MATCH" ? 2 : 3) else { throw RoutingPolicyError.invalidSnapshot }
      let target = parts[kind == "MATCH" ? 1 : 2]
      guard ["DIRECT", "REJECT", RoutingPolicyService.proxyPlaceholder].contains(target),
            parts.dropFirst(kind == "MATCH" ? 2 : 3).allSatisfy({ $0 == "no-resolve" }) else {
        throw RoutingPolicyError.invalidSnapshot
      }
      if kind == "IP-CIDR" || kind == "IP-CIDR6" {
        guard RoutingRuleResources.isValidCIDR(parts[1]) else { throw RoutingPolicyError.invalidSnapshot }
      }
      if kind == "MATCH", index != rules.count - 1 { throw RoutingPolicyError.invalidSnapshot }
      let baseCount = kind == "MATCH" ? 2 : 3
      guard parts.count <= baseCount + 1, parts.allSatisfy({ !$0.isEmpty && $0 == $0.trimmingCharacters(in: .whitespacesAndNewlines) }),
            !rule.contains("\r") else { throw RoutingPolicyError.invalidSnapshot }
      if kind.hasPrefix("DOMAIN") {
        let allowedCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_"))
        guard parts[1].unicodeScalars.allSatisfy(allowedCharacters.contains) else { throw RoutingPolicyError.invalidSnapshot }
      }
      if kind == "NETWORK" {
        guard ["tcp", "udp"].contains(parts[1].lowercased()), parts.count == 3 else {
          throw RoutingPolicyError.invalidSnapshot
        }
      }
      if kind == "GEOIP" {
        guard parts[1].count == 2, parts[1].allSatisfy({ $0.isASCII && $0.isLetter }) else { throw RoutingPolicyError.invalidSnapshot }
      }
    }
  }
}

public enum RoutingPolicyError: LocalizedError {
  case invalidSnapshot, missingSnapshot, missingProxy, unsupportedGroupSyntax, invalidRulePayload
  public var errorDescription: String? {
    switch self {
    case .invalidSnapshot: return L10n.string("routing.error.snapshot", "The rule set is invalid or contains unsupported policies.")
    case .missingSnapshot: return L10n.string("routing.error.missing_snapshot", "Import a rule set first.")
    case .missingProxy: return L10n.string("routing.error.proxy", "Import at least one supported proxy node before enabling general routing.")
    case .unsupportedGroupSyntax: return L10n.string("routing.error.groups", "The proxy-groups section must be a YAML sequence.")
    case .invalidRulePayload: return L10n.string("routing.error.payload", "Downloaded rules are empty or invalid; the last valid cache was retained.")
    }
  }
}

public enum RoutingPolicyService {
  public static let configKey = "iosRoutingPolicy"
  public static let proxyPlaceholder = "__IOS_PROXY__"
  public static let managedGroupName = "iOS 外网"

  public static func preference(in appConfig: String) -> IOSRoutingPolicy {
    guard let data = appConfig.data(using: .utf8),
          let values = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let raw = values[configKey] as? String else { return .automatic }
    return IOSRoutingPolicy(rawValue: raw) ?? .automatic
  }

  public static func setting(_ policy: IOSRoutingPolicy, in appConfig: String) throws -> String {
    let data = Data(appConfig.utf8)
    guard var values = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw CocoaError(.propertyListReadCorrupt)
    }
    values[configKey] = policy.rawValue
    return String(decoding: try JSONSerialization.data(withJSONObject: values, options: [.prettyPrinted, .sortedKeys]), as: UTF8.self)
  }

  public static func effectivePolicy(for requested: IOSRoutingPolicy, runtimeConfig: String) -> IOSRoutingPolicy {
    guard requested == .automatic else { return requested }
    // Migrate the narrow GPT validation profile, while keeping imported general
    // subscriptions and explicit profile routing untouched.
    let rules = ruleStrings(in: runtimeConfig)
    guard rules.last == "MATCH,DIRECT", rules.contains(where: isOpenAIRule) else { return .profile }
    let limitedProfile = rules.dropLast().allSatisfy { rule in
      isOpenAIRule(rule) || rule.hasPrefix("IP-CIDR,") || rule.hasPrefix("IP-CIDR6,")
    }
    return limitedProfile ? .general : .profile
  }

  public static func rewrite(
    _ runtimeConfig: String,
    policy requested: IOSRoutingPolicy,
    snapshot: DesktopRoutingSnapshot? = nil
  ) throws -> String {
    let policy = effectivePolicy(for: requested, runtimeConfig: runtimeConfig)
    guard policy != .profile else { return runtimeConfig }
    let normalizedConfig = normalizingProxyGroups(in: runtimeConfig)
    let compatibility = CompatibilityService()
    let supported = Set(["ss", "ssr", "socks5", "http", "vmess", "vless", "snell", "trojan", "hysteria", "wireguard", "tuic"])
    let nodes = compatibility.extractProxyNodes(from: normalizedConfig).filter { supported.contains($0.type.lowercased()) }
    var choices = nodes.map(\.name)
    if choices.isEmpty {
      choices = compatibility.extractProxyGroups(from: normalizedConfig)
        .filter { !$0.all.isEmpty && $0.all.contains(where: { !["DIRECT", "REJECT"].contains($0) }) }
        .map(\.name)
    }
    guard !choices.isEmpty else { throw RoutingPolicyError.missingProxy }
    let occupied = Set(nodes.map(\.name) + compatibility.extractProxyGroups(from: normalizedConfig).map(\.name))
    var groupName = managedGroupName
    var suffix = 1
    while occupied.contains(groupName) { groupName = "\(managedGroupName) \(suffix)"; suffix += 1 }
    var result = try appendingProxyGroup(name: groupName, choices: choices, to: normalizedConfig)

    let rules: [String]
    if policy == .desktopSnapshot {
      guard let snapshot = snapshot ?? loadDesktopSnapshot() else { throw RoutingPolicyError.missingSnapshot }
      try snapshot.validate()
      rules = snapshot.rules.map { $0.replacingOccurrences(of: proxyPlaceholder, with: groupName) }
    } else {
      let originalAI = ruleStrings(in: normalizedConfig).filter(isOpenAIRule)
      var general = nodes.map { node in
        if RoutingRuleResources.isValidCIDR(node.server + "/32") { return "IP-CIDR,\(node.server)/32,DIRECT,no-resolve" }
        if RoutingRuleResources.isValidCIDR(node.server + "/128") { return "IP-CIDR6,\(node.server)/128,DIRECT,no-resolve" }
        return "DOMAIN,\(node.server),DIRECT"
      }
      general += ["IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
                  "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
                  "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve", "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
                  "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve", "IP-CIDR6,::1/128,DIRECT,no-resolve",
                  "IP-CIDR6,fc00::/7,DIRECT,no-resolve", "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
                  "IP-CIDR6,ff00::/8,DIRECT,no-resolve", "DOMAIN-SUFFIX,lan,DIRECT", "DOMAIN-SUFFIX,local,DIRECT"]
      // Keep local discovery local; public UDP must not fall through a country DIRECT rule.
      general += ["NETWORK,udp,\(groupName)"]
      general += originalAI
      // Domain classification precedes IP geolocation and domestic CDN shortcuts.
      general += ["RULE-SET,ios-non-cn,\(groupName)"]
      let foreign = ["chatgpt.com", "openai.com", "oaiusercontent.com", "oaistatic.com", "claude.ai", "claude.com", "claudeusercontent.com", "anthropic.com", "google.com", "googleapis.com", "gstatic.com", "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "github.com", "githubusercontent.com", "githubassets.com", "wikipedia.org", "wikimedia.org", "telegram.org", "t.me", "discord.com", "discordapp.com", "x.com", "twitter.com", "facebook.com", "instagram.com", "reddit.com"]
      general += foreign.map { "DOMAIN-SUFFIX,\($0),\(groupName)" }
      general += ["RULE-SET,ios-private,DIRECT", "RULE-SET,ios-gfw,\(groupName)", "RULE-SET,ios-telegramcidr,\(groupName),no-resolve"]
      general += ["qq.com", "weixin.com", "wechat.com", "qpic.cn", "qlogo.cn", "gtimg.com", "baidu.com", "bilibili.com", "biliapi.net", "taobao.com", "tmall.com", "alipay.com", "jd.com", "163.com", "126.com", "mi.com", "aliyun.com", "cn"]
        .map { "DOMAIN-SUFFIX,\($0),DIRECT" }
      // Both complementary tiny matchers skip empty hosts. Their pair catches
      // every remaining named host, including single labels classified PRIVATE,
      // without loading a second large CN matcher. Explicit LAN rules run first.
      general += ["GEOSITE,cn,DIRECT", "GEOSITE,!private,\(groupName)", "GEOSITE,private,\(groupName)"]
      general += ["RULE-SET,ios-lancidr,DIRECT,no-resolve", "RULE-SET,ios-cncidr,DIRECT", "GEOIP,CN,DIRECT", "MATCH,\(groupName)"]
      rules = general
      result = try appendingProviders(to: result)
    }
    result = replacingSection("rules", in: result, with: "rules:\n" + rules.map { "  - " + yamlString($0) }.joined(separator: "\n"))
    result = replacingSection("mode", in: result, with: "mode: rule")
    return result
  }

  public static func ruleStrings(in yaml: String) -> [String] {
    let lines = yaml.components(separatedBy: .newlines)
    guard let range = sectionRange("rules", lines: lines) else { return [] }
    return lines[range].compactMap { line in
      let value = line.trimmingCharacters(in: .whitespaces)
      guard value.hasPrefix("- ") else { return nil }
      let raw = String(value.dropFirst(2)).trimmingCharacters(in: .whitespaces)
      if raw.hasPrefix("'"), raw.hasSuffix("'") {
        return String(raw.dropFirst().dropLast()).replacingOccurrences(of: "''", with: "'")
      }
      return (try? JSONDecoder().decode(String.self, from: Data(raw.utf8))) ?? raw
    }
  }

  public static func loadDesktopSnapshot(resourceRoot: URL? = nil) -> DesktopRoutingSnapshot? {
    let candidates: [URL]
    if let resourceRoot { candidates = [resourceRoot.appendingPathComponent("desktop-routing-snapshot.json")] }
    else { candidates = [try? SharedStore.desktopRoutingSnapshotURL(), bundledURL("desktop-routing-snapshot", extension: "json")].compactMap { $0 } }
    for url in candidates {
      if let data = try? Data(contentsOf: url), data.count <= 8 * 1024 * 1024,
         let snapshot = try? JSONDecoder().decode(DesktopRoutingSnapshot.self, from: data),
         (try? snapshot.validate()) != nil { return snapshot }
    }
    return nil
  }

  public static func importDesktopSnapshot(_ data: Data) throws -> DesktopRoutingSnapshot {
    guard data.count <= 8 * 1024 * 1024 else { throw RoutingPolicyError.invalidSnapshot }
    let snapshot = try JSONDecoder().decode(DesktopRoutingSnapshot.self, from: data)
    try snapshot.validate()
    let url = try SharedStore.desktopRoutingSnapshotURL()
    try JSONEncoder().encode(snapshot).write(to: url, options: [.atomic])
    return snapshot
  }

  static func bundledURL(_ name: String, extension ext: String) -> URL? {
    for bundle in [Bundle.main, Bundle(for: RoutingResourceAnchor.self)] {
      if let url = bundle.url(forResource: name, withExtension: ext, subdirectory: "RuleResources") { return url }
    }
    return nil
  }

  private static func isOpenAIRule(_ rule: String) -> Bool {
    let parts = rule.split(separator: ",").map(String.init)
    guard parts.count >= 3, ["DOMAIN", "DOMAIN-SUFFIX"].contains(parts[0]) else { return false }
    return ["chatgpt.com", "openai.com", "oaiusercontent.com", "oaistatic.com", "auth0.com", "sentry.io", "challenges.cloudflare.com", "client-api.arkoselabs.com", "events.statsigapi.net", "featuregates.org", "identrust.com", "intercom.io", "intercomcdn.com", "openaiapi-site.azureedge.net", "stripe.com"].contains { parts[1] == $0 || parts[1].hasSuffix("." + $0) }
  }

  private static func normalizingProxyGroups(in yaml: String) -> String {
    let lines = yaml.components(separatedBy: .newlines)
    guard let range = sectionRange("proxy-groups", lines: lines),
          lines[range].dropFirst().contains(where: { $0.hasPrefix("- ") }) else { return yaml }
    let section = [lines[range.lowerBound]] + lines[range].dropFirst().map { $0.isEmpty ? $0 : "  " + $0 }
    return replacingSection("proxy-groups", in: yaml, with: section.joined(separator: "\n"))
  }

  private static func appendingProxyGroup(name: String, choices: [String], to yaml: String) throws -> String {
    let mapping = "  - name: \(yamlString(name))\n    type: select\n    proxies:\n" + choices.map { "      - " + yamlString($0) }.joined(separator: "\n")
    return try appendingMapping(mapping, section: "proxy-groups", flowObject: ["name": name, "type": "select", "proxies": choices], to: yaml)
  }

  private static func appendingProviders(to yaml: String) throws -> String {
    var result = yaml
    for source in RoutingRuleResources.sources {
      let mapping = "  ios-\(source.name):\n    type: http\n    behavior: \(source.behavior)\n    url: \(source.url.absoluteString)\n    path: ./ruleset/ios-\(source.name).yaml\n    interval: 86400"
      // Namespaced providers are managed exclusively by this preset.
      guard !result.components(separatedBy: .newlines).contains(where: { $0.trimmingCharacters(in: .whitespaces) == "ios-\(source.name):" }) else {
        throw RoutingPolicyError.unsupportedGroupSyntax
      }
      result = try appendingMapping(mapping, section: "rule-providers", flowObject: nil, to: result)
    }
    return result
  }

  private static func appendingMapping(_ block: String, section: String, flowObject: [String: Any]?, to yaml: String) throws -> String {
    let lines = yaml.components(separatedBy: .newlines)
    guard let range = sectionRange(section, lines: lines) else { return yaml + "\n\(section):\n\(block)\n" }
    let existing = lines[range].joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
    let header = existing.components(separatedBy: .newlines).first ?? ""
    if header == "\(section): []" || header == "\(section): {}" {
      return replacingSection(section, in: yaml, with: "\(section):\n" + block)
    }
    if header == "\(section):" || header.hasPrefix("\(section): #") {
      // YAML permits indentless sequences (as emitted by PyYAML). Keep the
      // appended group at the same indentation as existing sequence items.
      let indentlessSequence = flowObject != nil && lines[range].dropFirst().contains(where: { $0.hasPrefix("- ") })
      let appended = indentlessSequence
        ? block.components(separatedBy: .newlines).map { String($0.dropFirst(2)) }.joined(separator: "\n")
        : block
      return replacingSection(section, in: yaml, with: existing + "\n" + appended)
    }
    if let flowObject, header.hasPrefix("\(section): ["), header.hasSuffix("]") {
      let encoded = String(decoding: try JSONSerialization.data(withJSONObject: flowObject, options: [.sortedKeys, .withoutEscapingSlashes]), as: UTF8.self)
      return replacingSection(section, in: yaml, with: String(header.dropLast()) + ", " + encoded + "]")
    }
    throw RoutingPolicyError.unsupportedGroupSyntax
  }

  static func replacingSection(_ name: String, in yaml: String, with replacement: String) -> String {
    var lines = yaml.components(separatedBy: .newlines)
    if let range = sectionRange(name, lines: lines) { lines.replaceSubrange(range, with: replacement.components(separatedBy: .newlines)) }
    else { lines += replacement.components(separatedBy: .newlines) }
    return lines.joined(separator: "\n")
  }

  private static func sectionRange(_ name: String, lines: [String]) -> Range<Int>? {
    guard let start = lines.firstIndex(where: { $0.hasPrefix(name + ":") }) else { return nil }
    var end = start + 1
    while end < lines.count {
      let line = lines[end]
      if let first = line.first, !first.isWhitespace, first != "#", first != "-", line.contains(":") { break }
      end += 1
    }
    return start..<end
  }

  static func yamlString(_ text: String) -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    let encoded = try! encoder.encode(text)
    return String(decoding: encoded, as: UTF8.self)
  }
}

private final class RoutingResourceAnchor: NSObject {}

public enum RoutingRuleResources {
  public struct Source: Sendable {
    public let name: String
    public let behavior: String
    public var url: URL {
      if name == "non-cn" {
        return URL(string: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-!cn.yaml")!
      }
      return URL(string: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/\(name).txt")!
    }
  }
  public static let sources = [Source(name: "non-cn", behavior: "domain"), Source(name: "private", behavior: "domain"), Source(name: "gfw", behavior: "domain"),
    Source(name: "cncidr", behavior: "ipcidr"), Source(name: "lancidr", behavior: "ipcidr"), Source(name: "telegramcidr", behavior: "ipcidr")]

  public static func seedIfNeeded(runtimeConfig: String, homeURL: URL, resourceRoot: URL? = nil) throws -> Int {
    let directory = homeURL.appendingPathComponent("ruleset", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    var seeded = 0
    for source in sources where runtimeConfig.contains("RULE-SET,ios-\(source.name),") {
      let destination = directory.appendingPathComponent("ios-\(source.name).yaml")
      if let data = try? Data(contentsOf: destination), isValidPayload(data) { continue }
      guard let origin = resourceRoot?.appendingPathComponent(source.name + ".yaml") ?? RoutingPolicyService.bundledURL(source.name, extension: "yaml") else { throw RoutingPolicyError.invalidRulePayload }
      let data = try Data(contentsOf: origin)
      guard isValidPayload(data) else { throw RoutingPolicyError.invalidRulePayload }
      try data.write(to: destination, options: [.atomic]); seeded += 1
    }
    return seeded
  }

  public static func refresh(homeURL: URL) async -> [String] {
    var errors: [String] = []
    for source in sources {
      do {
        var request = URLRequest(url: source.url)
        request.timeoutInterval = 20
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let response = response as? HTTPURLResponse, (200..<300).contains(response.statusCode), isValidPayload(data) else { throw RoutingPolicyError.invalidRulePayload }
        let directory = homeURL.appendingPathComponent("ruleset", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try data.write(to: directory.appendingPathComponent("ios-\(source.name).yaml"), options: [.atomic])
      } catch { errors.append("\(source.name): \(error.localizedDescription)") }
    }
    return errors
  }

  public static func isValidPayload(_ data: Data) -> Bool {
    guard !data.isEmpty, data.count <= 8 * 1024 * 1024, let text = String(data: data, encoding: .utf8) else { return false }
    let lines = text.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .filter { !$0.isEmpty && !$0.hasPrefix("#") }
    guard lines.first == "payload:", lines.count > 1 else { return false }
    let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-*+_"))
    return lines.dropFirst().allSatisfy { line in
      guard line.hasPrefix("- ") else { return false }
      var value = String(line.dropFirst(2)).trimmingCharacters(in: .whitespaces)
      if value.hasPrefix("\"") {
        guard let decoded = try? JSONDecoder().decode(String.self, from: Data(value.utf8)) else { return false }
        value = decoded
      } else if value.hasPrefix("'"), value.hasSuffix("'") {
        value = String(value.dropFirst().dropLast()).replacingOccurrences(of: "''", with: "'")
      }
      return !value.isEmpty && (isValidCIDR(value) || value.unicodeScalars.allSatisfy { allowed.contains($0) })
    }
  }

  static func isValidCIDR(_ text: String) -> Bool {
    let parts = text.split(separator: "/")
    guard parts.count == 2, let mask = Int(parts[1]) else { return false }
    let address = String(parts[0])
    var ipv4 = in_addr()
    if inet_pton(AF_INET, address, &ipv4) == 1 { return (0...32).contains(mask) }
    var ipv6 = in6_addr()
    return inet_pton(AF_INET6, address, &ipv6) == 1 && (0...128).contains(mask)
  }
}
