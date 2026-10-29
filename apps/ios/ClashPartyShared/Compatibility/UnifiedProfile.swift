import Foundation
import CoreFoundation

/// A transport for existing Mihomo policy, not for privileged app settings or TUN devices.
public enum UnifiedProfile {
  public static let format = "clash-party-unified"
  public static let platforms = ["macos", "windows", "ios"]
  private static let commonKeys: Set<String> = [
    "mode", "ipv6", "log-level", "find-process-mode", "geodata-mode", "geodata-loader",
    "geo-auto-update", "geo-update-interval", "geox-url", "dns", "hosts", "sniffer",
    "proxies", "proxy-groups", "proxy-providers", "rule-providers", "profile"
  ]
  public struct Failure: LocalizedError {
    let reason: String
    public var errorDescription: String? { "Unified profile: \(reason)" }
  }
  private static func fail(_ reason: String) -> Failure { Failure(reason: reason) }
  private static func object(_ value: Any?, _ context: String) throws -> [String: Any] {
    guard let result = value as? [String: Any] else { throw fail("\(context) must be an object") }
    return result
  }
  private static func keys(_ value: [String: Any], _ allowed: Set<String>, _ context: String) throws {
    if let key = value.keys.sorted().first(where: { !allowed.contains($0) }) {
      throw fail("\(context): unsupported field \(key)")
    }
  }
  private static func inspect(_ value: Any, _ depth: Int = 0) throws {
    guard depth <= 32 else { throw fail("nesting exceeds 32 levels") }
    if let value = value as? [String: Any] {
      for (key, child) in value {
        guard !["__proto__", "constructor", "prototype"].contains(key) else { throw fail("unsafe object key") }
        try inspect(child, depth + 1)
      }
    } else if let value = value as? [Any] {
      for child in value { try inspect(child, depth + 1) }
    }
  }
  public static func compile(_ value: Any, platform: String = "ios") throws -> [String: Any] {
    guard platforms.contains(platform) else { throw fail("unknown platform") }
    let envelope = try object(value, "document")
    try inspect(envelope)
    try keys(envelope, ["format", "version", "revision", "common", "rules", "platforms"], "document")
    guard envelope["format"] as? String == format,
          let version = envelope["version"] as? NSNumber,
          CFGetTypeID(version) != CFBooleanGetTypeID(), version == 1 else {
      throw fail("unsupported format or version")
    }
    guard let revision = envelope["revision"] as? String,
          !revision.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
          revision.utf16.count <= 128 else { throw fail("invalid revision") }
    var result = try object(envelope["common"], "common")
    try keys(result, commonKeys, "common (machine settings must be configured in the app)")
    if let dns = result["dns"], try object(dns, "common.dns")["listen"] != nil {
      throw fail("DNS listener belongs to local app settings, not the shared policy")
    }
    let variants = try object(envelope["platforms"] ?? [String: Any](), "platforms")
    try keys(variants, Set(platforms), "platforms")
    for (name, variant) in variants {
      let fields = try object(variant, name)
      try keys(fields, ["rule-providers"], name)
      _ = try object(fields["rule-providers"], "\(name).rule-providers")
    }
    guard let entries = envelope["rules"] as? [Any], !entries.isEmpty, entries.count <= 50000 else {
      throw fail("rules must contain 1–50000 entries")
    }
    var rules: [String] = []
    for entry in entries {
      var candidate: Any? = entry
      var applies = true
      if !(entry is String) {
        let item = try object(entry, "rule")
        try keys(item, ["rule", "platforms"], "rule")
        candidate = item["rule"]
        if let raw = item["platforms"] {
          guard let selected = raw as? [String], !selected.isEmpty,
                selected.allSatisfy({ platforms.contains($0) }), Set(selected).count == selected.count else {
            throw fail("invalid rule platforms")
          }
          applies = selected.contains(platform)
        }
      }
      guard let rule = candidate as? String, !rule.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
            !rule.contains("\n"), !rule.contains("\r") else { throw fail("invalid rule text") }
      if applies { rules.append(rule) }
    }
    func matchTarget(_ rule: String) -> String? {
      let fields = rule.split(separator: ",", omittingEmptySubsequences: false)
      guard fields.count == 2,
            fields[0].trimmingCharacters(in: .whitespaces).uppercased() == "MATCH" else { return nil }
      let target = fields[1].trimmingCharacters(in: .whitespaces)
      return target.isEmpty ? nil : target
    }
    guard let last = rules.last, matchTarget(last) != nil,
          !rules.dropLast().contains(where: { matchTarget($0) != nil }) else {
      throw fail("\(platform) must have exactly one final MATCH rule")
    }
    if let variant = variants[platform] as? [String: Any] {
      var providers = try object(result["rule-providers"] ?? [String: Any](), "common.rule-providers")
      let replacements = try object(variant["rule-providers"], "platform.rule-providers")
      for (name, provider) in replacements {
        if provider is NSNull { providers.removeValue(forKey: name) }
        else { providers[name] = provider }
      }
      result["rule-providers"] = providers
    }
    let providerNames = Set(try object(result["rule-providers"] ?? [String: Any](), "rule-providers").keys)
    let providerPattern = try NSRegularExpression(pattern: "(?:^|[,(])RULE-SET,([^,()]+)(?=[,)])")
    for rule in rules {
      for match in providerPattern.matches(in: rule, range: NSRange(rule.startIndex..., in: rule)) {
        let name = (rule as NSString).substring(with: match.range(at: 1))
        guard providerNames.contains(name) else { throw fail("missing rule provider: \(name)") }
      }
    }
    if platform == "ios" {
      guard !rules.contains(where: {
        $0.range(of: "(?:^|[,(])PROCESS-(?:NAME|PATH|NAME-REGEX|PATH-REGEX),", options: [.regularExpression, .caseInsensitive]) != nil
      }) else { throw fail("iOS cannot apply process rules; declare their desktop platforms explicitly") }
      for value in try object(result["rule-providers"] ?? [String: Any](), "rule-providers").values {
        guard try object(value, "rule provider")["format"] as? String != "mrs" else {
          throw fail("iOS cannot read MRS; provide an explicit YAML provider variant")
        }
      }
    }
    result["rules"] = rules
    return result
  }
  /// nil preserves the ordinary YAML import path. A recognized invalid envelope fails closed.
  public static func importedYAML(_ text: String) throws -> String? {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.hasPrefix("{") else { return nil }
    let data = Data(text.utf8)
    guard data.count <= 8 * 1024 * 1024 else { throw fail("file exceeds 8 MiB") }
    let parsed = try JSONSerialization.jsonObject(with: data)
    guard let object = parsed as? [String: Any], object["format"] != nil else { return nil }
    return try yaml(compile(object)) + "\n"
  }
  private static func scalar(_ value: Any) throws -> String {
    if value is NSNull { return "null" }
    if let text = value as? String,
       text.range(of: "^[A-Za-z_][A-Za-z0-9_.+/-]*$", options: .regularExpression) != nil,
       !["null", "true", "false", "yes", "no", "on", "off"].contains(text.lowercased()) {
      return text
    }
    let data = try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .sortedKeys, .withoutEscapingSlashes])
    return String(decoding: data, as: UTF8.self)
  }
  /// Emit ordinary block YAML for the existing mobile compatibility parser, preserving scalars.
  public static func yaml(_ value: Any, indent: Int = 0) throws -> String {
    let prefix = String(repeating: " ", count: indent)
    if let object = value as? [String: Any], !object.isEmpty {
      return try object.keys.sorted().map { key in
        let name = key.range(of: "^[A-Za-z_][A-Za-z0-9_.-]*$", options: .regularExpression) != nil ? key : String(decoding: try JSONSerialization.data(withJSONObject: key, options: [.fragmentsAllowed]), as: UTF8.self)
        let child = object[key]!
        if isNonemptyContainer(child) { return "\(prefix)\(name):\n" + (try yaml(child, indent: indent + 2)) }
        return "\(prefix)\(name): " + (try scalar(child))
      }.joined(separator: "\n")
    }
    if let array = value as? [Any], !array.isEmpty {
      return try array.map { child in
        if isNonemptyContainer(child) {
          let nested = try yaml(child, indent: indent + 2)
          return prefix + "- " + nested.dropFirst(indent + 2)
        }
        return prefix + "- " + (try scalar(child))
      }.joined(separator: "\n")
    }
    return prefix + (try scalar(value))
  }
  private static func isNonemptyContainer(_ value: Any) -> Bool {
    if let object = value as? [String: Any] { return !object.isEmpty }
    if let array = value as? [Any] { return !array.isEmpty }
    return false
  }
}
