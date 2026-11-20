// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Darwin

struct BootLeakPolicy: Codable, Equatable {
  var version = 1
  var disabled = false
  var mixedPort = 7890
  var dnsListenPort = 1053
  var proxyServers: [String] = []
}

enum BootLeakPolicyError: Error, CustomStringConvertible {
  case invalid
  var description: String { "Invalid boot leak policy" }
}

func shouldArmBootLeak(disabled: Bool, coreListening: Bool) -> Bool {
  if disabled { return false }
  return !coreListening
}

private let privateNetworks = [
  "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/24",
  "::1/128", "fc00::/7", "fe80::/10", "ff02::/16"
]

func normalizeProxyIP(_ value: String) -> String? {
  var host = value.trimmingCharacters(in: .whitespacesAndNewlines)
  if host.hasPrefix("[") && host.hasSuffix("]") {
    host = String(host.dropFirst().dropLast())
  }
  var v4 = in_addr(), v6 = in6_addr()
  if host.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 { return host.lowercased() }
  if host.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 { return host.lowercased() }
  return nil
}

func normalizedProxyServers(_ values: [String]) -> [String] {
  var seen = Set<String>()
  var result = [String]()
  for value in values {
    guard let ip = normalizeProxyIP(value), !seen.contains(ip) else { continue }
    seen.insert(ip)
    result.append(ip)
  }
  return result.sorted()
}

func bootLeakRuleSource(policy: BootLeakPolicy) -> String {
  var rules = ""
  rules += "pass quick on lo0 all no state\n"
  rules += "pass out quick from any to { \(privateNetworks.joined(separator: ", ")) } no state\n"
  rules += "pass in quick from { \(privateNetworks.joined(separator: ", ")) } to any no state\n"
  rules += "pass out quick inet proto udp from any port 68 to any port 67 no state\n"
  rules += "pass in quick inet proto udp from any port 67 to any port 68 no state\n"
  rules += "pass out quick inet6 proto udp from any port 546 to any port 547 no state\n"
  rules += "pass in quick inet6 proto udp from any port 547 to any port 546 no state\n"
  rules += "pass quick inet6 proto ipv6-icmp from any to { fe80::/10, ff02::/16 } no state\n"
  rules += "pass in quick inet proto icmp icmp-type unreach no state\n"
  rules += "pass in quick inet6 proto ipv6-icmp icmp6-type { toobig, unreach, paramprob } no state\n"
  for host in normalizedProxyServers(policy.proxyServers) {
    var v4 = in_addr(), v6 = in6_addr()
    if host.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
      rules += "pass out quick from any to \(host) no state\n"
    } else if host.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
      rules += "pass out quick from any to { \(host) } no state\n"
    }
  }
  rules += "block drop quick all label \"ClashPartyBootLeak\"\n"
  return rules
}

func parseBootLeakPolicyData(_ data: Data) throws -> BootLeakPolicy {
  let policy = try JSONDecoder().decode(BootLeakPolicy.self, from: data)
  guard policy.mixedPort > 0 && policy.mixedPort <= 65535 && policy.dnsListenPort > 0 && policy.dnsListenPort <= 65535 else {
    throw BootLeakPolicyError.invalid
  }
  var result = policy
  result.proxyServers = normalizedProxyServers(policy.proxyServers)
  return result
}

func mergedBootLeakPolicy(from files: [(path: String, policy: BootLeakPolicy)]) -> BootLeakPolicy {
  var merged = BootLeakPolicy()
  for entry in files {
  let policy = entry.policy
    if policy.mixedPort > 0 { merged.mixedPort = policy.mixedPort }
    if policy.dnsListenPort > 0 { merged.dnsListenPort = policy.dnsListenPort }
    merged.disabled = merged.disabled || policy.disabled
    if !policy.proxyServers.isEmpty {
      merged.proxyServers = normalizedProxyServers(merged.proxyServers + policy.proxyServers)
    }
  }
  return merged
}

func loopbackListeners(from text: String, ports: Set<UInt16>) -> Bool {
  var pid: Int32?, name: String?
  var hits = Set<UInt16>()
  for line in text.split(whereSeparator: \.isNewline) {
    guard let key = line.first else { continue }
    let value = String(line.dropFirst())
    switch key {
    case "p":
      pid = Int32(value)
      name = nil
    case "n":
      name = value
    default:
      break
    }
    guard let name, pid != nil else { continue }
    guard let close = name.lastIndex(of: ":") else { continue }
    let portText = String(name[name.index(after: close)...])
    guard let port = UInt16(portText), ports.contains(port) else { continue }
    let host = String(name[..<close])
    if host == "127.0.0.1" || host == "*" || host == "::1" || host == "[::1]" { hits.insert(port) }
  }
  return !hits.isEmpty
}

func policySelfTest() throws {
  func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw NSError(domain: "BootLeakPolicy", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
  }
  try require(shouldArmBootLeak(disabled: false, coreListening: false), "arm before core")
  try require(!shouldArmBootLeak(disabled: false, coreListening: true), "disarm when core ready")
  try require(!shouldArmBootLeak(disabled: true, coreListening: false), "respect disable")
  try require(normalizedProxyServers(["210.126.232.127", "210.126.232.127", "domain"]).count == 1, "normalize proxy ips")
  let rules = bootLeakRuleSource(policy: BootLeakPolicy(proxyServers: ["210.126.232.127"]))
  try require(rules.contains("210.126.232.127") && rules.contains("block drop quick all"), "allowlist + deny")
  try require(!bootLeakRuleSource(policy: BootLeakPolicy()).contains("210.126."), "empty proxy list")
  let merged = mergedBootLeakPolicy(from: [
    ("/a", BootLeakPolicy(proxyServers: ["210.126.232.127"])),
    ("/b", BootLeakPolicy(disabled: true))
  ])
  try require(merged.disabled && merged.proxyServers == ["210.126.232.127"], "merged policy")
  try require(
    loopbackListeners(from: "p123\nn127.0.0.1:7890\n", ports: [7890]),
    "mixed port listener"
  )
  try require(
    !loopbackListeners(from: "p123\nn192.0.2.1:7890\n", ports: [7890]),
    "reject non-loopback"
  )
  print("macos-boot-leak-guard-pure-self-test-ok")
}