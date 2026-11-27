import Foundation

/// Hosts that must finish (or the app must quit) before disconnecting VPN to avoid a direct-network leak window.
public enum DisconnectSensitiveTrafficGuard {
  public static let sensitiveSuffixes: [String] = [
    "claude.ai",
    "claude.app",
    "claude.com",
    "claudeusercontent.com",
    "anthropic.com",
    "openai.com",
    "chatgpt.com",
    "oaiusercontent.com",
    "oaistatic.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "youtube.com",
    "youtu.be",
    "googlevideo.com",
    "ytimg.com",
    "gmail.com",
    "googleusercontent.com",
    "github.com",
    "githubusercontent.com",
    "cursor.sh",
    "cursor.com"
  ]

  public static func effectiveHostname(for connection: ConnectionSnapshot) -> String {
    let sniff = connection.metadata.sniffHost.trimmingCharacters(in: .whitespacesAndNewlines)
    if !sniff.isEmpty, sniff.caseInsensitiveCompare("Pending route") != .orderedSame { return sniff.lowercased() }
    let host = connection.host.trimmingCharacters(in: .whitespacesAndNewlines)
    if !host.isEmpty, host.caseInsensitiveCompare("Pending route") != .orderedSame { return host.lowercased() }
    return ""
  }

  public static func matchesSensitiveHost(_ hostname: String) -> Bool {
    let host = hostname.lowercased()
    guard !host.isEmpty else { return false }
    return sensitiveSuffixes.contains { suffix in
      host == suffix || host.hasSuffix(".\(suffix)")
    }
  }

  public static func activeSensitiveHostnames(in connections: [ConnectionSnapshot]) -> [String] {
    var seen = Set<String>()
    var ordered: [String] = []
    for connection in connections {
      let host = effectiveHostname(for: connection)
      guard matchesSensitiveHost(host), seen.insert(host).inserted else { continue }
      ordered.append(host)
    }
    return ordered.sorted()
  }

  /// Refreshes the controller-backed connection list from the app process and returns active sensitive hosts, if any.
  public static func activeSensitiveHostnamesAfterRefresh() -> [String] {
    let bridge = RuntimeBridgeFactory.makeAppBridge()
    bridge.refreshDataPlaneSnapshotNow()
    return activeSensitiveHostnames(in: bridge.getConnections())
  }
}