import Foundation

public struct CompatibilityInput: Codable, Equatable, Sendable {
  public var profileYaml: String
  public var controlledConfigYaml: String
  public var appConfigJson: String
  public var overrideYaml: String
  public var overrideJavaScript: String

  public init(
    profileYaml: String,
    controlledConfigYaml: String,
    appConfigJson: String,
    overrideYaml: String = "",
    overrideJavaScript: String = ""
  ) {
    self.profileYaml = profileYaml
    self.controlledConfigYaml = controlledConfigYaml
    self.appConfigJson = appConfigJson
    self.overrideYaml = overrideYaml
    self.overrideJavaScript = overrideJavaScript
  }
}

public struct CompatibilityValidationReport: Codable, Equatable, Sendable {
  public var blockingErrors: [String]
  public var warnings: [String]
  public var preservedButInactiveFields: [String]

  public init(
    blockingErrors: [String] = [],
    warnings: [String] = [],
    preservedButInactiveFields: [String] = []
  ) {
    self.blockingErrors = blockingErrors
    self.warnings = warnings
    self.preservedButInactiveFields = preservedButInactiveFields
  }

  public var isValid: Bool {
    blockingErrors.isEmpty
  }
}

public struct DnsSummary: Codable, Equatable {
  public var enabled: Bool
  public var enhancedMode: String
  public var fakeIPRange: String
  public var fakeIPFilter: [String]
  public var nameservers: [String]
  public var proxyServerNameservers: [String]
  public var directNameservers: [String]
  public var fallbackServers: [String]
  public var nameserverPolicyKeys: [String]

  public init(
    enabled: Bool = false,
    enhancedMode: String = "unknown",
    fakeIPRange: String = "",
    fakeIPFilter: [String] = [],
    nameservers: [String] = [],
    proxyServerNameservers: [String] = [],
    directNameservers: [String] = [],
    fallbackServers: [String] = [],
    nameserverPolicyKeys: [String] = []
  ) {
    self.enabled = enabled
    self.enhancedMode = enhancedMode
    self.fakeIPRange = fakeIPRange
    self.fakeIPFilter = fakeIPFilter
    self.nameservers = nameservers
    self.proxyServerNameservers = proxyServerNameservers
    self.directNameservers = directNameservers
    self.fallbackServers = fallbackServers
    self.nameserverPolicyKeys = nameserverPolicyKeys
  }
}

public struct ProfileBundleRecord: Codable, Identifiable, Equatable, Sendable {
  public let id: String
  public var name: String
  public var input: CompatibilityInput
  public var remoteSource: String?
  public var createdAt: Date
  public var updatedAt: Date

  public init(
    id: String = UUID().uuidString,
    name: String,
    input: CompatibilityInput,
    remoteSource: String? = nil,
    createdAt: Date = .now,
    updatedAt: Date = .now
  ) {
    self.id = id
    self.name = name
    self.input = input
    self.remoteSource = remoteSource
    self.createdAt = createdAt
    self.updatedAt = updatedAt
  }
}

public extension ProfileBundleRecord {
  func matchesActiveWorkspace(
    input activeInput: CompatibilityInput,
    remoteSource activeRemoteSource: String?,
    activeProfileID: String?
  ) -> Bool {
    if let activeProfileID, activeProfileID == id {
      return true
    }

    if let recordRemoteSource = Self.normalizedRemoteImportSource(remoteSource),
       let activeRemoteSource = Self.normalizedRemoteImportSource(activeRemoteSource),
       recordRemoteSource == activeRemoteSource {
      return true
    }

    return input == activeInput
  }

  static func recordForRemoteImport(
    remoteSource: String,
    input: CompatibilityInput,
    existingRecords: [ProfileBundleRecord],
    fallbackName: String? = nil,
    now: Date = .now
  ) -> ProfileBundleRecord {
    let normalizedRemoteSource = normalizedRemoteImportSource(remoteSource) ?? remoteSource
      .trimmingCharacters(in: .whitespacesAndNewlines)
    let existingRecord = existingRecords.first {
      normalizedRemoteImportSource($0.remoteSource) == normalizedRemoteSource
    }
    let normalizedFallbackName = fallbackName?
      .trimmingCharacters(in: .whitespacesAndNewlines)
    let resolvedName = existingRecord?.name
      ?? (
        normalizedFallbackName?.isEmpty == false
          ? normalizedFallbackName!
          : suggestedRemoteImportName(from: normalizedRemoteSource)
      )

    return ProfileBundleRecord(
      id: existingRecord?.id ?? UUID().uuidString,
      name: resolvedName,
      input: input,
      remoteSource: normalizedRemoteSource,
      createdAt: existingRecord?.createdAt ?? now,
      updatedAt: now
    )
  }

  static func suggestedRemoteImportName(from remoteSource: String) -> String {
    let normalizedRemoteSource = normalizedRemoteImportSource(remoteSource)
      ?? remoteSource.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let url = URL(string: normalizedRemoteSource) else {
      return normalizedRemoteSource
    }

    let lastPathComponent = url.lastPathComponent
      .removingPercentEncoding?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if !lastPathComponent.isEmpty {
      return lastPathComponent
    }

    let host = url.host?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if !host.isEmpty {
      return host
    }

    return normalizedRemoteSource
  }

  private static func normalizedRemoteImportSource(_ value: String?) -> String? {
    let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return trimmed.isEmpty ? nil : trimmed
  }
}

public struct BackupRecord: Codable, Identifiable, Equatable, Sendable {
  public let id: String
  public var name: String
  public var input: CompatibilityInput
  public var runtimeStatus: RuntimeStatus
  public var createdAt: Date

  public init(
    id: String = UUID().uuidString,
    name: String,
    input: CompatibilityInput,
    runtimeStatus: RuntimeStatus,
    createdAt: Date = .now
  ) {
    self.id = id
    self.name = name
    self.input = input
    self.runtimeStatus = runtimeStatus
    self.createdAt = createdAt
  }
}

public struct RuleMatchRecord: Codable, Identifiable, Equatable {
  public let id: String
  public var type: String
  public var payload: String
  public var target: String
  public var raw: String

  public init(type: String, payload: String, target: String, raw: String) {
    self.id = raw
    self.type = type
    self.payload = payload
    self.target = target
    self.raw = raw
  }
}

public struct ResourceRecord: Codable, Identifiable, Equatable {
  public let id: String
  public var name: String
  public var kind: String
  public var behavior: String
  public var source: String
  public var path: String
  public var interval: String
  public var localStatus: String
  public var localSize: Int64?
  public var updatedAt: Date?
  public var lastError: String?

  public init(
    name: String,
    kind: String,
    behavior: String = "",
    source: String = "",
    path: String = "",
    interval: String = "",
    localStatus: String = "",
    localSize: Int64? = nil,
    updatedAt: Date? = nil,
    lastError: String? = nil
  ) {
    self.id = "\(kind):\(name)"
    self.name = name
    self.kind = kind
    self.behavior = behavior
    self.source = source
    self.path = path
    self.interval = interval
    self.localStatus = localStatus
    self.localSize = localSize
    self.updatedAt = updatedAt
    self.lastError = lastError
  }
}

public struct ProxyNodeRecord: Codable, Identifiable, Equatable {
  public let id: String
  public var name: String
  public var type: String
  public var server: String
  public var port: String
  public var network: String
  public var security: String
  public var udp: Bool
  public var tls: Bool

  public init(
    id: String? = nil,
    name: String,
    type: String = "",
    server: String = "",
    port: String = "",
    network: String = "",
    security: String = "",
    udp: Bool = false,
    tls: Bool = false
  ) {
    self.id = id ?? name
    self.name = name
    self.type = type
    self.server = server
    self.port = port
    self.network = network
    self.security = security
    self.udp = udp
    self.tls = tls
  }
}

public struct TunSummary: Codable, Equatable {
  public var enabled: Bool
  public var stack: String
  public var autoRoute: Bool
  public var autoDetectInterface: Bool
  public var dnsHijack: [String]
  public var inet4Addresses: [String]
  public var inet6Addresses: [String]
  public var ipv6Enabled: Bool
  public var mtu: Int?
  public var effectiveMTU: Int { (mtu == nil || mtu == 0) ? 1500 : mtu! }
  public var effectiveStack: String { ["system", "gvisor", ""].contains(stack.lowercased()) ? "lwIP" : stack }

  public init(
    enabled: Bool = false,
    stack: String = "system",
    autoRoute: Bool = false,
    autoDetectInterface: Bool = false,
    dnsHijack: [String] = [],
    inet4Addresses: [String] = [],
    inet6Addresses: [String] = [],
    ipv6Enabled: Bool = true,
    mtu: Int? = nil
  ) {
    self.enabled = enabled
    self.stack = stack
    self.autoRoute = autoRoute
    self.autoDetectInterface = autoDetectInterface
    self.dnsHijack = dnsHijack
    self.inet4Addresses = inet4Addresses
    self.inet6Addresses = inet6Addresses
    self.ipv6Enabled = ipv6Enabled
    self.mtu = mtu
  }
}

public struct PacketTunnelNetworkPlan: Codable, Equatable {
  public var tunnelRemoteAddress: String
  public var ipv4Address: String
  public var ipv4SubnetMask: String
  public var dnsServers: [String]
  public var ipv6Address: String?
  public var ipv6PrefixLength: Int?
  public var mtu: Int?
  public var effectiveMTU: Int { mtu ?? 1500 }

  public init(
    tunnelRemoteAddress: String = "172.31.255.2",
    ipv4Address: String = "172.31.255.1",
    ipv4SubnetMask: String = "255.255.255.252",
    dnsServers: [String] = ["172.31.255.2", "fdfe:dcba:9876::2"],
    ipv6Address: String? = "fdfe:dcba:9876::1",
    ipv6PrefixLength: Int? = 126,
    mtu: Int? = 1500
  ) {
    self.tunnelRemoteAddress = tunnelRemoteAddress
    self.ipv4Address = ipv4Address
    self.ipv4SubnetMask = ipv4SubnetMask
    self.dnsServers = dnsServers
    self.ipv6Address = ipv6Address
    self.ipv6PrefixLength = ipv6PrefixLength
    self.mtu = mtu
  }
}

public struct MihomoSummary: Codable, Equatable {
  public var mode: String
  public var mixedPort: String
  public var socksPort: String
  public var redirPort: String
  public var tproxyPort: String
  public var allowLan: Bool
  public var logLevel: String

  public init(
    mode: String = "rule",
    mixedPort: String = "",
    socksPort: String = "",
    redirPort: String = "",
    tproxyPort: String = "",
    allowLan: Bool = false,
    logLevel: String = "info"
  ) {
    self.mode = mode
    self.mixedPort = mixedPort
    self.socksPort = socksPort
    self.redirPort = redirPort
    self.tproxyPort = tproxyPort
    self.allowLan = allowLan
    self.logLevel = logLevel
  }
}

public struct SubStoreSummary: Codable, Equatable {
  public var enabled: Bool
  public var remoteURL: String
  public var artifact: String
  public var syncIntervalMinutes: Int
  public var lastProbeMessage: String

  public init(
    enabled: Bool = false,
    remoteURL: String = "",
    artifact: String = "",
    syncIntervalMinutes: Int = 0,
    lastProbeMessage: String = L10n.string("substore.probe.idle", "Not probed")
  ) {
    self.enabled = enabled
    self.remoteURL = remoteURL
    self.artifact = artifact
    self.syncIntervalMinutes = syncIntervalMinutes
    self.lastProbeMessage = lastProbeMessage
  }
}

public struct DelayTestSettings: Codable, Equatable {
  public var url: String
  public var timeoutMilliseconds: Int

  public init(url: String = "", timeoutMilliseconds: Int = 5_000) {
    self.url = url
    self.timeoutMilliseconds = timeoutMilliseconds
  }
}
