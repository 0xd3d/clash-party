import Foundation

public enum RuntimeConnectionState: String, Codable, CaseIterable, Sendable {
  case idle
  case starting
  case running
  case stopping
  case stopped
  case failed
}

public struct RuntimeStatus: Codable, Equatable, Sendable {
  public var state: RuntimeConnectionState
  public var mode: String
  public var vpnConnected: Bool
  public var fakeDnsEnabled: Bool
  public var activeProfileId: String?
  public var dnsMode: String
  public var backend: String
  public var dataPlaneReady: Bool
  public var startupPhase: String
  public var startupMessage: String
  public var lastFailureReason: String?
  public var lastFailurePhase: String?
  public var lastStopReason: String?
  public var updatedAt: Date

  public init(
    state: RuntimeConnectionState = .idle,
    mode: String = "rule",
    vpnConnected: Bool = false,
    fakeDnsEnabled: Bool = false,
    activeProfileId: String? = nil,
    dnsMode: String = "unknown",
    backend: String = "unknown",
    dataPlaneReady: Bool = false,
    startupPhase: String = "idle",
    startupMessage: String = "",
    lastFailureReason: String? = nil,
    lastFailurePhase: String? = nil,
    lastStopReason: String? = nil,
    updatedAt: Date = .now
  ) {
    self.state = state
    self.mode = mode
    self.vpnConnected = vpnConnected
    self.fakeDnsEnabled = fakeDnsEnabled
    self.activeProfileId = activeProfileId
    self.dnsMode = dnsMode
    self.backend = backend
    self.dataPlaneReady = dataPlaneReady
    self.startupPhase = startupPhase
    self.startupMessage = startupMessage
    self.lastFailureReason = lastFailureReason
    self.lastFailurePhase = lastFailurePhase
    self.lastStopReason = lastStopReason
    self.updatedAt = updatedAt
  }

  enum CodingKeys: String, CodingKey {
    case state
    case mode
    case vpnConnected
    case fakeDnsEnabled
    case activeProfileId
    case dnsMode
    case backend
    case dataPlaneReady
    case startupPhase
    case startupMessage
    case lastFailureReason
    case lastFailurePhase
    case lastStopReason
    case updatedAt
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    state = try container.decodeIfPresent(RuntimeConnectionState.self, forKey: .state) ?? .idle
    mode = try container.decodeIfPresent(String.self, forKey: .mode) ?? "rule"
    vpnConnected = try container.decodeIfPresent(Bool.self, forKey: .vpnConnected) ?? false
    fakeDnsEnabled = try container.decodeIfPresent(Bool.self, forKey: .fakeDnsEnabled) ?? false
    activeProfileId = try container.decodeIfPresent(String.self, forKey: .activeProfileId)
    dnsMode = try container.decodeIfPresent(String.self, forKey: .dnsMode) ?? "unknown"
    backend = try container.decodeIfPresent(String.self, forKey: .backend) ?? "unknown"
    dataPlaneReady = try container.decodeIfPresent(Bool.self, forKey: .dataPlaneReady) ?? false
    startupPhase = try container.decodeIfPresent(String.self, forKey: .startupPhase) ?? "idle"
    startupMessage = try container.decodeIfPresent(String.self, forKey: .startupMessage) ?? ""
    lastFailureReason = try container.decodeIfPresent(String.self, forKey: .lastFailureReason)
    lastFailurePhase = try container.decodeIfPresent(String.self, forKey: .lastFailurePhase)
    lastStopReason = try container.decodeIfPresent(String.self, forKey: .lastStopReason)
    updatedAt = try container.decodeIfPresent(Date.self, forKey: .updatedAt) ?? .now
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(state, forKey: .state)
    try container.encode(mode, forKey: .mode)
    try container.encode(vpnConnected, forKey: .vpnConnected)
    try container.encode(fakeDnsEnabled, forKey: .fakeDnsEnabled)
    try container.encodeIfPresent(activeProfileId, forKey: .activeProfileId)
    try container.encode(dnsMode, forKey: .dnsMode)
    try container.encode(backend, forKey: .backend)
    try container.encode(dataPlaneReady, forKey: .dataPlaneReady)
    try container.encode(startupPhase, forKey: .startupPhase)
    try container.encode(startupMessage, forKey: .startupMessage)
    try container.encodeIfPresent(lastFailureReason, forKey: .lastFailureReason)
    try container.encodeIfPresent(lastFailurePhase, forKey: .lastFailurePhase)
    try container.encodeIfPresent(lastStopReason, forKey: .lastStopReason)
    try container.encode(updatedAt, forKey: .updatedAt)
  }
}

public extension RuntimeStatus {
  func stoppedPreservingDiagnostics(message: String) -> RuntimeStatus {
    var stopped = self
    stopped.state = .stopped
    stopped.vpnConnected = false
    stopped.dataPlaneReady = false
    stopped.startupPhase = "idle"
    stopped.startupMessage = message
    return stopped.updatingTimestampIfNeeded(comparedTo: self)
  }

  var liveTunnelContext: Bool {
    state == .starting
      || state == .running
      || vpnConnected
      || dataPlaneReady
  }

  var startupAcceptedForControllerWarmup: Bool {
    let failureText = lastFailureReason?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard failureText.isEmpty else {
      return false
    }

    let normalizedPhase = startupPhase.trimmingCharacters(in: .whitespacesAndNewlines)
    return normalizedPhase == "warmingProviders" && liveTunnelContext
  }

  var isTerminalTunnelState: Bool {
    switch state {
    case .idle, .running, .stopped, .failed:
      return true
    case .starting, .stopping:
      return false
    }
  }

  func equivalentIgnoringUpdatedAt(to other: RuntimeStatus) -> Bool {
    var lhs = self
    var rhs = other
    lhs.updatedAt = .distantPast
    rhs.updatedAt = .distantPast
    return lhs == rhs
  }

  func updatingTimestampIfNeeded(comparedTo previous: RuntimeStatus) -> RuntimeStatus {
    guard !equivalentIgnoringUpdatedAt(to: previous) else {
      return previous
    }

    var updated = self
    updated.updatedAt = .now
    return updated
  }
}

// Keep the persisted descriptions compatible with existing diagnostic files.
public enum TunnelStopReason: String, CaseIterable, Sendable {
  case none = "Stopped without a specific provider stop reason."
  case userInitiated = "Stopped by the user."
  case providerFailed = "Packet Tunnel provider failed."
  case noNetworkAvailable = "No network was available for the tunnel."
  case unrecoverableNetworkChange = "An unrecoverable network change forced the tunnel to stop."
  case providerDisabled = "The Packet Tunnel provider was disabled."
  case internalError = "The Packet Tunnel provider hit an internal error."
  case authenticationCanceled = "Authentication was canceled."
  case configurationFailed = "Tunnel configuration failed."
  case idleTimeout = "The tunnel stopped after hitting the idle timeout."
  case configurationDisabled = "The VPN configuration was disabled in iOS settings."
  case configurationRemoved = "The VPN configuration was removed from iOS."
  case superseded = "The tunnel was superseded by another VPN configuration."
  case userLogout = "The current user logged out."
  case userSwitch = "The active user changed."
  case connectionFailed = "The system reported that the VPN connection failed."
  case sleep = "The device went to sleep."
  case appUpdate = "The provider stopped because the app was updated."

  public var logLevel: String {
    switch self {
    case .providerFailed, .internalError, .configurationFailed, .connectionFailed:
      return "error"
    case .none, .noNetworkAvailable, .unrecoverableNetworkChange:
      return "warning"
    case .userInitiated, .providerDisabled, .authenticationCanceled, .idleTimeout,
         .configurationDisabled, .configurationRemoved, .superseded, .userLogout,
         .userSwitch, .sleep, .appUpdate:
      return "info"
    }
  }
}

public struct TunnelStatusDiagnostic: Equatable, Sendable {
  public let level: String
  public let message: String

  public static func make(
    statusText: String,
    isInactive: Bool,
    runtimeStatus: RuntimeStatus,
    isInitialObservation: Bool
  ) -> TunnelStatusDiagnostic {
    let prefix = "System VPN status observed as \(statusText)."
    guard isInactive else {
      return TunnelStatusDiagnostic(level: "info", message: prefix)
    }

    let failure = nonEmpty(runtimeStatus.lastFailureReason)
    if runtimeStatus.state == .starting && failure == nil {
      return TunnelStatusDiagnostic(
        level: "info",
        message: prefix + " Startup request is still within the app-side grace period."
      )
    }

    let stopReason = nonEmpty(runtimeStatus.lastStopReason)
    if isInitialObservation,
       runtimeStatus.state == .idle || runtimeStatus.state == .stopped,
       stopReason == nil, failure == nil {
      return TunnelStatusDiagnostic(level: "info", message: prefix + " Initial inactive VPN observation.")
    }

    let phase = nonEmpty(runtimeStatus.startupPhase) ?? "n/a"
    let summary = stopReason ?? failure ?? (
      runtimeStatus.state == .failed
        ? "The runtime reported a failure without a persisted failure detail."
        : "No provider stop reason or failure reason was persisted before the tunnel stopped. Cause is unknown."
    )
    var message = prefix + " Last phase: \(phase). Last detail: \(summary)"
    if let failure, failure != stopReason, stopReason != nil {
      message += " Last failure: \(failure)"
    }
    if failure != nil, let failurePhase = nonEmpty(runtimeStatus.lastFailurePhase) {
      message += " Last failure phase: \(failurePhase)."
    }

    let level: String
    if failure != nil || runtimeStatus.state == .failed {
      level = "error"
    } else {
      level = stopReason.flatMap(TunnelStopReason.init(rawValue:))?.logLevel ?? "warning"
    }
    return TunnelStatusDiagnostic(level: level, message: message)
  }

  private static func nonEmpty(_ value: String?) -> String? {
    guard let text = value?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty else {
      return nil
    }
    return text
  }
}

public struct AppActivityLease: Codable, Equatable, Sendable {
  public var isActive: Bool
  public var updatedAt: Date
  public init(isActive: Bool, updatedAt: Date = .now) { self.isActive = isActive; self.updatedAt = updatedAt }
  public func isFresh(at now: Date = .now) -> Bool {
    isActive && (0...35).contains(now.timeIntervalSince(updatedAt))
  }
}

public enum PacketTunnelPollingPolicy {
  public static func interval(ready: Bool, foreground: Bool, recentTraffic: Bool) -> TimeInterval {
    if !ready { return 0.75 }
    if foreground { return 2 }
    return recentTraffic ? 5 : 30
  }
}

public struct NetworkPathSnapshot: Codable, Equatable, Sendable {
  public var status: String
  public var interfaces: [String]
  public var expensive: Bool
  public var constrained: Bool
  public var supportsIPv4: Bool
  public var supportsIPv6: Bool
  public var updatedAt: Date
  public init(status: String, interfaces: [String], expensive: Bool, constrained: Bool,
    supportsIPv4: Bool, supportsIPv6: Bool, updatedAt: Date = .now) {
    self.status = status; self.interfaces = interfaces; self.expensive = expensive; self.constrained = constrained
    self.supportsIPv4 = supportsIPv4; self.supportsIPv6 = supportsIPv6; self.updatedAt = updatedAt
  }
}

public struct TunnelExtensionSnapshot: Codable, Equatable, Sendable {
  public var runtimeStatus: RuntimeStatus
  public var startupPhase: String
  public var startupMessage: String
  public var lastFailureReason: String?
  public var lastFailurePhase: String?
  public var lastStopReason: String?
  public var controllerAddress: String?
  public var phaseUpdatedAt: Date
  public var running: Bool
  public var networkPath: NetworkPathSnapshot?
  public var packetFlowStatistics: [String: UInt64]?

  public init(
    runtimeStatus: RuntimeStatus = .init(),
    startupPhase: String = "idle",
    startupMessage: String = "",
    lastFailureReason: String? = nil,
    lastFailurePhase: String? = nil,
    lastStopReason: String? = nil,
    controllerAddress: String? = nil,
    phaseUpdatedAt: Date = .now,
    running: Bool = false,
    networkPath: NetworkPathSnapshot? = nil,
    packetFlowStatistics: [String: UInt64]? = nil
  ) {
    self.runtimeStatus = runtimeStatus
    self.startupPhase = startupPhase
    self.startupMessage = startupMessage
    self.lastFailureReason = lastFailureReason
    self.lastFailurePhase = lastFailurePhase
    self.lastStopReason = lastStopReason
    self.controllerAddress = controllerAddress
    self.phaseUpdatedAt = phaseUpdatedAt
    self.running = running
    self.networkPath = networkPath
    self.packetFlowStatistics = packetFlowStatistics
  }
}

public extension TunnelExtensionSnapshot {
  var startupAcceptedForAppOperations: Bool {
    let controllerIsPublished = !(controllerAddress?
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .isEmpty ?? true)
    let liveTunnelContext = running || runtimeStatus.liveTunnelContext
    return running
      || runtimeStatus.startupAcceptedForControllerWarmup
      || (controllerIsPublished && liveTunnelContext)
  }

  var canAuthoritativelyReconcileProxyPreferences: Bool {
    let controllerIsPublished = !(controllerAddress?
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .isEmpty ?? true)
    guard controllerIsPublished else {
      return false
    }

    if running {
      return true
    }

    return runtimeStatus.state == .running
      && runtimeStatus.vpnConnected
  }
}

public struct ControllerRuntimeMetadata: Codable, Equatable, Sendable {
  public var baseURLString: String
  public var listenAddress: String
  public var secret: String
  public var version: String
  public var active: Bool
  public var updatedAt: Date

  public init(
    baseURLString: String = "",
    listenAddress: String = "",
    secret: String = "",
    version: String = "",
    active: Bool = false,
    updatedAt: Date = .now
  ) {
    self.baseURLString = baseURLString
    self.listenAddress = listenAddress
    self.secret = secret
    self.version = version
    self.active = active
    self.updatedAt = updatedAt
  }

  public var baseURL: URL? {
    URL(string: baseURLString)
  }

  public func equivalentIgnoringUpdatedAt(to other: ControllerRuntimeMetadata) -> Bool {
    var lhs = self
    var rhs = other
    lhs.updatedAt = .distantPast
    rhs.updatedAt = .distantPast
    return lhs == rhs
  }
}

public struct ProxyGroupSnapshot: Codable, Identifiable, Equatable, Sendable {
  public let name: String
  public var selected: String?
  public var all: [String]
  public var displayOptions: [String]
  public var type: String?
  public var testURL: String?

  public var id: String { name }

  enum CodingKeys: String, CodingKey {
    case name
    case selected
    case all
    case displayOptions
    case type
    case testURL
  }

  public init(
    name: String,
    selected: String? = nil,
    all: [String] = [],
    displayOptions: [String]? = nil,
    type: String? = nil,
    testURL: String? = nil
  ) {
    self.name = name
    self.selected = selected
    self.all = all
    self.displayOptions = displayOptions ?? ProxyNameNormalizer.uniqueDisplayOptions(from: all)
    self.type = type
    self.testURL = testURL
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    name = try container.decode(String.self, forKey: .name)
    selected = try container.decodeIfPresent(String.self, forKey: .selected)
    all = try container.decodeIfPresent([String].self, forKey: .all) ?? []
    displayOptions = try container.decodeIfPresent([String].self, forKey: .displayOptions)
      ?? ProxyNameNormalizer.uniqueDisplayOptions(from: all)
    type = try container.decodeIfPresent(String.self, forKey: .type)
    testURL = try container.decodeIfPresent(String.self, forKey: .testURL)
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(name, forKey: .name)
    try container.encodeIfPresent(selected, forKey: .selected)
    try container.encode(all, forKey: .all)
    try container.encode(displayOptions, forKey: .displayOptions)
    try container.encodeIfPresent(type, forKey: .type)
    try container.encodeIfPresent(testURL, forKey: .testURL)
  }

  public func normalizedForDisplay() -> ProxyGroupSnapshot {
    var normalized = self
    let optionSource = all.isEmpty ? displayOptions : all
    normalized.displayOptions = ProxyNameNormalizer.uniqueDisplayOptions(from: optionSource)
    if normalized.all.isEmpty {
      normalized.all = normalized.displayOptions
    }
    return normalized
  }

  public var supportsManualSelection: Bool {
    let normalizedType = type?
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .lowercased() ?? ""
    if normalizedType.isEmpty {
      return true
    }
    return normalizedType == "selector"
      || normalizedType == "select"
      || normalizedType == "url-test"
      || normalizedType == "urltest"
      || normalizedType == "fallback"
  }

  public var needsRuntimeHydration: Bool {
    all.isEmpty && displayOptions.isEmpty
  }
}

public enum ProxyNameNormalizer {
  public static func uniqueDisplayOptions(from names: [String]) -> [String] {
    var seen = Set<String>()
    return names.compactMap { rawName in
      let normalizedName = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !normalizedName.isEmpty else { return nil }
      guard seen.insert(normalizedName).inserted else { return nil }
      return normalizedName
    }
  }
}

public struct RuntimeConnectionSnapshot: Codable, Equatable, Sendable {
  public var connections: [ConnectionSnapshot]
  public var uploadTotal: Int64
  public var downloadTotal: Int64
  public var updatedAt: Date

  public init(
    connections: [ConnectionSnapshot] = [],
    uploadTotal: Int64 = 0,
    downloadTotal: Int64 = 0,
    updatedAt: Date = .now
  ) {
    self.connections = connections
    self.uploadTotal = uploadTotal
    self.downloadTotal = downloadTotal
    self.updatedAt = updatedAt
  }

  public var traffic: TrafficSnapshot {
    TrafficSnapshot(
      upBytes: uploadTotal,
      downBytes: downloadTotal,
      updatedAt: updatedAt
    )
  }
}

public struct TrafficSnapshot: Codable, Equatable, Sendable {
  public var upBytes: Int64
  public var downBytes: Int64
  public var updatedAt: Date

  public init(upBytes: Int64 = 0, downBytes: Int64 = 0, updatedAt: Date = .now) {
    self.upBytes = upBytes
    self.downBytes = downBytes
    self.updatedAt = updatedAt
  }

  public func equivalentIgnoringUpdatedAt(to other: TrafficSnapshot) -> Bool {
    var lhs = self
    var rhs = other
    lhs.updatedAt = .distantPast
    rhs.updatedAt = .distantPast
    return lhs == rhs
  }
}

public struct RuntimeLogEntry: Codable, Identifiable, Equatable, Sendable {
  public let id: String
  public var level: String
  public var message: String
  public var timestamp: Date

  public init(
    id: String = UUID().uuidString,
    level: String,
    message: String,
    timestamp: Date = .now
  ) {
    self.id = id
    self.level = level
    self.message = message
    self.timestamp = timestamp
  }
}

public struct ConnectionSnapshot: Codable, Identifiable, Equatable, Sendable {
  public struct Metadata: Codable, Equatable, Sendable {
    public var network: String
    public var type: String
    public var sourceIP: String
    public var sourcePort: Int?
    public var destinationIP: String
    public var destinationPort: Int?
    public var destinationIPASN: String
    public var host: String
    public var sniffHost: String

    public init(
      network: String = "",
      type: String = "",
      sourceIP: String = "",
      sourcePort: Int? = nil,
      destinationIP: String = "",
      destinationPort: Int? = nil,
      destinationIPASN: String = "",
      host: String = "",
      sniffHost: String = ""
    ) {
      self.network = network
      self.type = type
      self.sourceIP = sourceIP
      self.sourcePort = sourcePort
      self.destinationIP = destinationIP
      self.destinationPort = destinationPort
      self.destinationIPASN = destinationIPASN
      self.host = host
      self.sniffHost = sniffHost
    }

    enum CodingKeys: String, CodingKey {
      case network
      case type
      case sourceIP
      case sourcePort
      case destinationIP
      case destinationPort
      case destinationIPASN
      case host
      case sniffHost
    }

    public init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      network = try container.decodeIfPresent(String.self, forKey: .network) ?? ""
      type = try container.decodeIfPresent(String.self, forKey: .type) ?? ""
      sourceIP = try container.decodeIfPresent(String.self, forKey: .sourceIP) ?? ""
      sourcePort = try container.decodeIfPresent(Int.self, forKey: .sourcePort)
      destinationIP = try container.decodeIfPresent(String.self, forKey: .destinationIP) ?? ""
      destinationPort = try container.decodeIfPresent(Int.self, forKey: .destinationPort)
      destinationIPASN = try container.decodeIfPresent(String.self, forKey: .destinationIPASN) ?? ""
      host = try container.decodeIfPresent(String.self, forKey: .host) ?? ""
      sniffHost = try container.decodeIfPresent(String.self, forKey: .sniffHost) ?? ""
    }
  }

  public let id: String
  public var host: String
  public var chain: String
  public var chainComponents: [String]
  public var rule: String
  public var rulePayload: String
  public var metadata: Metadata
  public var upload: Int64
  public var download: Int64

  enum CodingKeys: String, CodingKey {
    case id
    case host
    case chain
    case chainComponents
    case rule
    case rulePayload
    case metadata
    case upload
    case download
  }

  public init(
    id: String = UUID().uuidString,
    host: String,
    chain: String,
    chainComponents: [String]? = nil,
    rule: String,
    rulePayload: String = "",
    metadata: Metadata = .init(),
    upload: Int64 = 0,
    download: Int64 = 0
  ) {
    self.id = id
    self.host = host
    self.chain = chain
    self.chainComponents = chainComponents ?? Self.normalizedChainComponents(from: chain)
    self.rule = rule
    self.rulePayload = rulePayload
    self.metadata = metadata
    self.upload = upload
    self.download = download
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    id = try container.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
    let decodedHost = try container.decodeIfPresent(String.self, forKey: .host) ?? ""
    host = decodedHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      ? "Pending route"
      : decodedHost
    chain = try container.decodeIfPresent(String.self, forKey: .chain) ?? "DIRECT"
    chainComponents = try container.decodeIfPresent([String].self, forKey: .chainComponents)
      ?? Self.normalizedChainComponents(from: chain)
    rule = try container.decodeIfPresent(String.self, forKey: .rule) ?? "MATCH"
    rulePayload = try container.decodeIfPresent(String.self, forKey: .rulePayload) ?? ""
    metadata = try container.decodeIfPresent(Metadata.self, forKey: .metadata) ?? .init()
    upload = try container.decodeIfPresent(Int64.self, forKey: .upload) ?? 0
    download = try container.decodeIfPresent(Int64.self, forKey: .download) ?? 0
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(id, forKey: .id)
    try container.encode(host, forKey: .host)
    try container.encode(chain, forKey: .chain)
    try container.encode(chainComponents, forKey: .chainComponents)
    try container.encode(rule, forKey: .rule)
    try container.encode(rulePayload, forKey: .rulePayload)
    try container.encode(metadata, forKey: .metadata)
    try container.encode(upload, forKey: .upload)
    try container.encode(download, forKey: .download)
  }

  private static func normalizedChainComponents(from chain: String) -> [String] {
    chain
      .components(separatedBy: " -> ")
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .filter { !$0.isEmpty }
  }
}

public struct RouteDecisionSnapshot: Codable, Identifiable, Equatable, Sendable {
  public let id: String
  public var network: String
  public var source: String
  public var host: String
  public var sniffHost: String
  public var destinationIP: String
  public var destinationPort: Int?
  public var destinationIPASN: String
  public var matchedRule: String
  public var matchedRulePayload: String
  public var matchedRuleKind: String
  public var selectedProxy: String
  public var chainComponents: [String]
  public var finalNode: String
  public var dnsMode: String
  public var outcome: String
  public var upload: Int64
  public var download: Int64
  public var createdAt: String

  enum CodingKeys: String, CodingKey {
    case id
    case network
    case source
    case host
    case sniffHost
    case destinationIP
    case destinationPort
    case destinationIPASN
    case matchedRule
    case matchedRulePayload
    case matchedRuleKind
    case selectedProxy
    case chainComponents
    case finalNode
    case dnsMode
    case outcome
    case upload
    case download
    case createdAt
  }

  public init(
    id: String,
    network: String = "",
    source: String = "",
    host: String,
    sniffHost: String = "",
    destinationIP: String = "",
    destinationPort: Int? = nil,
    destinationIPASN: String = "",
    matchedRule: String = "MATCH",
    matchedRulePayload: String = "",
    matchedRuleKind: String = "",
    selectedProxy: String = "",
    chainComponents: [String] = [],
    finalNode: String = "",
    dnsMode: String = "",
    outcome: String = "",
    upload: Int64 = 0,
    download: Int64 = 0,
    createdAt: String = ""
  ) {
    self.id = id
    self.network = network
    self.source = source
    self.host = host
    self.sniffHost = sniffHost
    self.destinationIP = destinationIP
    self.destinationPort = destinationPort
    self.destinationIPASN = destinationIPASN
    self.matchedRule = matchedRule
    self.matchedRulePayload = matchedRulePayload
    self.matchedRuleKind = matchedRuleKind
    self.selectedProxy = selectedProxy
    self.chainComponents = chainComponents
    self.finalNode = finalNode
    self.dnsMode = dnsMode
    self.outcome = outcome
    self.upload = upload
    self.download = download
    self.createdAt = createdAt
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    id = try container.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
    network = try container.decodeIfPresent(String.self, forKey: .network) ?? ""
    source = try container.decodeIfPresent(String.self, forKey: .source) ?? ""
    host = try container.decodeIfPresent(String.self, forKey: .host) ?? "Pending route"
    sniffHost = try container.decodeIfPresent(String.self, forKey: .sniffHost) ?? ""
    destinationIP = try container.decodeIfPresent(String.self, forKey: .destinationIP) ?? ""
    destinationPort = try container.decodeIfPresent(Int.self, forKey: .destinationPort)
    destinationIPASN = try container.decodeIfPresent(String.self, forKey: .destinationIPASN) ?? ""
    matchedRule = try container.decodeIfPresent(String.self, forKey: .matchedRule) ?? "MATCH"
    matchedRulePayload = try container.decodeIfPresent(String.self, forKey: .matchedRulePayload) ?? ""
    matchedRuleKind = try container.decodeIfPresent(String.self, forKey: .matchedRuleKind) ?? ""
    selectedProxy = try container.decodeIfPresent(String.self, forKey: .selectedProxy) ?? ""
    chainComponents = try container.decodeIfPresent([String].self, forKey: .chainComponents) ?? []
    finalNode = try container.decodeIfPresent(String.self, forKey: .finalNode) ?? ""
    dnsMode = try container.decodeIfPresent(String.self, forKey: .dnsMode) ?? ""
    outcome = try container.decodeIfPresent(String.self, forKey: .outcome) ?? ""
    upload = try container.decodeIfPresent(Int64.self, forKey: .upload) ?? 0
    download = try container.decodeIfPresent(Int64.self, forKey: .download) ?? 0
    createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt) ?? ""
  }
}

public struct RouteExplanation: Codable, Identifiable, Equatable, Sendable {
  public enum Outcome: String, Codable, Equatable, Sendable {
    case ruleHit
    case direct
    case unknown
  }

  public enum RuleKind: String, Codable, Equatable, Sendable {
    case domain
    case domainSuffix
    case domainKeyword
    case geoSite
    case geoIP
    case ipASN
    case ipCIDR
    case ipCIDR6
    case match
    case final
    case script
    case process
    case network
    case unknown
  }

  public enum DNSContext: String, Codable, Equatable, Sendable {
    case fakeIPMapped
    case sniffedDomain
    case metadataDomain
    case ipOnly
    case unknown
  }

  public struct ChainStep: Codable, Identifiable, Equatable, Sendable {
    public var position: Int
    public var name: String
    public var role: String

    public var id: String { "\(position)-\(name)-\(role)" }

    public init(position: Int, name: String, role: String) {
      self.position = position
      self.name = name
      self.role = role
    }
  }

  public let id: String
  public var host: String
  public var matchedRule: String
  public var matchedRulePayload: String
  public var matchedRuleKind: RuleKind
  public var chainComponents: [String]
  public var chainSteps: [ChainStep]
  public var finalNode: String
  public var outcome: Outcome
  public var dnsContext: DNSContext
  public var destinationIP: String
  public var destinationIPASN: String
  public var destinationPort: Int?
  public var summary: String
  public var matchedRuleDisplay: String
  public var chainDisplay: String
  public var chainStepDisplay: String
  public var destinationDisplay: String
  public var upload: Int64
  public var download: Int64

  enum CodingKeys: String, CodingKey {
    case id
    case host
    case matchedRule
    case matchedRulePayload
    case matchedRuleKind
    case chainComponents
    case chainSteps
    case finalNode
    case outcome
    case dnsContext
    case destinationIP
    case destinationIPASN
    case destinationPort
    case summary
    case matchedRuleDisplay
    case chainDisplay
    case chainStepDisplay
    case destinationDisplay
    case upload
    case download
  }

  public init(
    id: String,
    host: String,
    matchedRule: String,
    matchedRulePayload: String = "",
    matchedRuleKind: RuleKind = .unknown,
    chainComponents: [String],
    chainSteps: [ChainStep] = [],
    finalNode: String,
    outcome: Outcome,
    dnsContext: DNSContext = .unknown,
    destinationIP: String = "",
    destinationIPASN: String = "",
    destinationPort: Int? = nil,
    summary: String = "",
    matchedRuleDisplay: String = "",
    chainDisplay: String = "",
    chainStepDisplay: String = "",
    destinationDisplay: String = "",
    upload: Int64,
    download: Int64
  ) {
    self.id = id
    self.host = host
    self.matchedRule = matchedRule
    self.matchedRulePayload = matchedRulePayload
    self.matchedRuleKind = matchedRuleKind
    self.chainComponents = chainComponents
    self.chainSteps = chainSteps
    self.finalNode = finalNode
    self.outcome = outcome
    self.dnsContext = dnsContext
    self.destinationIP = destinationIP
    self.destinationIPASN = destinationIPASN
    self.destinationPort = destinationPort
    self.summary = summary
    self.matchedRuleDisplay = matchedRuleDisplay
    self.chainDisplay = chainDisplay
    self.chainStepDisplay = chainStepDisplay
    self.destinationDisplay = destinationDisplay
    self.upload = upload
    self.download = download
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    id = try container.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
    host = Self.nonEmpty(
      try container.decodeIfPresent(String.self, forKey: .host),
      fallback: "Pending route"
    )
    matchedRule = Self.nonEmpty(
      try container.decodeIfPresent(String.self, forKey: .matchedRule),
      fallback: "MATCH"
    )
    matchedRulePayload = try container.decodeIfPresent(String.self, forKey: .matchedRulePayload) ?? ""
    matchedRuleKind = Self.decodeEnum(
      RouteExplanation.RuleKind.self,
      from: container,
      forKey: .matchedRuleKind,
      fallback: .unknown
    )
    chainComponents = try container.decodeIfPresent([String].self, forKey: .chainComponents) ?? []
    chainSteps = try container.decodeIfPresent([ChainStep].self, forKey: .chainSteps) ?? []
    finalNode = Self.nonEmpty(
      try container.decodeIfPresent(String.self, forKey: .finalNode),
      fallback: chainComponents.reversed().first { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        ?? "DIRECT"
    )
    outcome = Self.decodeEnum(
      RouteExplanation.Outcome.self,
      from: container,
      forKey: .outcome,
      fallback: finalNode.caseInsensitiveCompare("DIRECT") == .orderedSame ? .direct : .unknown
    )
    dnsContext = Self.decodeDNSContext(from: container, forKey: .dnsContext)
    destinationIP = try container.decodeIfPresent(String.self, forKey: .destinationIP) ?? ""
    destinationIPASN = try container.decodeIfPresent(String.self, forKey: .destinationIPASN) ?? ""
    destinationPort = try container.decodeIfPresent(Int.self, forKey: .destinationPort)
    matchedRuleDisplay = Self.nonEmpty(
      try container.decodeIfPresent(String.self, forKey: .matchedRuleDisplay),
      fallback: matchedRulePayload.isEmpty ? matchedRule : "\(matchedRule) · \(matchedRulePayload)"
    )
    chainDisplay = Self.nonEmpty(
      try container.decodeIfPresent(String.self, forKey: .chainDisplay),
      fallback: chainComponents.isEmpty ? "None" : chainComponents.joined(separator: " -> ")
    )
    chainStepDisplay = Self.nonEmpty(
      try container.decodeIfPresent(String.self, forKey: .chainStepDisplay),
      fallback: chainSteps.isEmpty
        ? (chainComponents.isEmpty ? "None" : chainComponents.joined(separator: " -> "))
        : chainSteps.map { "\($0.position). \($0.role): \($0.name)" }.joined(separator: "  ")
    )
    destinationDisplay = Self.nonEmpty(
      try container.decodeIfPresent(String.self, forKey: .destinationDisplay),
      fallback: Self.destinationText(ip: destinationIP, port: destinationPort)
    )
    summary = Self.nonEmpty(
      try container.decodeIfPresent(String.self, forKey: .summary),
      fallback: "Recovered a cached route explanation for \(host)."
    )
    upload = try container.decodeIfPresent(Int64.self, forKey: .upload) ?? 0
    download = try container.decodeIfPresent(Int64.self, forKey: .download) ?? 0
  }

  private static func nonEmpty(_ value: String?, fallback: String) -> String {
    let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return trimmed.isEmpty || trimmed.lowercased() == "unknown" ? fallback : trimmed
  }

  private static func decodeEnum<T: RawRepresentable & Decodable>(
    _ type: T.Type,
    from container: KeyedDecodingContainer<CodingKeys>,
    forKey key: CodingKeys,
    fallback: T
  ) -> T where T.RawValue == String {
    guard let rawValue = try? container.decodeIfPresent(String.self, forKey: key),
          let value = T(rawValue: rawValue) else {
      return fallback
    }
    return value
  }

  private static func decodeDNSContext(
    from container: KeyedDecodingContainer<CodingKeys>,
    forKey key: CodingKeys
  ) -> RouteExplanation.DNSContext {
    guard let rawValue = try? container.decodeIfPresent(String.self, forKey: key) else {
      return .unknown
    }
    if rawValue == "resolvedDomain" {
      return .metadataDomain
    }
    return RouteExplanation.DNSContext(rawValue: rawValue) ?? .unknown
  }

  private static func destinationText(ip: String, port: Int?) -> String {
    let normalizedIP = ip.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalizedIP.isEmpty else { return "" }
    guard let port else { return normalizedIP }
    return "\(normalizedIP):\(port)"
  }
}

public enum RouteExplanationResolver {
  public static func explain(_ decision: RouteDecisionSnapshot) -> RouteExplanation {
    let host = firstNonEmpty([
      decision.host,
      decision.sniffHost,
      destinationText(ip: decision.destinationIP, port: decision.destinationPort)
    ]) ?? "Pending route"
    let matchedRule = normalized(decision.matchedRule, fallback: "MATCH")
    let matchedRulePayload = normalized(decision.matchedRulePayload, fallback: "")
    let matchedRuleKind = ruleKind(from: firstNonEmpty([decision.matchedRuleKind, matchedRule]) ?? matchedRule)
    let chainComponents = normalizedChainComponents(decision.chainComponents)
    let finalNode = normalized(
      decision.finalNode,
      fallback: chainComponents.first { !isDirect($0) && !isUnknownPlaceholder($0) }
        ?? chainComponents.first
        ?? normalized(decision.selectedProxy, fallback: "Pending route")
    )
    let outcome = RouteExplanation.Outcome(rawValue: decision.outcome)
      ?? routeOutcome(matchedRule: matchedRule, finalNode: finalNode, chainComponents: chainComponents)
    let dnsContext = dnsContext(fromRouteDecisionDNSMode: decision.dnsMode, decision: decision)
    let chainSteps = chainComponents.enumerated().map { index, component in
      RouteExplanation.ChainStep(
        position: index + 1,
        name: component,
        role: chainRole(
          for: component,
          at: index,
          totalCount: chainComponents.count,
          outcome: outcome
        )
      )
    }
    let summary = summaryText(
      host: host,
      matchedRule: matchedRule,
      matchedRulePayload: matchedRulePayload,
      matchedRuleKind: matchedRuleKind,
      finalNode: finalNode,
      outcome: outcome,
      dnsContext: dnsContext,
      chainComponents: chainComponents
    )
    let destinationDisplay = destinationText(
      ip: decision.destinationIP,
      port: decision.destinationPort
    )

    return RouteExplanation(
      id: decision.id,
      host: host,
      matchedRule: matchedRule,
      matchedRulePayload: matchedRulePayload,
      matchedRuleKind: matchedRuleKind,
      chainComponents: chainComponents,
      chainSteps: chainSteps,
      finalNode: finalNode,
      outcome: outcome,
      dnsContext: dnsContext,
      destinationIP: decision.destinationIP,
      destinationIPASN: decision.destinationIPASN,
      destinationPort: decision.destinationPort,
      summary: summary,
      matchedRuleDisplay: matchedRuleDisplay(rule: matchedRule, payload: matchedRulePayload),
      chainDisplay: displayText(for: chainComponents, fallback: "None"),
      chainStepDisplay: chainStepDisplay(chainSteps),
      destinationDisplay: destinationDisplay,
      upload: decision.upload,
      download: decision.download
    )
  }

  public static func explain(_ decisions: [RouteDecisionSnapshot]) -> [RouteExplanation] {
    decisions.map(explain)
  }

  public static func explain(
    _ connection: ConnectionSnapshot,
    fakeDnsEnabled: Bool = false,
    fakeIPRange: String = ""
  ) -> RouteExplanation {
    let host = firstNonEmpty([
      connection.host,
      connection.metadata.sniffHost,
      connection.metadata.host,
      destinationText(ip: connection.metadata.destinationIP, port: connection.metadata.destinationPort)
    ]) ?? "Pending route"
    let matchedRule = normalized(connection.rule, fallback: "MATCH")
    let matchedRulePayload = normalized(connection.rulePayload, fallback: "")
    let matchedRuleKind = ruleKind(from: matchedRule)
    let reportedChainComponents = connection.chainComponents.isEmpty
      ? connection.chain
        .components(separatedBy: " -> ")
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
      : connection.chainComponents
    let chainComponents = reportedChainComponents.filter { !isUnknownPlaceholder($0) }

    let finalNode = chainComponents.first { !isDirect($0) && !isUnknownPlaceholder($0) }
      ?? chainComponents.first
      ?? "Pending route"
    let outcome = routeOutcome(matchedRule: matchedRule, finalNode: finalNode, chainComponents: chainComponents)
    let dnsContext = resolveDNSContext(
      connection: connection,
      fakeDnsEnabled: fakeDnsEnabled,
      fakeIPRange: fakeIPRange
    )
    let chainSteps = chainComponents.enumerated().map { index, component in
      RouteExplanation.ChainStep(
        position: index + 1,
        name: component,
        role: chainRole(
          for: component,
          at: index,
          totalCount: chainComponents.count,
          outcome: outcome
        )
      )
    }
    let summary = summaryText(
      host: host,
      matchedRule: matchedRule,
      matchedRulePayload: matchedRulePayload,
      matchedRuleKind: matchedRuleKind,
      finalNode: finalNode,
      outcome: outcome,
      dnsContext: dnsContext,
      chainComponents: chainComponents
    )
    let destinationDisplay = destinationText(
      ip: connection.metadata.destinationIP,
      port: connection.metadata.destinationPort
    )

    return RouteExplanation(
      id: connection.id,
      host: host,
      matchedRule: matchedRule,
      matchedRulePayload: matchedRulePayload,
      matchedRuleKind: matchedRuleKind,
      chainComponents: chainComponents,
      chainSteps: chainSteps,
      finalNode: finalNode,
      outcome: outcome,
      dnsContext: dnsContext,
      destinationIP: connection.metadata.destinationIP,
      destinationIPASN: connection.metadata.destinationIPASN,
      destinationPort: connection.metadata.destinationPort,
      summary: summary,
      matchedRuleDisplay: matchedRuleDisplay(rule: matchedRule, payload: matchedRulePayload),
      chainDisplay: displayText(for: chainComponents, fallback: "None"),
      chainStepDisplay: chainStepDisplay(chainSteps),
      destinationDisplay: destinationDisplay,
      upload: connection.upload,
      download: connection.download
    )
  }

  public static func explain(
    _ connections: [ConnectionSnapshot],
    fakeDnsEnabled: Bool = false,
    fakeIPRange: String = ""
  ) -> [RouteExplanation] {
    connections.map {
      explain($0, fakeDnsEnabled: fakeDnsEnabled, fakeIPRange: fakeIPRange)
    }
  }

  public static func proxiedCount(in explanations: [RouteExplanation]) -> Int {
    explanations.filter { $0.outcome == .ruleHit }.count
  }

  private static func routeOutcome(
    matchedRule: String,
    finalNode: String,
    chainComponents: [String]
  ) -> RouteExplanation.Outcome {
    if chainComponents.isEmpty || isPendingRoute(finalNode) {
      return .unknown
    }

    if isDirect(finalNode) || chainComponents.allSatisfy(isDirect) {
      return .direct
    }

    if !matchedRule.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      return .ruleHit
    }

    return .unknown
  }

  private static func isPendingRoute(_ value: String) -> Bool {
    value.trimmingCharacters(in: .whitespacesAndNewlines).caseInsensitiveCompare("Pending route") == .orderedSame
  }

  private static func ruleKind(from rule: String) -> RouteExplanation.RuleKind {
    let token = rule
      .split(separator: ",", maxSplits: 1, omittingEmptySubsequences: true)
      .first
      .map(String.init) ?? rule
    let normalizedToken = token
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .replacingOccurrences(of: "-", with: "")
      .replacingOccurrences(of: "_", with: "")
      .lowercased()

    switch normalizedToken {
    case "domain":
      return .domain
    case "domainsuffix":
      return .domainSuffix
    case "domainkeyword":
      return .domainKeyword
    case "geosite":
      return .geoSite
    case "geoip":
      return .geoIP
    case "ipasn", "asn":
      return .ipASN
    case "ipcidr":
      return .ipCIDR
    case "ipcidr6":
      return .ipCIDR6
    case "match":
      return .match
    case "final":
      return .final
    case "script":
      return .script
    case "process", "processname":
      return .process
    case "network":
      return .network
    default:
      return normalizedToken.isEmpty ? .unknown : .unknown
    }
  }

  private static func normalizedChainComponents(_ components: [String]) -> [String] {
    var seen = Set<String>()
    return components.compactMap { rawComponent in
      let component = rawComponent.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !component.isEmpty, !isUnknownPlaceholder(component) else { return nil }
      guard seen.insert(component.lowercased()).inserted else { return nil }
      return component
    }
  }

  private static func dnsContext(
    fromRouteDecisionDNSMode dnsMode: String,
    decision: RouteDecisionSnapshot
  ) -> RouteExplanation.DNSContext {
    let normalizedMode = dnsMode
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .replacingOccurrences(of: "_", with: "-")
      .lowercased()

    if !decision.sniffHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      return .sniffedDomain
    }

    switch normalizedMode {
    case "fake-ip":
      return .fakeIPMapped
    case "redir-host", "hosts":
      return .metadataDomain
    case "normal":
      return decision.destinationIP.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        ? .metadataDomain
        : .ipOnly
    default:
      return decision.destinationIP.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        ? .unknown
        : .ipOnly
    }
  }

  private static func resolveDNSContext(
    connection: ConnectionSnapshot,
    fakeDnsEnabled: Bool,
    fakeIPRange: String
  ) -> RouteExplanation.DNSContext {
    let host = normalized(connection.host, fallback: "")
    let sniffHost = normalized(connection.metadata.sniffHost, fallback: "")
    let metadataHost = normalized(connection.metadata.host, fallback: "")
    let destinationIP = normalized(connection.metadata.destinationIP, fallback: "")

    if fakeDnsEnabled,
       !host.isEmpty,
       !destinationIP.isEmpty,
       host != destinationIP,
       containsIP(destinationIP, inCIDR: fakeIPRange) {
      return .fakeIPMapped
    }
    if !sniffHost.isEmpty {
      return .sniffedDomain
    }
    if !host.isEmpty, !destinationIP.isEmpty, host != destinationIP {
      return .metadataDomain
    }
    if isIPAddress(host) || isIPAddress(destinationIP) {
      return .ipOnly
    }
    if !metadataHost.isEmpty {
      return .metadataDomain
    }
    return .unknown
  }

  private static func chainRole(
    for component: String,
    at index: Int,
    totalCount: Int,
    outcome: RouteExplanation.Outcome
  ) -> String {
    if outcome == .direct || isDirect(component) {
      return "DIRECT"
    }
    if index == 0 {
      return totalCount == 1 ? "Node" : "Final Node"
    }
    if index == totalCount - 1 {
      return "Matched Group"
    }
    return "Proxy Group"
  }

  private static func matchedRuleDisplay(rule: String, payload: String) -> String {
    payload.isEmpty ? rule : "\(rule) · \(payload)"
  }

  private static func displayText(for values: [String], fallback: String) -> String {
    values.isEmpty ? fallback : values.joined(separator: " -> ")
  }

  private static func chainStepDisplay(_ steps: [RouteExplanation.ChainStep]) -> String {
    guard !steps.isEmpty else { return "None" }
    return steps
      .map { "\($0.position). \($0.role): \($0.name)" }
      .joined(separator: "  ")
  }

  private static func destinationText(ip: String, port: Int?) -> String {
    let normalizedIP = ip.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalizedIP.isEmpty else { return "" }
    guard let port else { return normalizedIP }
    return "\(normalizedIP):\(port)"
  }

  private static func summaryText(
    host: String,
    matchedRule: String,
    matchedRulePayload: String,
    matchedRuleKind: RouteExplanation.RuleKind,
    finalNode: String,
    outcome: RouteExplanation.Outcome,
    dnsContext: RouteExplanation.DNSContext,
    chainComponents: [String]
  ) -> String {
    switch outcome {
    case .ruleHit:
      let ruleLabel = matchedRulePayload.isEmpty
        ? matchedRule
        : "\(matchedRule) \(matchedRulePayload)"
      let dnsLabel = dnsContextLabel(dnsContext)
      let chainLabel = chainComponents.isEmpty ? "no reported chain" : chainComponents.joined(separator: " -> ")
      return "Matched \(ruleLabel) as \(ruleKindLabel(matchedRuleKind)); \(dnsLabel); followed \(chainLabel) and selected \(finalNode)."
    case .direct:
      return "Matched \(matchedRule) and used DIRECT without a proxy node."
    case .unknown:
      let dnsLabel = dnsContextLabel(dnsContext)
      return "The controller reported \(host), but the route chain is incomplete; \(dnsLabel)."
    }
  }

  private static func ruleKindLabel(_ kind: RouteExplanation.RuleKind) -> String {
    switch kind {
    case .domain:
      return "domain"
    case .domainSuffix:
      return "domain-suffix"
    case .domainKeyword:
      return "domain-keyword"
    case .geoSite:
      return "geosite"
    case .geoIP:
      return "geoip"
    case .ipASN:
      return "ip-asn"
    case .ipCIDR:
      return "ip-cidr"
    case .ipCIDR6:
      return "ip-cidr6"
    case .match:
      return "match"
    case .final:
      return "final"
    case .script:
      return "script"
    case .process:
      return "process"
    case .network:
      return "network"
    case .unknown:
      return "reported rule"
    }
  }

  private static func dnsContextLabel(_ context: RouteExplanation.DNSContext) -> String {
    switch context {
    case .fakeIPMapped:
      return "Fake DNS mapped the configured fake-IP range back to the domain"
    case .sniffedDomain:
      return "the TCP sniffer recovered the domain from buffered client metadata"
    case .metadataDomain:
      return "controller metadata already carried a routable domain"
    case .ipOnly:
      return "only IP metadata was available"
    case .unknown:
      return "DNS context was not reported"
    }
  }

  private static func normalized(_ value: String, fallback: String) -> String {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty || trimmed.lowercased() == "unknown" ? fallback : trimmed
  }

  private static func firstNonEmpty(_ values: [String]) -> String? {
    values
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .first { !$0.isEmpty && !isUnknownPlaceholder($0) }
  }

  private static func isUnknownPlaceholder(_ value: String) -> Bool {
    value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "unknown"
  }

  private static func isIPAddress(_ value: String) -> Bool {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return false }
    return trimmed.allSatisfy { character in
      character.isNumber || character == "." || character == ":"
    }
  }

  private static func containsIP(_ ip: String, inCIDR cidr: String) -> Bool {
    let normalizedCIDR = cidr.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalizedCIDR.isEmpty else { return false }

    let parts = normalizedCIDR.split(separator: "/", maxSplits: 1).map(String.init)
    guard let baseAddress = parts.first,
          let ipValue = ipv4Value(ip),
          let baseValue = ipv4Value(baseAddress) else {
      return false
    }

    guard parts.count == 2 else {
      return ipValue == baseValue
    }
    guard let prefixLength = Int(parts[1]), (0...32).contains(prefixLength) else {
      return false
    }

    let mask: UInt32 = prefixLength == 0 ? 0 : UInt32.max << UInt32(32 - prefixLength)
    return (ipValue & mask) == (baseValue & mask)
  }

  private static func ipv4Value(_ rawValue: String) -> UInt32? {
    let octets = rawValue
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .split(separator: ".")
    guard octets.count == 4 else { return nil }

    var value: UInt32 = 0
    for octet in octets {
      guard let part = UInt32(octet), part <= 255 else {
        return nil
      }
      value = (value << 8) | part
    }
    return value
  }

  private static func isDirect(_ value: String) -> Bool {
    value
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .caseInsensitiveCompare("DIRECT") == .orderedSame
  }
}

public enum ProxySummaryResolver {
  public static func activeProxySummary(
    proxyGroups: [ProxyGroupSnapshot],
    connections: [ConnectionSnapshot]
  ) -> String? {
    if let selectedLeaf = selectedProxyGroupLeaf(from: proxyGroups) {
      return selectedLeaf
    }

    return proxiedConnectionLeaf(from: connections)
  }

  private static func selectedProxyGroupLeaf(from proxyGroups: [ProxyGroupSnapshot]) -> String? {
    let groupsWithSelection = proxyGroups.filter { group in
      guard let selected = group.selected?.trimmingCharacters(in: .whitespacesAndNewlines) else {
        return false
      }
      return !selected.isEmpty
    }
    guard !groupsWithSelection.isEmpty else { return nil }

    let groupsByName = proxyGroups.reduce(into: [String: ProxyGroupSnapshot]()) { result, group in
      result[group.name] = group
    }
    let resolvedLeaves = groupsWithSelection
      .sorted { lhs, rhs in
        let lhsPriority = proxySummaryPriority(for: lhs)
        let rhsPriority = proxySummaryPriority(for: rhs)
        if lhsPriority != rhsPriority {
          return lhsPriority < rhsPriority
        }
        return lhs.name.localizedCompare(rhs.name) == .orderedAscending
      }
      .compactMap { group in
        resolvedLeafProxyName(fromGroupName: group.name, groupsByName: groupsByName)
      }

    return resolvedLeaves.first { !isDirect($0) } ?? resolvedLeaves.first
  }

  private static func proxiedConnectionLeaf(from connections: [ConnectionSnapshot]) -> String? {
    for connection in connections {
      let components = connection.chainComponents.isEmpty
        ? connection.chain
          .components(separatedBy: " -> ")
          .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
          .filter { !$0.isEmpty }
        : connection.chainComponents
      guard let firstComponent = components.first, !isDirect(firstComponent) else {
        continue
      }
      return firstComponent
    }
    return nil
  }

  private static func proxySummaryPriority(for group: ProxyGroupSnapshot) -> Int {
    let normalized = group.name.lowercased()
    if normalized == "global" || normalized == "proxy" {
      return 0
    }
    if normalized.contains("节点选择") || normalized.contains("proxy") || normalized.contains("select") {
      return 1
    }
    return 2
  }

  private static func resolvedLeafProxyName(
    fromGroupName groupName: String,
    groupsByName: [String: ProxyGroupSnapshot],
    visited: Set<String> = []
  ) -> String? {
    let normalizedGroupName = normalizedGroupReference(groupName, groupsByName: groupsByName)
    guard !normalizedGroupName.isEmpty else { return nil }
    guard !visited.contains(normalizedGroupName) else { return normalizedGroupName }
    guard let group = groupsByName[normalizedGroupName] else { return normalizedGroupName }
    guard let selected = group.selected?.trimmingCharacters(in: .whitespacesAndNewlines),
          !selected.isEmpty else {
      return group.name
    }

    let normalizedSelection = normalizedGroupReference(selected, groupsByName: groupsByName)
    guard groupsByName[normalizedSelection] != nil else {
      return normalizedSelection
    }

    var nextVisited = visited
    nextVisited.insert(normalizedGroupName)
    return resolvedLeafProxyName(
      fromGroupName: normalizedSelection,
      groupsByName: groupsByName,
      visited: nextVisited
    )
  }

  private static func normalizedGroupReference(
    _ rawValue: String,
    groupsByName: [String: ProxyGroupSnapshot]
  ) -> String {
    let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return trimmed }
    if groupsByName[trimmed] != nil {
      return trimmed
    }

    let wrapperCharacters = CharacterSet(charactersIn: "<>[](){} ")
    let unwrapped = trimmed.trimmingCharacters(in: wrapperCharacters)
    if groupsByName[unwrapped] != nil {
      return unwrapped
    }

    return trimmed
  }

  private static func isDirect(_ value: String) -> Bool {
    value
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .caseInsensitiveCompare("DIRECT") == .orderedSame
  }
}

public struct TunnelNetworkSettingsReply: Codable, Sendable {
  public var error: String?
  public init(error: String? = nil) { self.error = error }
}

// Independent extension-owned journal. It never takes the shared status/log
// file lock, and its heartbeat does not depend on Go FFI or controller HTTP.
public struct TunnelHealthRecord: Codable, Equatable {
  public var sessionID: String
  public var processID: Int32
  public var startedAt: Date
  public var heartbeatAt: Date
  public var eventAt: Date
  public var event: String
  public var phase: String
  public var physFootprintBytes: UInt64?
  public var peakPhysFootprintBytes: UInt64?
  public var residentBytes: UInt64?
  public var stopReason: String?

  public init(processID: Int32, now: Date = .now) {
    sessionID = UUID().uuidString
    self.processID = processID
    startedAt = now
    heartbeatAt = now
    eventAt = now
    event = "startRequested"
    phase = "starting"
  }
}

public struct TunnelHealthStore {
  public let directoryURL: URL
  public init(directoryURL: URL) { self.directoryURL = directoryURL }
  private func url(previous: Bool) -> URL {
    directoryURL.appendingPathComponent(previous ? "previous-tunnel-health.json" : "tunnel-health.json")
  }
  public func read(previous: Bool = false) -> TunnelHealthRecord? {
    let path = url(previous: previous)
    guard let attributes = try? FileManager.default.attributesOfItem(atPath: path.path),
          let size = attributes[.size] as? NSNumber, size.intValue <= 64 * 1024,
          let data = try? Data(contentsOf: path) else { return nil }
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    return try? decoder.decode(TunnelHealthRecord.self, from: data)
  }
  public func begin(processID: Int32, now: Date = .now) throws -> TunnelHealthRecord {
    if let last = read() { try write(last, previous: true) }
    let record = TunnelHealthRecord(processID: processID, now: now)
    try write(record)
    return record
  }
  public func write(_ record: TunnelHealthRecord, previous: Bool = false) throws {
    try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.sortedKeys]
    try encoder.encode(record).write(to: url(previous: previous), options: [.atomic])
  }
}

public enum TunnelDisconnectErrorSummary {
  // Record only domain/code. Never serialize arbitrary userInfo, URLs or tokens.
  public static func describe(_ error: NSError) -> String {
    var parts: [String] = []
    var current: NSError? = error
    for _ in 0..<4 {
      guard let item = current else { break }
      parts.append("\(item.domain.prefix(120))/\(item.code)")
      current = item.userInfo[NSUnderlyingErrorKey] as? NSError
    }
    return parts.joined(separator: " -> ")
  }
}
