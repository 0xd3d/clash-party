import Foundation

public protocol RuntimeBridge {
  func start(configPath: String) throws
  func stop() throws
  func reload() throws
  func version() -> String
  func getRuntimeStatus() -> RuntimeStatus
  func getProxies() -> [ProxyGroupSnapshot]
  func selectProxy(group: String, proxy: String) throws
  func getProxyDelay(name: String, url: String, timeoutMilliseconds: Int) throws -> Int
  func getGroupDelays(name: String, url: String, timeoutMilliseconds: Int) throws -> [String: Int]
  func subscribeLogs() -> [RuntimeLogEntry]
  func subscribeTraffic() -> TrafficSnapshot
  func getConnections() -> [ConnectionSnapshot]
  func refreshSnapshotIfNeeded()
  func refreshProxyGroupsSnapshotIfNeeded()
  func refreshDataPlaneSnapshotNow()
  func refreshSnapshotNow()
}

public final class StubMihomoRuntimeBridge: RuntimeBridge {
  private let compatibilityService = CompatibilityService()
  private var timer: DispatchSourceTimer?
  private var totalUp: Int64 = 0
  private var totalDown: Int64 = 0

  public init() {}

  public func start(configPath: String) throws {
    let configurationBundle = try SharedStore.readPublishedConfigurationBundle(
      forRuntimeConfigPath: configPath
    )
    let content = configurationBundle.runtimeConfig
    let input = configurationBundle.input
    let report = compatibilityService.validate(input)
    guard report.isValid else {
      throw RuntimeBridgeError.invalidCompatibility(report.blockingErrors.joined(separator: "\n"))
    }
    let dnsSummary = compatibilityService.parseDnsSummary(from: input.controlledConfigYaml)
    let rules = compatibilityService.extractRules(from: input.profileYaml)
    let resources = compatibilityService.extractResources(
      profileYaml: input.profileYaml,
      controlledConfigYaml: input.controlledConfigYaml,
      overrideYaml: input.overrideYaml
    )

    let mode = content
      .components(separatedBy: .newlines)
      .first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("mode:") })?
      .components(separatedBy: ":")
      .dropFirst()
      .joined(separator: ":")
      .trimmingCharacters(in: .whitespaces) ?? "rule"

    try SharedStore.writeControllerMetadata(ControllerRuntimeMetadata())
    try SharedStore.writeRuntimeStatus(
      RuntimeStatus(
        state: .running,
        mode: mode,
        vpnConnected: true,
        fakeDnsEnabled: dnsSummary.enabled && dnsSummary.enhancedMode == "fake-ip",
        activeProfileId: "default",
        dnsMode: dnsSummary.enhancedMode,
        backend: "stub",
        dataPlaneReady: false,
        startupPhase: "running",
        startupMessage: L10n.string("runtime.phase.running", "Runtime is running.")
      )
    )
    try SharedStore.writeLogs([
      RuntimeLogEntry(
        level: "info",
        message: L10n.format("log.stub.started", "Stub runtime started with config path %@.", configPath)
      ),
      RuntimeLogEntry(
        level: "info",
        message: L10n.string(
          "log.stub.fake_dns_validated",
          "Fake DNS validation passed. Replace the stub with a Mihomo-compatible iOS core."
        )
      ),
      RuntimeLogEntry(
        level: "info",
        message: L10n.format(
          "log.stub.loaded_summary",
          "Loaded %d rules and %d remote resources.",
          rules.count,
          resources.count
        )
      )
    ])
    try SharedStore.writeConnections([
      ConnectionSnapshot(
        host: "connectivitycheck.gstatic.com",
        chain: SharedStore.readProxyGroups().first?.selected ?? "DIRECT",
        rule: rules.first?.type ?? "MATCH"
      )
    ])

    let proxies = SharedStore.readProxyGroups()
    if !proxies.isEmpty {
      try SharedStore.writeProxyGroups(proxies)
    }

    startTrafficTimer()
  }

  public func stop() throws {
    timer?.cancel()
    timer = nil
    try SharedStore.writeControllerMetadata(ControllerRuntimeMetadata())
    let previous = SharedStore.readRuntimeStatus()
    try SharedStore.writeRuntimeStatus(previous.stoppedPreservingDiagnostics(
      message: L10n.string("runtime.phase.idle", "Runtime is idle.")
    ))
    SharedStore.appendLog(
      level: "info",
      message: L10n.string("log.stub.stopped", "Stub runtime stopped.")
    )
  }

  public func reload() throws {
    SharedStore.appendLog(
      level: "info",
      message: L10n.string("log.stub.reload_requested", "Stub runtime reload requested.")
    )
    SharedStore.appendLog(
      level: "debug",
      message: L10n.string(
        "log.stub.reload_preserved",
        "Override and resource definitions are preserved across reload."
      )
    )
  }

  public func version() -> String {
    "stub-mihomo-ios-bridge/0.1.0"
  }

  public func getRuntimeStatus() -> RuntimeStatus {
    SharedStore.readRuntimeStatus()
  }

  public func getProxies() -> [ProxyGroupSnapshot] {
    SharedStore.readProxyGroups()
  }

  public func selectProxy(group: String, proxy: String) throws {
    var groups = SharedStore.readProxyGroups()
    guard let index = groups.firstIndex(where: { $0.name == group }) else {
      throw RuntimeBridgeError.proxyGroupNotFound(group)
    }
    groups[index].selected = proxy
    try SharedStore.writeProxyGroups(groups)

    SharedStore.appendLog(
      level: "info",
      message: L10n.format(
        "log.stub.proxy_selected",
        "Selected proxy '%@' for group '%@'.",
        proxy,
        group
      )
    )
  }

  public func getProxyDelay(name: String, url: String, timeoutMilliseconds: Int) throws -> Int {
    deterministicDelay(for: name)
  }

  public func getGroupDelays(
    name: String,
    url: String,
    timeoutMilliseconds: Int
  ) throws -> [String: Int] {
    guard let group = SharedStore.readProxyGroups().first(where: { $0.name == name }) else {
      throw RuntimeBridgeError.proxyGroupNotFound(name)
    }

    var measurements: [String: Int] = [:]
    for proxyName in group.all {
      measurements[proxyName] = deterministicDelay(for: proxyName)
    }
    return measurements
  }

  public func subscribeLogs() -> [RuntimeLogEntry] {
    SharedStore.readLogs()
  }

  public func subscribeTraffic() -> TrafficSnapshot {
    SharedStore.readTraffic()
  }

  public func getConnections() -> [ConnectionSnapshot] {
    SharedStore.readConnections()
  }

  public func refreshSnapshotIfNeeded() {}

  public func refreshProxyGroupsSnapshotIfNeeded() {}

  public func refreshDataPlaneSnapshotNow() {}

  public func refreshSnapshotNow() {}

  private func startTrafficTimer() {
    timer?.cancel()
    let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
    timer.schedule(deadline: .now(), repeating: 1)
    timer.setEventHandler { [weak self] in
      guard let self else { return }
      self.totalUp += 12_000
      self.totalDown += 48_000
      try? SharedStore.writeTraffic(
        TrafficSnapshot(upBytes: self.totalUp, downBytes: self.totalDown, updatedAt: .now)
      )
    }
    timer.resume()
    self.timer = timer
  }

  private func deterministicDelay(for proxyName: String) -> Int {
    let scalarSum = proxyName.unicodeScalars.reduce(0) { partialResult, scalar in
      partialResult + Int(scalar.value)
    }
    return 40 + (scalarSum % 220)
  }
}

public enum RuntimeBridgeError: LocalizedError {
  case invalidConfigPath
  case invalidCompatibility(String)
  case proxyGroupNotFound(String)
  case proxySelectionNotConfirmed(group: String, requested: String, actual: String?)

  public var errorDescription: String? {
    switch self {
    case .invalidConfigPath:
      return L10n.string("error.runtime.invalid_config_path", "Runtime config path is invalid.")
    case .invalidCompatibility(let message):
      return L10n.format(
        "error.runtime.invalid_compatibility",
        "Compatibility validation failed.\n%@",
        message
      )
    case .proxyGroupNotFound(let group):
      return L10n.format(
        "error.runtime.proxy_group_not_found",
        "Proxy group '%@' was not found.",
        group
      )
    case .proxySelectionNotConfirmed(let group, let requested, let actual):
      let active = actual?.trimmingCharacters(in: .whitespacesAndNewlines)
      if let active, !active.isEmpty {
        return L10n.format(
          "error.runtime.proxy_selection_not_confirmed",
          "The runtime did not confirm '%@' for group '%@'. Active node is '%@'. Try another alive node or run Test All first.",
          requested,
          group,
          active
        )
      }
      return L10n.format(
        "error.runtime.proxy_selection_not_confirmed_missing",
        "The runtime did not confirm '%@' for group '%@'. Refresh the proxy list and try again.",
        requested,
        group
      )
    }
  }
}
