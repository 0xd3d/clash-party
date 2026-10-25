import Foundation

public enum RuntimeBridgeRole {
  case app
  case packetTunnel
}

public enum RuntimeBridgeFactory {
  public static func makeAppBridge() -> RuntimeBridge {
    MihomoRuntimeBridge(role: .app)
  }

  public static func makePacketTunnelBridge() -> RuntimeBridge {
    MihomoRuntimeBridge(role: .packetTunnel)
  }
}

enum MihomoRuntimeBridgeError: LocalizedError {
  case appCannotOwnCoreLifecycle
  case controllerUnavailable

  var errorDescription: String? {
    switch self {
    case .appCannotOwnCoreLifecycle:
      return L10n.string(
        "error.runtime.app_cannot_control_core",
        "The app process cannot own the embedded core lifecycle. Start or stop the runtime through PacketTunnelProvider."
      )
    case .controllerUnavailable:
      return L10n.string(
        "error.runtime.controller_unavailable",
        "The embedded controller is unavailable. Wait for VPN startup to finish and try again."
      )
    }
  }
}

final class MihomoRuntimeBridge: RuntimeBridge {
  private let role: RuntimeBridgeRole
  private let fallback = StubMihomoRuntimeBridge()
  private let compatibilityService = CompatibilityService()
  private let observerQueue = DispatchQueue(label: "org.mihomo.party.ios.runtime-observer")
  private let controllerRequestQueue = DispatchQueue(
    label: "org.mihomo.party.ios.controller-requests",
    qos: .userInitiated,
    attributes: .concurrent
  )
  private let fileManager = FileManager.default
  private let connectionObservationLogLimit = 12
  private let persistedRouteExplanationLimit = 80
  private let slowSnapshotInFlightLock = NSLock()

  private var refreshTimer: DispatchSourceTimer?
  private var packetPollingGeneration = UUID()
  private var lastPacketTunnelPollAt: Date?
  private var lastPacketTrafficTotal: UInt64 = 0
  private var lastPacketTrafficAt: Date?
  private var logTask: URLSessionWebSocketTask?
  private var trafficTask: URLSessionWebSocketTask?
  private var lastSnapshotPollingSummary: String?
  private var lastSnapshotPollingLogAt: Date?
  private var lastSnapshotPollingError: String?
  private var lastFetchedControllerVersionAt: Date?
  private var lastFastRuntimeStatusRefreshAt: Date?
  private var lastSlowSnapshotRefreshAt: Date?
  private var lastKnownProxyGroupCount: Int = 0
  private var lastRouteExplanationConnectionSignature: String?
  private var slowSnapshotInFlight = false

  init(role: RuntimeBridgeRole) {
    self.role = role
  }

  func start(configPath: String) throws {
    guard role == .packetTunnel else {
      throw MihomoRuntimeBridgeError.appCannotOwnCoreLifecycle
    }

    appendLog(level: "info", message: "Mihomo runtime bridge start requested by Packet Tunnel.")
    let configurationBundle = try SharedStore.readPublishedConfigurationBundle(
      forRuntimeConfigPath: configPath
    )
    let input = configurationBundle.input
    let report = compatibilityService.validate(input)
    guard report.isValid else {
      throw RuntimeBridgeError.invalidCompatibility(report.blockingErrors.joined(separator: "\n"))
    }
    appendLog(level: "info", message: "Compatibility validation passed for the embedded runtime startup.")
    appendLog(
      level: "debug",
      message: "Packet Tunnel is booting configuration bundle generation \(configurationBundle.generation)."
    )
    let seedSummary = try GeoResourceManager.seedBundledResourcesIfNeeded(
      from: configurationBundle.runtimeConfig
    )
    if seedSummary.preparedCount > 0 {
      appendLog(
        level: "info",
        message: "Prepared \(seedSummary.preparedCount) bundled route database(s) before starting the embedded core."
      )
    }
    if !seedSummary.failedMessages.isEmpty {
      appendLog(
        level: "warning",
        message: "Some bundled route databases were not ready before core startup: \(seedSummary.failedMessages.joined(separator: " "))"
      )
    }

    if !MihomoCoreFFI.isAvailable {
      try fallback.start(configPath: configPath)
      appendLog(
        level: "warning",
        message: L10n.string(
          "log.runtime.stub_fallback",
          "Embedded MihomoMobile xcframework is not linked. Packet tunnel is running in stub fallback mode."
        )
      )
      return
    }

    let dnsSummary = compatibilityService.parseDnsSummary(from: input.controlledConfigYaml)
    let runtimeStatus = RuntimeStatus(
      state: .starting,
      mode: compatibilityService.parseMihomoSummary(from: input.controlledConfigYaml).mode,
      vpnConnected: false,
      fakeDnsEnabled: dnsSummary.enabled && dnsSummary.enhancedMode == "fake-ip",
      activeProfileId: "default",
      dnsMode: dnsSummary.enhancedMode,
      backend: "embedded-mihomo",
      dataPlaneReady: false,
      startupPhase: MihomoCoreFFI.startupPhase(),
      startupMessage: MihomoCoreFFI.startupMessage()
    )
    try SharedStore.writeRuntimeStatus(runtimeStatus)
    appendLog(level: "debug", message: "Initial runtime status written before calling the embedded core.")

    let controllerAddress = suggestedControllerAddress()
    let controllerSecret = UUID().uuidString.replacingOccurrences(of: "-", with: "")
    let metadata = ControllerRuntimeMetadata(
      baseURLString: "",
      listenAddress: controllerAddress,
      secret: controllerSecret,
      version: "",
      active: false
    )
    try SharedStore.writeControllerMetadata(metadata)
    if role == .packetTunnel {
      appendLog(
        level: "info",
        message: "Packet Tunnel requested an embedded controller endpoint so the app can switch proxies after startup."
      )
    } else {
      appendLog(
        level: "debug",
        message: "Prepared controller metadata with requested address \(metadata.listenAddress). Calling MihomoStart."
      )
    }

    let homeURL = try SharedStore.runtimeHomeURL()
    appendLog(level: "info", message: "Invoking MihomoStart through the Swift FFI layer.")
    try MihomoCoreFFI.start(
      configPath: configPath,
      homeDirectory: homeURL.path,
      controllerAddress: controllerAddress,
      controllerSecret: metadata.secret
    )
    appendLog(level: "info", message: "MihomoStart returned control to the Swift runtime bridge.")

    var activatedMetadata: ControllerRuntimeMetadata?
    var startedMetadata = metadata
    let actualAddress = MihomoCoreFFI.controllerAddress() ?? metadata.listenAddress
    startedMetadata.listenAddress = actualAddress
    startedMetadata.baseURLString = "http://\(actualAddress)"
    startedMetadata.version = MihomoCoreFFI.version()
    startedMetadata.active = true
    startedMetadata.updatedAt = .now
    try SharedStore.writeControllerMetadata(startedMetadata)
    activatedMetadata = startedMetadata
    appendLog(
      level: "debug",
      message: "Controller metadata activated with address \(startedMetadata.baseURLString)."
    )

    appendLog(
      level: "info",
      message: L10n.string("log.runtime.core_started", "Embedded Mihomo core started.")
    )
    let activeMetadata = SharedStore.readControllerMetadata()
    appendLog(
      level: "info",
      message: L10n.format(
        "log.runtime.controller_listening",
        "Controller listening at %@.",
        activeMetadata.baseURLString
      )
    )

    if role == .packetTunnel {
      appendLog(
        level: "info",
        message: "Packet Tunnel started lightweight controller snapshot polling so background browser traffic keeps route diagnostics fresh without attaching long-lived log streams."
      )
      scheduleInitialControllerWarmup()
      startPacketTunnelFastSnapshotPolling()
      return
    }

    appendLog(level: "debug", message: "Starting controller observers and warmup after Mihomo core startup.")
    if let activatedMetadata {
      startObservers(with: activatedMetadata)
    }
    scheduleInitialControllerWarmup()
  }

  func stop() throws {
    stopObservers()

    if role == .packetTunnel, MihomoCoreFFI.isAvailable {
      try MihomoCoreFFI.stop()
      try SharedStore.writeControllerMetadata(ControllerRuntimeMetadata())
      let previous = SharedStore.readRuntimeStatus()
      try SharedStore.writeRuntimeStatus(previous.stoppedPreservingDiagnostics(
        message: L10n.string("runtime.phase.idle", "Runtime is idle.")
      ))
      return
    }

    try fallback.stop()
  }

  func reload() throws {
    let configurationBundle = try SharedStore.readPublishedConfigurationBundle()
    _ = try GeoResourceManager.seedBundledResourcesIfNeeded(
      from: configurationBundle.runtimeConfig
    )

    if role == .packetTunnel, MihomoCoreFFI.isAvailable {
      try MihomoCoreFFI.reload()
    } else {
      let client = try resolveControllerClientForAppOperation()
      try client.reloadConfig(payload: configurationBundle.runtimeConfig)
    }
    try refreshControllerSnapshots()
  }

  func version() -> String {
    let metadata = SharedStore.readControllerMetadata()
    if metadata.active, !metadata.version.isEmpty {
      return metadata.version
    }
    if MihomoCoreFFI.isAvailable {
      return MihomoCoreFFI.version()
    }
    return fallback.version()
  }

  func getRuntimeStatus() -> RuntimeStatus {
    SharedStore.readRuntimeStatus()
  }

  func getProxies() -> [ProxyGroupSnapshot] {
    SharedStore.readProxyGroups()
  }

  func selectProxy(group: String, proxy: String) throws {
    let client = try resolveControllerClientForAppOperation()

    try client.selectProxy(group: group, proxy: proxy)
    let observedGroups = try client.fetchProxyGroups()
    guard let observedGroup = observedGroups.first(where: { $0.name == group }) else {
      throw RuntimeBridgeError.proxyGroupNotFound(group)
    }

    let confirmedSelection = observedGroup.selected?
      .trimmingCharacters(in: .whitespacesAndNewlines)
    guard confirmedSelection == proxy else {
      publishObservedProxyGroups(
        observedGroups,
        sourceDescription: "post-selection verification"
      )
      throw RuntimeBridgeError.proxySelectionNotConfirmed(
        group: group,
        requested: proxy,
        actual: confirmedSelection
      )
    }

    publishObservedProxyGroups(
      observedGroups,
      sourceDescription: "post-selection verification"
    )
    do {
      try refreshControllerSnapshots()
    } catch {
      appendLog(
        level: "warning",
        message: "Embedded controller accepted the proxy selection '\(group)' -> '\(proxy)', but refreshing the local runtime snapshot failed right afterward: \(error.localizedDescription). The selection remains queued in the runtime and the app will continue refreshing controller state in the background."
      )
    }
  }

  func getProxyDelay(name: String, url: String, timeoutMilliseconds: Int) throws -> Int {
    let liveTunnelContext = SharedStore.readRuntimeStatus().liveTunnelContext
    if role == .app, liveTunnelContext, MihomoCoreFFI.isAvailable {
      appendLog(
        level: "info",
        message: "System VPN is active, so the app is measuring proxy '\(name)' with the lightweight delay-test core instead of the live Packet Tunnel controller."
      )
      return try performOfflineDelayTest(
        expectedGroupName: nil,
        startReason: "System VPN is active, so the app is starting a lightweight delay-test core without tun to keep node measurements off the live Packet Tunnel path."
      ) { client in
        try client.fetchProxyDelay(
          name: name,
          url: url,
          timeoutMilliseconds: timeoutMilliseconds
        )
      }
    }

    do {
      let client = try resolveControllerClientForAppOperation()
      return try client.fetchProxyDelay(
        name: name,
        url: url,
        timeoutMilliseconds: timeoutMilliseconds
      )
    } catch {
      if role == .app, liveTunnelContext {
        throw error
      }
      guard shouldFallBackToOfflineDelayTestCore(after: error) else {
        throw error
      }

      return try performOfflineDelayTest(
        expectedGroupName: nil,
        startReason: "Embedded controller is unavailable, so the app is starting a lightweight delay-test core without tun."
      ) { client in
        try client.fetchProxyDelay(
          name: name,
          url: url,
          timeoutMilliseconds: timeoutMilliseconds
        )
      }
    }
  }

  func getGroupDelays(
    name: String,
    url: String,
    timeoutMilliseconds: Int
  ) throws -> [String: Int] {
    let liveTunnelContext = SharedStore.readRuntimeStatus().liveTunnelContext
    if role == .app, liveTunnelContext, MihomoCoreFFI.isAvailable {
      appendLog(
        level: "info",
        message: "System VPN is active, so the app is measuring group '\(name)' with the lightweight delay-test core instead of the live Packet Tunnel controller."
      )
      return try performOfflineDelayTest(
        expectedGroupName: name,
        startReason: "System VPN is active, so the app is starting a lightweight delay-test core without tun to keep group measurements off the live Packet Tunnel path."
      ) { client in
        try measureGroupDelays(
          client: client,
          groupName: name,
          url: url,
          timeoutMilliseconds: timeoutMilliseconds
        )
      }
    }

    do {
      let client = try resolveControllerClientForAppOperation()
      return try measureGroupDelays(
        client: client,
        groupName: name,
        url: url,
        timeoutMilliseconds: timeoutMilliseconds
      )
    } catch {
      if role == .app, liveTunnelContext {
        throw error
      }
      guard shouldFallBackToOfflineDelayTestCore(after: error)
        || shouldFallBackToOfflineDelayTestCoreForWarmup(groupName: name, after: error) else {
        throw error
      }

      if shouldFallBackToOfflineDelayTestCoreForWarmup(groupName: name, after: error) {
        appendLog(
          level: "info",
          message: "Group '\(name)' is not ready on the live controller yet, so the app is retrying the delay test with a lightweight offline core."
        )
      }

      return try performOfflineDelayTest(
        expectedGroupName: name,
        startReason: "Embedded controller is unavailable, so the app is starting a lightweight delay-test core without tun."
      ) { client in
        try measureGroupDelays(
          client: client,
          groupName: name,
          url: url,
          timeoutMilliseconds: timeoutMilliseconds
        )
      }
    }
  }

  func subscribeLogs() -> [RuntimeLogEntry] {
    SharedStore.readLogs()
  }

  func subscribeTraffic() -> TrafficSnapshot {
    SharedStore.readTraffic()
  }

  func getConnections() -> [ConnectionSnapshot] {
    SharedStore.readConnections()
  }

  func refreshSnapshotIfNeeded() {
    guard role == .app else { return }
    let runtimeStatus = SharedStore.readRuntimeStatus()
    let metadata = SharedStore.readControllerMetadata()

    guard let client = activeControllerClientForAppOperation(
      runtimeStatus: runtimeStatus,
      metadata: metadata
    ) ?? probePendingControllerClient(runtimeStatus: runtimeStatus, metadata: metadata) else {
      return
    }

    let refreshSlowSnapshot = shouldRefreshSlowControllerSnapshot()
      && persistedProxyGroupsNeedRuntimeHydration()
    let refreshRuntimeStatus: Bool? = refreshSlowSnapshot ? true : nil
    let fastSnapshot = try? refreshFastControllerSnapshots(
      using: client,
      emitSummary: !refreshSlowSnapshot,
      refreshRuntimeStatus: refreshRuntimeStatus
    )
    if refreshSlowSnapshot {
      try? refreshControllerSnapshots(using: client, fastSnapshot: fastSnapshot)
    }
  }

  func refreshProxyGroupsSnapshotIfNeeded() {
    guard role == .app else { return }
    let runtimeStatus = SharedStore.readRuntimeStatus()
    let metadata = SharedStore.readControllerMetadata()

    let persistedGroups = SharedStore.readProxyGroups()
    guard persistedProxyGroupsNeedRuntimeHydration(persistedGroups) || shouldRefreshSlowControllerSnapshot() else {
      return
    }

    guard let client = activeControllerClientForAppOperation(
      runtimeStatus: runtimeStatus,
      metadata: metadata
    ) ?? probePendingControllerClient(runtimeStatus: runtimeStatus, metadata: metadata) else {
      return
    }

    do {
      let refreshRuntimeStatus: Bool? = persistedGroups.isEmpty ? true : nil
      let fastSnapshot = try refreshFastControllerSnapshots(
        using: client,
        emitSummary: false,
        refreshRuntimeStatus: refreshRuntimeStatus
      )
      try refreshControllerSnapshots(using: client, fastSnapshot: fastSnapshot)
    } catch {
      noteSnapshotPollingFailure(error)
    }
  }

  func refreshDataPlaneSnapshotNow() {
    guard role == .app || role == .packetTunnel else { return }
    guard let client = currentControllerClient() ?? probePendingControllerClient() else {
      noteSnapshotPollingFailure(MihomoRuntimeBridgeError.controllerUnavailable)
      return
    }

    do {
      _ = try refreshFastControllerSnapshots(
        using: client,
        refreshRuntimeStatus: shouldRefreshFastRuntimeStatusSnapshot()
      )
    } catch {
      noteSnapshotPollingFailure(error)
    }
  }

  func refreshSnapshotNow() {
    guard role == .app else { return }
    guard let client = currentControllerClient() ?? probePendingControllerClient() else {
      noteSnapshotPollingFailure(MihomoRuntimeBridgeError.controllerUnavailable)
      return
    }

    do {
      let fastSnapshot = try refreshFastControllerSnapshots(
        using: client,
        emitSummary: false,
        refreshRuntimeStatus: true
      )
      try refreshControllerSnapshots(using: client, fastSnapshot: fastSnapshot)
    } catch {
      noteSnapshotPollingFailure(error)
    }
  }

  private func startObservers(with metadata: ControllerRuntimeMetadata) {
    stopObservers()

    guard metadata.active else { return }

    if let client = try? controllerClient(for: metadata) {
      startLogStream(client: client)
      startTrafficStream(client: client)
      startSnapshotPolling()
    }
  }

  private func startSnapshotPolling() {
    refreshTimer?.cancel()

    let timer = DispatchSource.makeTimerSource(queue: observerQueue)
    timer.schedule(deadline: .now(), repeating: .seconds(1))
    timer.setEventHandler { [weak self] in
      guard let self else { return }
      do {
        guard let client = self.currentControllerClient() ?? self.probePendingControllerClient() else {
          throw MihomoRuntimeBridgeError.controllerUnavailable
        }
        let refreshSlowSnapshot = self.shouldRefreshSlowControllerSnapshot()
        let fastSnapshot = try self.refreshFastControllerSnapshots(
          using: client,
          emitSummary: !refreshSlowSnapshot,
          refreshRuntimeStatus: refreshSlowSnapshot
        )
        if refreshSlowSnapshot {
          try self.refreshControllerSnapshots(using: client, fastSnapshot: fastSnapshot)
        }
      } catch {
        self.noteSnapshotPollingFailure(error)
      }
    }
    timer.resume()
    refreshTimer = timer
  }

  private func startPacketTunnelFastSnapshotPolling() {
    refreshTimer?.cancel()
    packetPollingGeneration = UUID()
    let generation = packetPollingGeneration
    lastPacketTunnelPollAt = nil
    lastPacketTrafficTotal = 0
    lastPacketTrafficAt = nil

    let timer = DispatchSource.makeTimerSource(queue: observerQueue)
    timer.schedule(deadline: .now() + .milliseconds(250), repeating: .never, leeway: .milliseconds(125))
    timer.setEventHandler { [weak self] in
      guard let self, self.packetPollingGeneration == generation else { return }
      let now = Date()
      let statistics = MihomoPacketFlowBridge.queueStatistics
      let total = (statistics["readBytes"] ?? 0) &+ (statistics["writtenBytes"] ?? 0)
      if total != self.lastPacketTrafficTotal { self.lastPacketTrafficAt = now; self.lastPacketTrafficTotal = total }
      let status = SharedStore.readRuntimeStatus()
      let interval = PacketTunnelPollingPolicy.interval(
        ready: status.state == .running && status.dataPlaneReady,
        foreground: SharedStore.isAppForeground(at: now),
        recentTraffic: self.lastPacketTrafficAt.map({ now.timeIntervalSince($0) < 15 }) ?? false)
      defer {
        if self.packetPollingGeneration == generation, let activeTimer = self.refreshTimer, !activeTimer.isCancelled {
          activeTimer.schedule(deadline: .now() + interval, repeating: .never, leeway: .milliseconds(125))
        }
      }
      self.lastPacketTunnelPollAt = now
      do {
        guard let client = self.currentControllerClient() ?? self.probePendingControllerClient() else {
          throw MihomoRuntimeBridgeError.controllerUnavailable
        }
        _ = try self.refreshFastControllerSnapshots(
          using: client,
          emitSummary: false,
          refreshRuntimeStatus: self.shouldRefreshFastRuntimeStatusSnapshot()
        )
      } catch {
        self.noteSnapshotPollingFailure(error)
      }
    }
    refreshTimer = timer
    timer.resume()
  }

  private func stopObservers() {
    packetPollingGeneration = UUID()
    refreshTimer?.cancel()
    refreshTimer = nil

    logTask?.cancel(with: .goingAway, reason: nil)
    logTask = nil

    trafficTask?.cancel(with: .goingAway, reason: nil)
    trafficTask = nil
  }

  private func startLogStream(client: MihomoControllerClient) {
    do {
      let task = try client.makeWebSocketTask(
        path: "logs",
        queryItems: [URLQueryItem(name: "level", value: "debug")]
      )
      logTask = task
      task.resume()
      receiveLogs(on: task)
    } catch {
      appendLog(
        level: "warning",
        message: L10n.format(
          "log.runtime.log_stream_attach_failed",
          "Failed to attach log stream: %@",
          error.localizedDescription
        )
      )
    }
  }

  private func startTrafficStream(client: MihomoControllerClient) {
    do {
      let task = try client.makeWebSocketTask(path: "traffic")
      trafficTask = task
      task.resume()
      receiveTraffic(on: task)
    } catch {
      appendLog(
        level: "warning",
        message: L10n.format(
          "log.runtime.traffic_stream_attach_failed",
          "Failed to attach traffic stream: %@",
          error.localizedDescription
        )
      )
    }
  }

  private func receiveLogs(on task: URLSessionWebSocketTask) {
    task.receive { [weak self] result in
      guard let self else { return }

      switch result {
      case .success(let message):
        if case .string(let text) = message {
          self.handleLogMessage(text)
        } else if case .data(let data) = message,
                  let text = String(data: data, encoding: .utf8) {
          self.handleLogMessage(text)
        }
        self.receiveLogs(on: task)
      case .failure(let error):
        self.appendLog(
          level: "warning",
          message: L10n.format(
            "log.runtime.log_stream_closed",
            "Log stream closed: %@",
            error.localizedDescription
          )
        )
      }
    }
  }

  private func receiveTraffic(on task: URLSessionWebSocketTask) {
    task.receive { [weak self] result in
      guard let self else { return }

      switch result {
      case .success(let message):
        if case .string(let text) = message {
          self.handleTrafficMessage(text)
        } else if case .data(let data) = message,
                  let text = String(data: data, encoding: .utf8) {
          self.handleTrafficMessage(text)
        }
        self.receiveTraffic(on: task)
      case .failure(let error):
        self.appendLog(
          level: "warning",
          message: L10n.format(
            "log.runtime.traffic_stream_closed",
            "Traffic stream closed: %@",
            error.localizedDescription
          )
        )
      }
    }
  }

  private func refreshControllerSnapshots() throws {
    guard let client = currentControllerClient() ?? probePendingControllerClient() else {
      throw MihomoRuntimeBridgeError.controllerUnavailable
    }

    try refreshControllerSnapshots(using: client)
  }

  private func refreshFastControllerSnapshots() throws {
    guard let client = currentControllerClient() ?? probePendingControllerClient() else {
      throw MihomoRuntimeBridgeError.controllerUnavailable
    }

    try refreshFastControllerSnapshots(using: client)
  }

  private struct ControllerFastSnapshot {
    var fallbackStatus: RuntimeStatus
    var previousConnections: [ConnectionSnapshot]
    var status: RuntimeStatus?
    var connectionSnapshot: RuntimeConnectionSnapshot
    var routeDecisions: [RouteDecisionSnapshot]

    var connections: [ConnectionSnapshot] {
      connectionSnapshot.connections
    }

    var uploadTotal: Int64 {
      connectionSnapshot.uploadTotal
    }

    var downloadTotal: Int64 {
      connectionSnapshot.downloadTotal
    }
  }

  private final class ControllerFastPayloadResults {
    private let lock = NSLock()
    private var statusResult: Result<RuntimeStatus, Error>?
    private var connectionResult: Result<RuntimeConnectionSnapshot, Error>?
    private var routeDecisionsResult: Result<[RouteDecisionSnapshot], Error>?

    func setStatus(_ result: Result<RuntimeStatus, Error>) {
      lock.lock()
      statusResult = result
      lock.unlock()
    }

    func setConnections(
      _ result: Result<RuntimeConnectionSnapshot, Error>
    ) {
      lock.lock()
      connectionResult = result
      lock.unlock()
    }

    func setRouteDecisions(_ result: Result<[RouteDecisionSnapshot], Error>) {
      lock.lock()
      routeDecisionsResult = result
      lock.unlock()
    }

    func snapshot() -> (
      status: Result<RuntimeStatus, Error>?,
      connections: Result<RuntimeConnectionSnapshot, Error>?,
      routeDecisions: Result<[RouteDecisionSnapshot], Error>?
    ) {
      lock.lock()
      defer { lock.unlock() }
      return (statusResult, connectionResult, routeDecisionsResult)
    }
  }

  private final class ControllerSlowPayloadResults {
    private let lock = NSLock()
    private var proxyGroupsResult: Result<[ProxyGroupSnapshot], Error>?
    private var versionResult: Result<String, Error>?

    func setProxyGroups(_ result: Result<[ProxyGroupSnapshot], Error>) {
      lock.lock()
      proxyGroupsResult = result
      lock.unlock()
    }

    func setVersion(_ result: Result<String, Error>) {
      lock.lock()
      versionResult = result
      lock.unlock()
    }

    func snapshot() -> (
      proxyGroups: Result<[ProxyGroupSnapshot], Error>?,
      version: Result<String, Error>?
    ) {
      lock.lock()
      defer { lock.unlock() }
      return (proxyGroupsResult, versionResult)
    }
  }

  @discardableResult
  private func refreshFastControllerSnapshots(
    using client: MihomoControllerClient,
    emitSummary: Bool = true,
    refreshRuntimeStatus: Bool? = nil
  ) throws -> ControllerFastSnapshot {
    let snapshot = try fetchFastControllerSnapshot(
      using: client,
      refreshRuntimeStatus: refreshRuntimeStatus ?? shouldRefreshFastRuntimeStatusSnapshot()
    )
    try applyFastControllerSnapshot(snapshot, emitSummary: emitSummary)
    return snapshot
  }

  private func fetchFastControllerSnapshot(
    using client: MihomoControllerClient,
    refreshRuntimeStatus: Bool = false
  ) throws -> ControllerFastSnapshot {
    let fallbackStatus = SharedStore.readRuntimeStatus()
    let previousConnections = SharedStore.readConnections()
    let fetched = try fetchFastControllerPayload(
      using: client,
      fallbackStatus: fallbackStatus,
      refreshRuntimeStatus: refreshRuntimeStatus
    )
    if refreshRuntimeStatus {
      lastFastRuntimeStatusRefreshAt = .now
    }
    return ControllerFastSnapshot(
      fallbackStatus: fallbackStatus,
      previousConnections: previousConnections,
      status: fetched.status,
      connectionSnapshot: fetched.connectionSnapshot,
      routeDecisions: fetched.routeDecisions
    )
  }

  private func fetchFastControllerPayload(
    using client: MihomoControllerClient,
    fallbackStatus: RuntimeStatus,
    refreshRuntimeStatus: Bool
  ) throws -> (
    status: RuntimeStatus?,
    connectionSnapshot: RuntimeConnectionSnapshot,
    routeDecisions: [RouteDecisionSnapshot]
  ) {
    let results = ControllerFastPayloadResults()
    let group = DispatchGroup()

    if refreshRuntimeStatus {
      group.enter()
      controllerRequestQueue.async {
        defer { group.leave() }
        results.setStatus(Result {
          try client.fetchRuntimeStatus(fallback: fallbackStatus)
        })
      }
    }

    group.enter()
    controllerRequestQueue.async {
      defer { group.leave() }
      results.setConnections(Result {
        try client.fetchConnectionsSnapshot()
      })
    }

    group.enter()
    controllerRequestQueue.async {
      defer { group.leave() }
      results.setRouteDecisions(Result {
        try client.fetchRouteDecisions()
      })
    }

    group.wait()
    let (statusResult, connectionResult, routeDecisionsResult) = results.snapshot()
    let connections = try connectionResult?.get() ?? client.fetchConnectionsSnapshot()
    let routeDecisions = (try? routeDecisionsResult?.get()) ?? []
    return (try statusResult?.get(), connections, routeDecisions)
  }

  private func applyFastControllerSnapshot(
    _ snapshot: ControllerFastSnapshot,
    proxyGroupCount: Int? = nil,
    emitSummary: Bool = true
  ) throws {
    if let status = snapshot.status, snapshot.fallbackStatus != status {
      try SharedStore.writeRuntimeStatusIfChanged(status)
    }

    let connectionsChanged = snapshot.previousConnections != snapshot.connections
    if connectionsChanged {
      appendConnectionObservationsIfNeeded(
        previousConnections: snapshot.previousConnections,
        currentConnections: snapshot.connections
      )
      try SharedStore.writeConnectionsIfChanged(snapshot.connections)
    }
    try SharedStore.writeTrafficIfChanged(snapshot.connectionSnapshot.traffic)
    let routeExplanationSignature = routeExplanationSignature(
      routeDecisions: snapshot.routeDecisions,
      connections: snapshot.connections
    )
    if routeExplanationSignature != lastRouteExplanationConnectionSignature {
      persistRouteExplanations(
        routeDecisions: snapshot.routeDecisions,
        fallbackConnections: snapshot.connections,
        status: snapshot.status ?? snapshot.fallbackStatus
      )
      lastRouteExplanationConnectionSignature = routeExplanationSignature
    }

    guard emitSummary else { return }
    noteSnapshotPollingSuccess(
      connectionCount: snapshot.connections.count,
      proxyGroupCount: proxyGroupCount ?? lastKnownProxyGroupCount,
      trackedUpload: snapshot.uploadTotal,
      trackedDownload: snapshot.downloadTotal
    )
  }

  private func refreshControllerSnapshots(
    using client: MihomoControllerClient,
    fastSnapshot: ControllerFastSnapshot? = nil
  ) throws {
    guard beginSlowSnapshotRefreshIfNeeded() else {
      return
    }
    defer { finishSlowSnapshotRefresh() }

    lastSlowSnapshotRefreshAt = .now
    let previousMetadata = SharedStore.readControllerMetadata()
    let existingProxyGroups = SharedStore.readProxyGroups()
    let snapshot = try ensureRuntimeStatus(
      in: fastSnapshot ?? fetchFastControllerSnapshot(using: client, refreshRuntimeStatus: false),
      using: client
    )
    let slowPayload = try fetchSlowControllerPayload(
      using: client,
      metadata: previousMetadata
    )
    let observedProxies = slowPayload.proxyGroups
    let proxies = mergeObservedProxyGroups(
      observedProxies,
      into: existingProxyGroups
    )
    let version = slowPayload.version

    let proxiesChanged = existingProxyGroups != proxies

    if fastSnapshot == nil {
      try applyFastControllerSnapshot(
        snapshot,
        proxyGroupCount: proxies.count,
        emitSummary: false
      )
    }
    if proxiesChanged {
      try SharedStore.writeProxyGroupsIfChanged(proxies)
    }
    lastKnownProxyGroupCount = proxies.count
    noteSnapshotPollingSuccess(
      connectionCount: snapshot.connections.count,
      proxyGroupCount: proxies.count,
      trackedUpload: snapshot.uploadTotal,
      trackedDownload: snapshot.downloadTotal
    )

    var metadata = previousMetadata
    metadata.version = version
    metadata.active = true
    metadata.updatedAt = .now
    if metadata.baseURLString != previousMetadata.baseURLString
      || metadata.listenAddress != previousMetadata.listenAddress
      || metadata.secret != previousMetadata.secret
      || metadata.version != previousMetadata.version
      || metadata.active != previousMetadata.active {
      try SharedStore.writeControllerMetadataIfChanged(metadata)
    }
  }

  private func ensureRuntimeStatus(
    in snapshot: ControllerFastSnapshot,
    using client: MihomoControllerClient
  ) throws -> ControllerFastSnapshot {
    guard snapshot.status == nil else {
      return snapshot
    }

    var resolvedSnapshot = snapshot
    resolvedSnapshot.status = try client.fetchRuntimeStatus(fallback: snapshot.fallbackStatus)
    lastFastRuntimeStatusRefreshAt = .now
    return resolvedSnapshot
  }

  private func shouldRefreshFastRuntimeStatusSnapshot() -> Bool {
    let runtimeStatus = SharedStore.readRuntimeStatus()
    let metadata = SharedStore.readControllerMetadata()
    let interval = fastRuntimeStatusSnapshotInterval(
      runtimeStatus: runtimeStatus,
      metadata: metadata
    )
    guard interval > 0 else { return false }

    return lastFastRuntimeStatusRefreshAt.map { Date().timeIntervalSince($0) >= interval } ?? true
  }

  private func fastRuntimeStatusSnapshotInterval(
    runtimeStatus: RuntimeStatus,
    metadata: ControllerRuntimeMetadata
  ) -> TimeInterval {
    let normalizedPhase = runtimeStatus.startupPhase
      .trimmingCharacters(in: .whitespacesAndNewlines)

    if runtimeStatus.startupAcceptedForControllerWarmup
      || normalizedPhase == "warmingProviders"
      || runtimeStatus.state == .starting
      || (!metadata.active && hasPublishedControllerEndpoint(metadata) && runtimeStatus.liveTunnelContext) {
      return 1.25
    }

    if runtimeStatus.state == .running {
      return runtimeStatus.dataPlaneReady ? 6.0 : 2.0
    }

    if runtimeStatus.state == .stopping {
      return 2.0
    }

    if runtimeStatus.state == .failed {
      return 8.0
    }

    return 10.0
  }

  private func shouldRefreshSlowControllerSnapshot() -> Bool {
    let runtimeStatus = SharedStore.readRuntimeStatus()
    let metadata = SharedStore.readControllerMetadata()
    let interval = slowControllerSnapshotInterval(
      runtimeStatus: runtimeStatus,
      metadata: metadata
    )
    guard interval > 0 else { return false }

    return lastSlowSnapshotRefreshAt.map { Date().timeIntervalSince($0) >= interval } ?? true
  }

  private func persistedProxyGroupsNeedRuntimeHydration() -> Bool {
    persistedProxyGroupsNeedRuntimeHydration(SharedStore.readProxyGroups())
  }

  private func persistedProxyGroupsNeedRuntimeHydration(_ groups: [ProxyGroupSnapshot]) -> Bool {
    groups.isEmpty || groups.contains(where: \.needsRuntimeHydration)
  }

  private func beginSlowSnapshotRefreshIfNeeded() -> Bool {
    slowSnapshotInFlightLock.lock()
    defer { slowSnapshotInFlightLock.unlock() }
    guard !slowSnapshotInFlight else {
      return false
    }
    slowSnapshotInFlight = true
    return true
  }

  private func finishSlowSnapshotRefresh() {
    slowSnapshotInFlightLock.lock()
    slowSnapshotInFlight = false
    slowSnapshotInFlightLock.unlock()
  }

  private func slowControllerSnapshotInterval(
    runtimeStatus: RuntimeStatus,
    metadata: ControllerRuntimeMetadata
  ) -> TimeInterval {
    let normalizedPhase = runtimeStatus.startupPhase
      .trimmingCharacters(in: .whitespacesAndNewlines)

    if runtimeStatus.startupAcceptedForControllerWarmup
      || normalizedPhase == "warmingProviders"
      || runtimeStatus.state == .starting
      || (!metadata.active && hasPublishedControllerEndpoint(metadata) && runtimeStatus.liveTunnelContext) {
      return 1.25
    }

    if runtimeStatus.state == .running {
      return runtimeStatus.dataPlaneReady ? 6.0 : 2.0
    }

    if runtimeStatus.state == .stopping {
      return 2.0
    }

    if runtimeStatus.state == .failed {
      return 8.0
    }

    return 10.0
  }

  private func fetchControllerVersionIfNeeded(
    client: MihomoControllerClient,
    metadata: ControllerRuntimeMetadata
  ) throws -> String {
    let trimmedVersion = metadata.version.trimmingCharacters(in: .whitespacesAndNewlines)
    let shouldRefreshVersion =
      trimmedVersion.isEmpty
      || lastFetchedControllerVersionAt.map { Date().timeIntervalSince($0) >= 30 } ?? true

    guard shouldRefreshVersion else {
      return metadata.version
    }

    let version = try client.fetchVersion()
    lastFetchedControllerVersionAt = .now
    return version
  }

  private func shouldFetchControllerVersion(metadata: ControllerRuntimeMetadata) -> Bool {
    let trimmedVersion = metadata.version.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmedVersion.isEmpty
      || lastFetchedControllerVersionAt.map { Date().timeIntervalSince($0) >= 30 } ?? true
  }

  private func fetchSlowControllerPayload(
    using client: MihomoControllerClient,
    metadata: ControllerRuntimeMetadata
  ) throws -> (
    proxyGroups: [ProxyGroupSnapshot],
    version: String
  ) {
    let shouldFetchVersion = shouldFetchControllerVersion(metadata: metadata)
    guard shouldFetchVersion else {
      return (try client.fetchProxyGroups(), metadata.version)
    }

    let results = ControllerSlowPayloadResults()
    let group = DispatchGroup()

    group.enter()
    controllerRequestQueue.async {
      defer { group.leave() }
      results.setProxyGroups(Result {
        try client.fetchProxyGroups()
      })
    }

    group.enter()
    controllerRequestQueue.async {
      defer { group.leave() }
      results.setVersion(Result {
        try client.fetchVersion()
      })
    }

    group.wait()
    let (proxyGroupsResult, versionResult) = results.snapshot()
    let proxyGroups = try proxyGroupsResult?.get() ?? client.fetchProxyGroups()
    let version: String
    if let versionResult {
      version = try versionResult.get()
    } else {
      version = try client.fetchVersion()
    }
    lastFetchedControllerVersionAt = .now
    return (proxyGroups, version)
  }

  private func mergeObservedProxyGroups(
    _ observedGroups: [ProxyGroupSnapshot],
    into existingGroups: [ProxyGroupSnapshot]
  ) -> [ProxyGroupSnapshot] {
    var mergedByName = existingGroups.reduce(into: [String: ProxyGroupSnapshot]()) { result, group in
      result[group.name] = group
    }

    for observedGroup in observedGroups {
      var mergedGroup = observedGroup
      if let existingGroup = mergedByName[observedGroup.name] {
        if mergedGroup.selected == nil {
          mergedGroup.selected = existingGroup.selected
        }
        if mergedGroup.all.isEmpty, !existingGroup.all.isEmpty {
          mergedGroup.all = existingGroup.all
        }
        if mergedGroup.type == nil {
          mergedGroup.type = existingGroup.type
        }
        if mergedGroup.testURL?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true {
          mergedGroup.testURL = existingGroup.testURL
        }
      }

      mergedByName[observedGroup.name] = mergedGroup.normalizedForDisplay()
    }

    return mergedByName.values.sorted { $0.name.localizedCompare($1.name) == .orderedAscending }
  }

  private func publishObservedProxyGroups(
    _ observedGroups: [ProxyGroupSnapshot],
    sourceDescription: String
  ) {
    let existingGroups = SharedStore.readProxyGroups()
    let mergedGroups = mergeObservedProxyGroups(observedGroups, into: existingGroups)
    guard mergedGroups != existingGroups else { return }

    do {
      try SharedStore.writeProxyGroupsIfChanged(mergedGroups)
      appendLog(
        level: "debug",
        message: "Updated the local proxy snapshot from \(sourceDescription) with \(mergedGroups.count) group entries."
      )
    } catch {
      appendLog(
        level: "warning",
        message: "Failed to persist proxy groups from \(sourceDescription): \(error.localizedDescription)"
      )
    }
  }

  private func appendConnectionObservationsIfNeeded(
    previousConnections: [ConnectionSnapshot],
    currentConnections: [ConnectionSnapshot]
  ) {
    let previousConnectionIDs = Set(previousConnections.map(\.id))
    let newConnections = currentConnections.filter { !previousConnectionIDs.contains($0.id) }
    guard !newConnections.isEmpty else { return }

    for connection in newConnections.prefix(connectionObservationLogLimit) {
      appendLog(
        level: "info",
        message: """
        Observed controller connection host='\(sanitizedConnectionField(connection.host, fallback: "unknown"))' chain='\(sanitizedConnectionField(connection.chain, fallback: "DIRECT"))' rule='\(sanitizedConnectionField(connection.rule, fallback: "MATCH"))' up=\(connection.upload) down=\(connection.download).
        """
      )
    }

    let omittedCount = newConnections.count - min(newConnections.count, connectionObservationLogLimit)
    if omittedCount > 0 {
      appendLog(
        level: "debug",
        message: "Skipped logging \(omittedCount) additional new controller connection(s) in this refresh to keep the console readable."
      )
    }
  }

  private func persistRouteExplanations(
    routeDecisions: [RouteDecisionSnapshot],
    fallbackConnections: [ConnectionSnapshot],
    status: RuntimeStatus
  ) {
    let recentRouteDecisions = Array(routeDecisions.prefix(persistedRouteExplanationLimit))
    if !recentRouteDecisions.isEmpty {
      let explanations = RouteExplanationResolver.explain(recentRouteDecisions)
      persistRouteExplanationsIfNeeded(explanations)
      return
    }

    let connections = fallbackConnections
    let recentConnections = Array(connections.prefix(persistedRouteExplanationLimit))
    guard !recentConnections.isEmpty else { return }

    let explanations = RouteExplanationResolver.explain(
      recentConnections,
      fakeDnsEnabled: status.fakeDnsEnabled,
      fakeIPRange: currentFakeIPRange(for: status)
    )
    persistRouteExplanationsIfNeeded(explanations)
  }

  private func persistRouteExplanationsIfNeeded(_ explanations: [RouteExplanation]) {
    guard !explanations.isEmpty else { return }

    do {
      _ = try SharedStore.writeRouteExplanationsIfChanged(explanations)
    } catch {
      appendLog(
        level: "warning",
        message: "Failed to persist controller-backed route explanations: \(error.localizedDescription)"
      )
    }
  }

  private func routeExplanationSignature(
    routeDecisions: [RouteDecisionSnapshot],
    connections: [ConnectionSnapshot]
  ) -> String {
    if !routeDecisions.isEmpty {
      return routeDecisions
        .prefix(persistedRouteExplanationLimit)
        .map { "\($0.id):\($0.host):\($0.sniffHost):\($0.matchedRule):\($0.matchedRulePayload):\($0.chainComponents.joined(separator: ">")):\($0.destinationIP):\($0.destinationPort ?? 0):\($0.finalNode)" }
        .joined(separator: "|")
    }

    return connections
      .prefix(persistedRouteExplanationLimit)
      .map { "\($0.id):\($0.host):\($0.metadata.sniffHost):\($0.rule):\($0.rulePayload):\($0.chain):\($0.metadata.destinationIP):\($0.metadata.destinationPort ?? 0)" }
      .joined(separator: "|")
  }

  private func currentFakeIPRange(for status: RuntimeStatus) -> String {
    guard status.fakeDnsEnabled,
          let bundle = try? SharedStore.readPublishedConfigurationBundle() else {
      return ""
    }

    return compatibilityService.parseDnsSummary(from: bundle.input.controlledConfigYaml).fakeIPRange
  }

  private func sanitizedConnectionField(
    _ rawValue: String,
    fallback: String,
    maxLength: Int = 120
  ) -> String {
    let trimmedValue = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
    let normalizedValue = trimmedValue.isEmpty ? fallback : trimmedValue
    let singleLineValue = normalizedValue
      .replacingOccurrences(of: "\r", with: " ")
      .replacingOccurrences(of: "\n", with: " ")
      .replacingOccurrences(of: "'", with: "\\'")

    guard singleLineValue.count > maxLength else {
      return singleLineValue
    }

    return String(singleLineValue.prefix(maxLength - 3)) + "..."
  }

  private func noteSnapshotPollingSuccess(
    connectionCount: Int,
    proxyGroupCount: Int,
    trackedUpload: Int64,
    trackedDownload: Int64
  ) {
    lastSnapshotPollingError = nil
    guard connectionCount > 0 || trackedUpload > 0 || trackedDownload > 0 else {
      return
    }
    let summary =
      "connections=\(connectionCount) proxyGroups=\(proxyGroupCount)"
    let now = Date()
    let shouldEmitHeartbeat = lastSnapshotPollingLogAt.map { now.timeIntervalSince($0) >= 30 } ?? true
    guard summary != lastSnapshotPollingSummary || shouldEmitHeartbeat else { return }
    lastSnapshotPollingSummary = summary
    lastSnapshotPollingLogAt = now
    appendLog(
      level: "debug",
      message: "Controller snapshot polling updated \(summary) trackedUpload=\(trackedUpload) trackedDownload=\(trackedDownload)."
    )
  }

  private func noteSnapshotPollingFailure(_ error: Error) {
    let description = error.localizedDescription
    guard description != lastSnapshotPollingError else { return }
    lastSnapshotPollingError = description
    appendLog(
      level: "warning",
      message: "Controller snapshot polling failed: \(description)"
    )
  }

  private func scheduleInitialControllerWarmup() {
    observerQueue.async { [weak self] in
      guard let self else { return }

      for attempt in 1...8 {
        do {
          try self.refreshControllerSnapshots()
          if attempt > 1 {
            self.appendLog(
              level: "info",
              message: L10n.format(
                "log.runtime.controller_warmup_ready",
                "Embedded controller became ready after %d startup retries.",
                attempt
              )
            )
          }
          return
        } catch {
          if attempt == 1 {
            self.appendLog(
              level: "info",
              message: L10n.string(
                "log.runtime.controller_warmup_started",
                "Embedded controller is warming up. VPN startup may remain in the starting state for a few seconds."
              )
            )
          }

          Thread.sleep(forTimeInterval: 0.5)
        }
      }

      self.appendLog(
        level: "warning",
        message: L10n.string(
          "log.runtime.controller_warmup_timeout",
          "Embedded controller did not respond during startup warmup. Check Packet Tunnel logs if the VPN remains stuck in starting."
        )
      )
    }
  }

  private func handleLogMessage(_ text: String) {
    guard let data = text.data(using: .utf8),
          let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      return
    }

    let level = payload["type"] as? String ?? "info"
    let message = payload["payload"] as? String ?? text
    appendLog(level: level, message: message)
  }

  private func handleTrafficMessage(_ text: String) {
    guard let data = text.data(using: .utf8),
          let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      return
    }

    let up = parseInt64(payload["up"])
    let down = parseInt64(payload["down"])
    try? SharedStore.writeTraffic(
      TrafficSnapshot(upBytes: up, downBytes: down, updatedAt: .now)
    )
  }

  private func appendLog(level: String, message: String) {
    SharedStore.appendLogNonBlocking(level: level, message: message)
  }

  private func measureGroupDelays(
    client: MihomoControllerClient,
    groupName: String,
    url: String,
    timeoutMilliseconds: Int
  ) throws -> [String: Int] {
    do {
      let measurements = try client.fetchGroupDelays(
        name: groupName,
        url: url,
        timeoutMilliseconds: timeoutMilliseconds
      )
      if !measurements.isEmpty {
        appendLog(
          level: "info",
          message: "Delay test received \(measurements.count) measurements for group '\(groupName)' through the native group delay endpoint."
        )
        return measurements
      }

      appendLog(
        level: "debug",
        message: "Native group delay endpoint returned no measurements for group '\(groupName)'. Falling back to per-proxy delay requests."
      )
    } catch {
      appendLog(
        level: "debug",
        message: "Native group delay endpoint failed for group '\(groupName)': \(error.localizedDescription). Falling back to per-proxy delay requests."
      )
    }

    return try measureGroupDelaysUsingProxyEndpoints(
      client: client,
      groupName: groupName,
      url: url,
      timeoutMilliseconds: timeoutMilliseconds
    )
  }

  private func measureGroupDelaysUsingProxyEndpoints(
    client: MihomoControllerClient,
    groupName: String,
    url: String,
    timeoutMilliseconds: Int
  ) throws -> [String: Int] {
    let groups = try client.fetchProxyGroups()
    guard let group = groups.first(where: { $0.name == groupName }) else {
      appendLog(
        level: "warning",
        message: "Delay test could not find group '\(groupName)' in the controller snapshot."
      )
      throw RuntimeBridgeError.proxyGroupNotFound(groupName)
    }

    let proxyNames = ProxyNameNormalizer.uniqueDisplayOptions(from: group.all)
    guard !proxyNames.isEmpty else {
      appendLog(
        level: "warning",
        message: "Delay test found group '\(groupName)' but it does not expose any proxy entries yet."
      )
      throw RuntimeBridgeError.proxyGroupNotFound(groupName)
    }

    appendLog(
      level: "info",
      message: "Delay test is probing \(proxyNames.count) entries for group '\(groupName)' through per-proxy delay requests with concurrency \(perProxyDelayWorkerCount(proxyCount: proxyNames.count))."
    )

    var measurements: [String: Int] = [:]
    var lastError: Error?
    let queue = DispatchQueue(
      label: "org.mihomo.party.ios.runtime-delay-probes",
      qos: .userInitiated,
      attributes: .concurrent
    )
    let groupWait = DispatchGroup()
    let resultLock = NSLock()
    var nextProxyIndex = 0

    let workerCount = perProxyDelayWorkerCount(proxyCount: proxyNames.count)
    for _ in 0..<workerCount {
      groupWait.enter()
      queue.async {
        defer { groupWait.leave() }

        while true {
          let proxyName: String
          resultLock.lock()
          if nextProxyIndex < proxyNames.count {
            proxyName = proxyNames[nextProxyIndex]
            nextProxyIndex += 1
            resultLock.unlock()
          } else {
            resultLock.unlock()
            return
          }

          do {
            let delay = try client.fetchProxyDelay(
              name: proxyName,
              url: url,
              timeoutMilliseconds: timeoutMilliseconds
            )
            resultLock.lock()
            measurements[proxyName] = delay
            resultLock.unlock()
          } catch {
            resultLock.lock()
            lastError = error
            resultLock.unlock()
            self.appendLog(
              level: "debug",
              message: "Delay probe failed for '\(proxyName)' while testing group '\(groupName)': \(error.localizedDescription)"
            )
          }
        }
      }
    }
    groupWait.wait()

    if measurements.isEmpty, let lastError {
      appendLog(
        level: "warning",
        message: "Delay test did not receive any successful measurements for group '\(groupName)'. Last error: \(lastError.localizedDescription)"
      )
      throw lastError
    }
    return measurements
  }

  private func perProxyDelayWorkerCount(proxyCount: Int) -> Int {
    guard proxyCount > 1 else { return 1 }
    let activeProcessors = max(1, ProcessInfo.processInfo.activeProcessorCount)
    return min(proxyCount, activeProcessors)
  }

  private func shouldFallBackToOfflineDelayTestCore(after error: Error) -> Bool {
    guard role == .app, MihomoCoreFFI.isAvailable else {
      return false
    }

    if let runtimeError = error as? MihomoRuntimeBridgeError,
       case .controllerUnavailable = runtimeError {
      return true
    }

    if let controllerError = error as? MihomoControllerClientError {
      switch controllerError {
      case .invalidMetadata, .timeout:
        return true
      case .httpError, .invalidResponse:
        return false
      }
    }

    if let urlError = error as? URLError {
      switch urlError.code {
      case .cannotConnectToHost, .networkConnectionLost, .timedOut, .notConnectedToInternet:
        return true
      default:
        return false
      }
    }

    return false
  }

  private func shouldFallBackToOfflineDelayTestCoreForWarmup(
    groupName: String,
    after error: Error
  ) -> Bool {
    guard role == .app, MihomoCoreFFI.isAvailable else {
      return false
    }

    guard case RuntimeBridgeError.proxyGroupNotFound(let missingGroupName) = error else {
      return false
    }

    return missingGroupName == groupName
  }

  private func performOfflineDelayTest<T>(
    expectedGroupName: String?,
    startReason: String,
    operation: (MihomoControllerClient) throws -> T
  ) throws -> T {
    let configurationBundle = try SharedStore.readPublishedConfigurationBundle()
    let input = configurationBundle.input
    let report = compatibilityService.validate(input)
    guard report.isValid else {
      throw RuntimeBridgeError.invalidCompatibility(report.blockingErrors.joined(separator: "\n"))
    }

    let runtimeConfig = compatibilityService.buildDelayTestRuntimeConfig(
      fromRuntimeConfig: configurationBundle.runtimeConfig
    )
    let sessionDirectoryURL = try makeOfflineDelayTestSessionDirectory()
    let homeDirectoryURL = sessionDirectoryURL.appendingPathComponent("mihomo-home", isDirectory: true)
    let runtimeConfigURL = sessionDirectoryURL.appendingPathComponent("runtime-config.yaml")
    try fileManager.createDirectory(at: homeDirectoryURL, withIntermediateDirectories: true)
    try runtimeConfig.write(to: runtimeConfigURL, atomically: true, encoding: .utf8)
    _ = try GeoResourceManager.seedBundledResourcesIfNeeded(
      from: runtimeConfig,
      homeURL: homeDirectoryURL
    )

    let requestedControllerAddress = suggestedControllerAddress()
    let controllerSecret = UUID().uuidString.replacingOccurrences(of: "-", with: "")
    var runtimeStarted = false

    appendLog(
      level: "info",
      message: startReason
    )

    defer {
      if runtimeStarted {
        do {
          try MihomoCoreFFI.stop()
          appendLog(
            level: "info",
            message: "Stopped the lightweight delay-test core after the app-side speed test completed."
          )
        } catch {
          appendLog(
            level: "warning",
            message: "Failed to stop the lightweight delay-test core cleanly: \(error.localizedDescription)"
          )
        }
      }
      try? fileManager.removeItem(at: sessionDirectoryURL)
    }

    try MihomoCoreFFI.start(
      configPath: runtimeConfigURL.path,
      homeDirectory: homeDirectoryURL.path,
      controllerAddress: requestedControllerAddress,
      controllerSecret: controllerSecret
    )
    runtimeStarted = true

    let readyState = try waitForOfflineDelayTestController(
      requestedAddress: requestedControllerAddress,
      controllerSecret: controllerSecret,
      expectedGroupName: expectedGroupName
    )
    publishObservedProxyGroups(
      readyState.groups,
      sourceDescription: "the lightweight delay-test core"
    )

    appendLog(
      level: "info",
      message: "Lightweight delay-test core is ready at \(readyState.client.baseURLStringForLogging)."
    )
    return try operation(readyState.client)
  }

  private func makeOfflineDelayTestSessionDirectory() throws -> URL {
    let baseDirectoryURL = try SharedStore.containerURL()
      .appendingPathComponent("runtime/offline-delay-test", isDirectory: true)
    try fileManager.createDirectory(at: baseDirectoryURL, withIntermediateDirectories: true)

    let sessionDirectoryURL = baseDirectoryURL.appendingPathComponent(
      UUID().uuidString.lowercased(),
      isDirectory: true
    )
    try fileManager.createDirectory(at: sessionDirectoryURL, withIntermediateDirectories: true)
    return sessionDirectoryURL
  }

  private func waitForOfflineDelayTestController(
    requestedAddress: String,
    controllerSecret: String,
    expectedGroupName: String?
  ) throws -> (client: MihomoControllerClient, groups: [ProxyGroupSnapshot]) {
    let deadline = Date().addingTimeInterval(expectedGroupName == nil ? 6.0 : 30.0)
    var lastError: Error?

    while Date() < deadline {
      let actualAddress = MihomoCoreFFI.controllerAddress()?
        .trimmingCharacters(in: .whitespacesAndNewlines)
      let listenAddress = (actualAddress?.isEmpty == false ? actualAddress : requestedAddress) ?? requestedAddress
      let metadata = ControllerRuntimeMetadata(
        baseURLString: "http://\(listenAddress)",
        listenAddress: listenAddress,
        secret: controllerSecret,
        version: "",
        active: true
      )
      let client = MihomoControllerClient(metadata: metadata)

      do {
        _ = try client.probeVersion(timeout: 0.5)
        if let expectedGroupName {
          let groups = try client.fetchProxyGroups()
          if groups.contains(where: { $0.name == expectedGroupName && !$0.all.isEmpty }) {
            return (client, groups)
          }
        } else {
          return (client, [])
        }
      } catch {
        lastError = error
      }

      Thread.sleep(forTimeInterval: 0.2)
    }

    throw lastError ?? MihomoRuntimeBridgeError.controllerUnavailable
  }

  private func currentControllerClient() -> MihomoControllerClient? {
    currentControllerClient(using: SharedStore.readControllerMetadata())
  }

  private func currentControllerClient(using metadata: ControllerRuntimeMetadata) -> MihomoControllerClient? {
    guard metadata.active else {
      return nil
    }
    return try? controllerClient(for: metadata)
  }

  private func activeControllerClientForAppOperation(
    runtimeStatus: RuntimeStatus,
    metadata: ControllerRuntimeMetadata
  ) -> MihomoControllerClient? {
    guard let client = currentControllerClient(using: metadata) else {
      return nil
    }

    guard role == .app, shouldProbeActiveControllerBeforeAppOperation(runtimeStatus: runtimeStatus) else {
      return client
    }

    do {
      let version = try client.probeVersion(timeout: 1.0)
      if metadata.version != version {
        var refreshedMetadata = SharedStore.readControllerMetadata()
        if refreshedMetadata.listenAddress == metadata.listenAddress,
           refreshedMetadata.baseURLString == metadata.baseURLString,
           refreshedMetadata.secret == metadata.secret {
          refreshedMetadata.version = version
          refreshedMetadata.active = true
          refreshedMetadata.updatedAt = .now
          _ = try? SharedStore.writeControllerMetadataIfChanged(refreshedMetadata)
        }
      }
      return client
    } catch {
      markPublishedControllerMetadataPendingIfNeeded(metadata, error: error)
      return nil
    }
  }

  private func shouldProbeActiveControllerBeforeAppOperation(runtimeStatus: RuntimeStatus) -> Bool {
    if runtimeStatus.state == .starting {
      return true
    }

    let normalizedPhase = runtimeStatus.startupPhase.trimmingCharacters(in: .whitespacesAndNewlines)
    return normalizedPhase == "warmingProviders"
  }

  private func resolveControllerClientForAppOperation() throws -> MihomoControllerClient {
    let runtimeStatus = SharedStore.readRuntimeStatus()
    let metadata = SharedStore.readControllerMetadata()

    if role == .packetTunnel {
      guard let client = activeControllerClientForAppOperation(runtimeStatus: runtimeStatus, metadata: metadata)
        ?? probePendingControllerClient(runtimeStatus: runtimeStatus, metadata: metadata) else {
        throw MihomoRuntimeBridgeError.controllerUnavailable
      }
      return client
    }

    if let client = activeControllerClientForAppOperation(runtimeStatus: runtimeStatus, metadata: metadata) {
      return client
    }

    if let client = probePendingControllerClient(runtimeStatus: runtimeStatus, metadata: metadata) {
      return client
    }

    let shouldWaitForWarmup = controllerShouldWarmUp(runtimeStatus: runtimeStatus, metadata: metadata)

    guard shouldWaitForWarmup else {
      throw MihomoRuntimeBridgeError.controllerUnavailable
    }

    appendLog(
      level: "info",
      message: L10n.string(
        "log.runtime.controller_wait_started",
        "App is waiting for the embedded controller to become ready before sending the request."
      )
    )

    if let client = waitForControllerClient(
      timeout: controllerWaitTimeout(runtimeStatus: runtimeStatus, metadata: metadata)
    ) {
      appendLog(
        level: "info",
        message: L10n.string(
          "log.runtime.controller_wait_ready",
          "Embedded controller became ready while the app was waiting to issue a runtime request."
        )
      )
      return client
    }

    appendLog(
      level: "warning",
      message: L10n.string(
        "log.runtime.controller_wait_timeout",
        "Timed out waiting for the embedded controller. The requested runtime action was not applied."
      )
    )
    throw MihomoRuntimeBridgeError.controllerUnavailable
  }

  private func waitForControllerClient(
    timeout: TimeInterval,
    pollInterval: TimeInterval = 0.2
  ) -> MihomoControllerClient? {
    let initialMetadata = SharedStore.readControllerMetadata()
    let initialRuntimeStatus = SharedStore.readRuntimeStatus()
    if let client = activeControllerClientForAppOperation(
      runtimeStatus: initialRuntimeStatus,
      metadata: initialMetadata
    )
      ?? probePendingControllerClient(runtimeStatus: initialRuntimeStatus, metadata: initialMetadata) {
      return client
    }

    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
      Thread.sleep(forTimeInterval: pollInterval)
      let metadata = SharedStore.readControllerMetadata()
      let runtimeStatus = SharedStore.readRuntimeStatus()
      if let client = activeControllerClientForAppOperation(runtimeStatus: runtimeStatus, metadata: metadata)
        ?? probePendingControllerClient(runtimeStatus: runtimeStatus, metadata: metadata) {
        return client
      }
    }
    return nil
  }

  private func controllerClient(for metadata: ControllerRuntimeMetadata) throws -> MihomoControllerClient {
    guard metadata.baseURL != nil else {
      throw MihomoRuntimeBridgeError.controllerUnavailable
    }
    return MihomoControllerClient(metadata: metadata)
  }

  private func markPublishedControllerMetadataPendingIfNeeded(
    _ metadata: ControllerRuntimeMetadata,
    error: Error
  ) {
    guard metadata.active else { return }

    let persistedMetadata = SharedStore.readControllerMetadata()
    guard persistedMetadata.listenAddress == metadata.listenAddress,
          persistedMetadata.baseURLString == metadata.baseURLString,
          persistedMetadata.secret == metadata.secret else {
      return
    }

    var pendingMetadata = persistedMetadata
    pendingMetadata.active = false
    pendingMetadata.version = ""
    pendingMetadata.updatedAt = .now
    _ = try? SharedStore.writeControllerMetadataIfChanged(pendingMetadata)
    appendLog(
      level: "warning",
      message: "App-side controller probe could not confirm the published embedded controller endpoint during VPN startup: \(error.localizedDescription). Kept the endpoint in pending state so warmup retries can continue probing the same local controller address."
    )
  }

  private func probePendingControllerClient() -> MihomoControllerClient? {
    probePendingControllerClient(
      runtimeStatus: SharedStore.readRuntimeStatus(),
      metadata: SharedStore.readControllerMetadata()
    )
  }

  private func probePendingControllerClient(
    runtimeStatus: RuntimeStatus,
    metadata: ControllerRuntimeMetadata
  ) -> MihomoControllerClient? {
    guard let pendingMetadata = pendingControllerMetadata(
      runtimeStatus: runtimeStatus,
      metadata: metadata
    ),
          let client = try? controllerClient(for: pendingMetadata) else {
      return nil
    }

    do {
      let version = try client.fetchVersion()
      var activatedMetadata = SharedStore.readControllerMetadata()
      let wasInactive = !activatedMetadata.active
      activatedMetadata.listenAddress = pendingMetadata.listenAddress
      activatedMetadata.secret = pendingMetadata.secret
      activatedMetadata.baseURLString = pendingMetadata.baseURLString
      activatedMetadata.version = version
      activatedMetadata.active = true
      activatedMetadata.updatedAt = .now
      _ = try? SharedStore.writeControllerMetadataIfChanged(activatedMetadata)

      if wasInactive {
        appendLog(
          level: "info",
          message: "App-side controller probe confirmed the embedded controller before runtime.start finished activating controller metadata."
        )
      }
      return client
    } catch {
      return nil
    }
  }

  private func pendingControllerMetadata() -> ControllerRuntimeMetadata? {
    pendingControllerMetadata(
      runtimeStatus: SharedStore.readRuntimeStatus(),
      metadata: SharedStore.readControllerMetadata()
    )
  }

  private func pendingControllerMetadata(
    runtimeStatus: RuntimeStatus,
    metadata: ControllerRuntimeMetadata
  ) -> ControllerRuntimeMetadata? {
    guard controllerShouldWarmUp(runtimeStatus: runtimeStatus, metadata: metadata),
          hasPublishedControllerEndpoint(metadata) else {
      return nil
    }

    var resolvedMetadata = metadata
    if resolvedMetadata.baseURLString.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
       !resolvedMetadata.listenAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      resolvedMetadata.baseURLString = "http://\(resolvedMetadata.listenAddress)"
    }
    return resolvedMetadata.baseURL == nil ? nil : resolvedMetadata
  }

  private func controllerShouldWarmUp(
    runtimeStatus: RuntimeStatus,
    metadata: ControllerRuntimeMetadata
  ) -> Bool {
    let failureText = runtimeStatus.lastFailureReason?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard failureText.isEmpty else {
      return false
    }

    guard runtimeStatus.liveTunnelContext else {
      return false
    }

    return runtimeStatus.startupAcceptedForControllerWarmup || hasPublishedControllerEndpoint(metadata)
  }

  private func controllerWaitTimeout(
    runtimeStatus: RuntimeStatus,
    metadata: ControllerRuntimeMetadata
  ) -> TimeInterval {
    if runtimeStatus.startupAcceptedForControllerWarmup
      || (hasPublishedControllerEndpoint(metadata) && runtimeStatus.liveTunnelContext) {
      return 20.0
    }
    if runtimeStatus.liveTunnelContext {
      return 10.0
    }
    return 3.0
  }

  private func hasPublishedControllerEndpoint(_ metadata: ControllerRuntimeMetadata) -> Bool {
    let listenAddress = metadata.listenAddress.trimmingCharacters(in: .whitespacesAndNewlines)
    if !listenAddress.isEmpty {
      return true
    }

    let baseURLString = metadata.baseURLString.trimmingCharacters(in: .whitespacesAndNewlines)
    return !baseURLString.isEmpty
  }

  private func suggestedControllerAddress() -> String {
    "127.0.0.1:\(Int.random(in: 30000...45000))"
  }

  private func parseInt64(_ value: Any?) -> Int64 {
    if let value = value as? Int64 {
      return value
    }
    if let value = value as? Int {
      return Int64(value)
    }
    if let value = value as? Double {
      return Int64(value)
    }
    if let value = value as? NSNumber {
      return value.int64Value
    }
    return 0
  }
}
