import Foundation
import NetworkExtension
import Network
import Darwin

private struct PacketTunnelRouteExclusions {
  var ipv4Routes: [NEIPv4Route]
  var ipv6Routes: [NEIPv6Route]
  var unresolvedHosts: [String]
  var resolvedProxyHosts: [String: [String]]
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
  private let runtime: RuntimeBridge = RuntimeBridgeFactory.makePacketTunnelBridge()
  private let compatibilityService = CompatibilityService()
  private let runtimeBootstrapQueue = DispatchQueue(
    label: "org.mihomo.party.ios.packet-tunnel.runtime-bootstrap",
    qos: .userInitiated
  )
  private let startupPhaseQueue = DispatchQueue(
    label: "org.mihomo.party.ios.packet-tunnel.startup-phase",
    qos: .utility
  )
  private var startupPhaseTimer: DispatchSourceTimer?
  private var retainedPacketFlow: NEPacketTunnelFlow?
  private var activeNetworkSettings: NEPacketTunnelNetworkSettings?
  private var rollbackNetworkSettings: NEPacketTunnelNetworkSettings?
  private var activeIPv6DropPolicy = false
  private var rollbackIPv6DropPolicy: Bool?
  private var startupTask: Task<Void, Never>?
  private let startupIdentityLock = NSLock()
  private var startupIdentity: UUID?
  private let networkPathQueue = DispatchQueue(label: "org.mihomo.party.ios.network-path", qos: .utility)
  private let networkPathLock = NSLock()
  private var networkPathMonitor: NWPathMonitor?
  private var networkPathGeneration: UUID?
  private var observedNetworkPath: NetworkPathSnapshot?

  private let providerHealthQueue = DispatchQueue(label: "org.mihomo.party.ios.provider-health", qos: .utility)
  private var providerHealthStore: TunnelHealthStore?
  private var providerHealthRecord: TunnelHealthRecord?
  private var providerHealthTimer: DispatchSourceTimer?
  private var lastHealthWriteAt = Date.distantPast
  private var startupHealthSampling = true

  private func startProviderHealthJournal() {
    providerHealthQueue.sync {
      do {
        let root = try SharedStore.containerURL().appendingPathComponent("runtime", isDirectory: true)
        let store = TunnelHealthStore(directoryURL: root)
        providerHealthStore = store
        providerHealthRecord = try store.begin(processID: getpid())
        let timer = DispatchSource.makeTimerSource(queue: providerHealthQueue)
        startupHealthSampling = true
        lastHealthWriteAt = .distantPast
        timer.schedule(deadline: .now() + .milliseconds(200), repeating: .milliseconds(200), leeway: .milliseconds(50))
        timer.setEventHandler { [weak self] in self?.persistProviderHealth() }
        providerHealthTimer?.cancel()
        providerHealthTimer = timer
        timer.resume()
      } catch {
        // Forwarding must not depend on diagnostic storage availability.
        providerHealthStore = nil
        providerHealthRecord = nil
      }
    }
  }

  private func persistProviderHealth(event: String? = nil, phase: String? = nil, stopReason: String? = nil) {
    guard var record = providerHealthRecord, let store = providerHealthStore else { return }
    record.heartbeatAt = .now
    if record.stopReason != nil, event?.hasPrefix("state:") == true { return }
    if let event { record.event = event; record.eventAt = .now }
    if let phase { record.phase = phase }
    if let stopReason { record.stopReason = stopReason }
    // task_info is independent of the Go runtime and packet coordinator.
    let memory = MihomoPacketFlowObjCBridge.processMemoryStatistics()
    record.physFootprintBytes = memory["physFootprintBytes"]?.uint64Value
    record.residentBytes = memory["residentBytes"]?.uint64Value
    let previousPeak = record.peakPhysFootprintBytes ?? 0
    record.peakPhysFootprintBytes = max(previousPeak, record.physFootprintBytes ?? 0)
    let now = Date()
    if startupHealthSampling, now.timeIntervalSince(record.startedAt) > 30 {
      startupHealthSampling = false
      providerHealthTimer?.schedule(deadline: .now() + .seconds(15), repeating: .seconds(15), leeway: .seconds(3))
    }
    // Startup sampling is frequent; persist only lifecycle events, meaningful
    // new peaks or one-second checkpoints to keep file I/O bounded.
    if event != nil || now.timeIntervalSince(lastHealthWriteAt) >= 1
      || (record.peakPhysFootprintBytes ?? 0) > previousPeak + 1024 * 1024 {
      try? store.write(record)
      lastHealthWriteAt = now
    }
    providerHealthRecord = record
  }

  private func recordProviderHealth(event: String, phase: String? = nil, stopReason: String? = nil, finish: Bool = false) {
    providerHealthQueue.sync {
      persistProviderHealth(event: event, phase: phase, stopReason: stopReason)
      if finish { providerHealthTimer?.cancel(); providerHealthTimer = nil }
    }
  }

  private let runtimeBootstrapTimeout: DispatchTimeInterval = .seconds(20)
  private let packetFlowAttachTimeout: TimeInterval = 1.5

  override func startTunnel(
    options: [String: NSObject]? = nil,
    completionHandler: @escaping (Error?) -> Void
  ) {
    startProviderHealthJournal()
    let identity = UUID()
    startupIdentityLock.lock()
    startupIdentity = identity
    startupIdentityLock.unlock()
    startupTask = Task { [weak self] in
      guard let self else { completionHandler(CancellationError()); return }
      await self.startTunnelWithEncryptedBootstrap(identity: identity, completionHandler: completionHandler)
    }
  }

  private func isCurrentStartup(_ identity: UUID) -> Bool {
    startupIdentityLock.lock()
    defer { startupIdentityLock.unlock() }
    return startupIdentity == identity
  }

  private func startTunnelWithEncryptedBootstrap(identity: UUID, completionHandler: @escaping (Error?) -> Void) async {
    var failurePhase = "validatingConfig"
    do {
      appendLog(level: "info", message: "Packet Tunnel received a start request from iOS.")
      let configurationBundle = try SharedStore.readPublishedConfigurationBundle()
      let input = configurationBundle.input
      let report = compatibilityService.validate(input)
      guard report.isValid else {
        throw PacketTunnelError.invalidConfiguration(report.blockingErrors.joined(separator: "\n"))
      }
      var runtimeConfig = configurationBundle.runtimeConfig
      let networkPlan = compatibilityService.makePacketTunnelNetworkPlan(from: runtimeConfig)
      failurePhase = "resolvingProxyEndpoints"
      updateRuntimeState(.starting, startupPhase: failurePhase,
        startupMessage: "Resolving proxy endpoints through encrypted bootstrap DNS.",
        clearLastFailure: true, clearLastStopReason: true)
      let routeExclusions = try await resolveProxyServerHostRouteExclusions(
        from: runtimeConfig,
        networkPlan: networkPlan
      )
      try Task.checkCancellation()
      guard isCurrentStartup(identity) else { throw CancellationError() }
      failurePhase = "preparingNetworkSettings"
      runtimeConfig = compatibilityService.injectingResolvedProxyServerHosts(
        in: runtimeConfig,
        resolvedHosts: routeExclusions.resolvedProxyHosts
      )
      try writeBootstrappedRuntimeConfigIfNeeded(
        runtimeConfig,
        originalRuntimeConfig: configurationBundle.runtimeConfig,
        runtimeConfigURL: configurationBundle.runtimeConfigURL
      )
      resetControllerMetadataForStartup()

      updateRuntimeState(
        .starting,
        startupPhase: "applyingNetworkSettings",
        startupMessage: "Applying iOS network settings before booting the embedded core.",
        clearLastFailure: true,
        clearLastStopReason: true
      )
      appendLog(level: "info", message: "Packet Tunnel is applying network settings.")

      let settings = makeNetworkSettings(plan: networkPlan, exclusions: routeExclusions)
      let ipv6Summary = networkPlan.ipv6Address.map {
        "\($0)/\(networkPlan.ipv6PrefixLength ?? 0)"
      } ?? "disabled"
      appendLog(
        level: "info",
        message: "Packet Tunnel prepared iOS network settings. remoteIPv4=\(networkPlan.tunnelRemoteAddress) localIPv4=\(networkPlan.ipv4Address)/30 mtu=\(networkPlan.effectiveMTU) dns=\(networkPlan.dnsServers.joined(separator: ",")) excludedProxyRoutes=\(routeExclusionSummary(routeExclusions)) unresolvedProxyHosts=\(unresolvedProxyHostSummary(routeExclusions.unresolvedHosts)) ipv6=\(ipv6Summary)"
      )

      setTunnelNetworkSettings(settings) { [weak self] error in
        guard let self else { return }
        guard self.isCurrentStartup(identity) else { completionHandler(CancellationError()); return }
        if let error {
          self.updateRuntimeState(
            .failed,
            startupPhase: "failed",
            startupMessage: "System network settings failed.",
            lastFailureReason: error.localizedDescription,
            lastFailurePhase: "applyingNetworkSettings",
            clearLastStopReason: true
          )
          self.appendLog(level: "error", message: "setTunnelNetworkSettings failed: \(error.localizedDescription)")
          completionHandler(error)
          return
        }

        self.activeNetworkSettings = settings
        self.activeIPv6DropPolicy = PacketTunnelIPv6Policy(plan: networkPlan).dropsIPv6
        let runtimeConfigPath = configurationBundle.runtimeConfigURL.path
        let packetFlow = self.packetFlow
        self.retainedPacketFlow = packetFlow
        self.startNetworkPathMonitoring()
        self.appendLog(
          level: "info",
          message: "Network settings applied. Continuing Packet Tunnel bootstrap and preparing to report readiness to iOS."
        )
        self.appendLog(
          level: "debug",
          message: "Packet Tunnel is starting configuration bundle generation \(configurationBundle.generation)."
        )
        self.updateRuntimeState(
          .starting,
          startupPhase: "attachingPacketFlow",
          startupMessage: "Network settings applied. Attaching the packet flow bridge before confirming the tunnel is ready."
        )

        self.runtimeBootstrapQueue.async { [weak self] in
          guard let self else { return }
          guard self.isCurrentStartup(identity) else { completionHandler(CancellationError()); return }
          self.appendLog(
            level: "info",
            message: "Packet flow object retained. Attaching the packet flow bridge before completing the VPN startup request."
          )
          self.updateRuntimeState(
            .starting,
            startupPhase: "attachingPacketFlow",
            startupMessage: "Attaching the packet flow bridge before the VPN startup request is completed.",
            clearLastFailure: true,
            clearLastStopReason: true
          )
          MihomoPacketFlowBridge.attach(packetFlow, dropIPv6: PacketTunnelIPv6Policy(plan: networkPlan).dropsIPv6)
          self.appendLog(level: "info", message: "Packet flow bridge attach request submitted. Waiting for bridge registration.")
          guard self.waitForPacketFlowAttachment() else {
            let error = PacketTunnelError.packetFlowAttachTimedOut
            self.handleRuntimeBootstrapFailure(
              error,
              phase: "attachingPacketFlow",
              reason: "Packet flow bridge registration did not complete before the attachment timeout.",
              cancelTunnel: false
            )
            completionHandler(error)
            return
          }
          self.appendLog(
            level: "info",
            message: "Packet flow bridge attached. Reporting readiness to iOS and booting the embedded core in background."
          )
          self.updateRuntimeState(
            .starting,
            startupPhase: "startingCore",
            startupMessage: "Packet flow bridge attached. Booting the embedded core after the tunnel was handed back to iOS.",
            clearLastFailure: true,
            clearLastStopReason: true
          )
          completionHandler(nil)
          self.bootstrapRuntimeAsync(configPath: runtimeConfigPath)
        }
      }
    } catch {
      guard isCurrentStartup(identity) else { completionHandler(CancellationError()); return }
      updateRuntimeState(
        .failed,
        startupPhase: "failed",
        startupMessage: "Packet Tunnel failed before applying network settings.",
        lastFailureReason: error.localizedDescription,
        lastFailurePhase: failurePhase,
        clearLastStopReason: true
      )
      appendLog(level: "error", message: "Packet Tunnel startup failed during \(failurePhase), before applying network settings: \(error.localizedDescription)")
      completionHandler(error)
    }
  }

  private func resolveProxyServerHostRouteExclusions(
    from runtimeConfig: String,
    networkPlan: PacketTunnelNetworkPlan
  ) async throws -> PacketTunnelRouteExclusions {
    let proxyEndpoints = compatibilityService.extractProxyServerEndpointHosts(from: runtimeConfig)
    let domainEndpoints = proxyEndpoints.filter { !isIPv4Address($0) && !isIPv6Address($0) }
    let bootstrapURLs = compatibilityService.extractBootstrapDNSUpstreams(from: runtimeConfig)
      .compactMap(EncryptedBootstrapResolver.endpoint)
    let resolution = await EncryptedBootstrapResolver().resolve(hosts: domainEndpoints, endpoints: bootstrapURLs)
    try Task.checkCancellation()
    var ipv4Addresses: [String] = []
    var ipv6Addresses: [String] = []
    var unresolvedHosts: [String] = []
    var resolvedProxyHosts: [String: [String]] = [:]

    for endpoint in proxyEndpoints {
      let addresses: [String]
      if isIPv4Address(endpoint) || isIPv6Address(endpoint) {
        addresses = [endpoint]
      } else {
        addresses = resolution.addresses[endpoint] ?? []
      }

      if addresses.isEmpty {
        unresolvedHosts.append(endpoint)
        continue
      }

      if !isIPv4Address(endpoint),
         !isIPv6Address(endpoint) {
        resolvedProxyHosts[endpoint] = addresses
      }

      for address in addresses {
        if isIPv4Address(address) {
          guard shouldExcludeIPv4ProxyAddress(address, networkPlan: networkPlan),
                !ipv4Addresses.contains(address) else {
            continue
          }
          ipv4Addresses.append(address)
        } else if isIPv6Address(address) {
          guard shouldExcludeIPv6ProxyAddress(address, networkPlan: networkPlan),
                !ipv6Addresses.contains(address) else {
            continue
          }
          ipv6Addresses.append(address)
        }
      }
    }

    return PacketTunnelRouteExclusions(
      ipv4Routes: ipv4Addresses.map {
        NEIPv4Route(destinationAddress: $0, subnetMask: "255.255.255.255")
      },
      ipv6Routes: ipv6Addresses.map {
        NEIPv6Route(destinationAddress: $0, networkPrefixLength: NSNumber(value: 128))
      },
      unresolvedHosts: unresolvedHosts,
      resolvedProxyHosts: resolvedProxyHosts
    )
  }

  private func writeBootstrappedRuntimeConfigIfNeeded(
    _ runtimeConfig: String,
    originalRuntimeConfig: String,
    runtimeConfigURL: URL
  ) throws {
    guard runtimeConfig != originalRuntimeConfig else { return }

    try runtimeConfig.write(to: runtimeConfigURL, atomically: true, encoding: .utf8)
    appendLog(
      level: "info",
      message: "Packet Tunnel injected dynamically resolved proxy server host overrides into the runtime config before starting the embedded core."
    )
  }


  private func shouldExcludeIPv4ProxyAddress(
    _ address: String,
    networkPlan: PacketTunnelNetworkPlan
  ) -> Bool {
    address != networkPlan.ipv4Address
      && address != networkPlan.tunnelRemoteAddress
      && !networkPlan.dnsServers.contains(address)
  }

  private func shouldExcludeIPv6ProxyAddress(
    _ address: String,
    networkPlan: PacketTunnelNetworkPlan
  ) -> Bool {
    address != networkPlan.ipv6Address
      && !networkPlan.dnsServers.contains(address)
  }

  private func isIPv4Address(_ value: String) -> Bool {
    var address = in_addr()
    return value.withCString { inet_pton(AF_INET, $0, &address) == 1 }
  }

  private func isIPv6Address(_ value: String) -> Bool {
    var address = in6_addr()
    return value.withCString { inet_pton(AF_INET6, $0, &address) == 1 }
  }

  private func routeExclusionSummary(_ exclusions: PacketTunnelRouteExclusions) -> String {
    let ipv4Routes = exclusions.ipv4Routes.map { "\($0.destinationAddress)/32" }
    let ipv6Routes = exclusions.ipv6Routes.map {
      "\($0.destinationAddress)/\($0.destinationNetworkPrefixLength)"
    }
    let routes = ipv4Routes + ipv6Routes
    guard !routes.isEmpty else {
      return "none"
    }

    return routes.joined(separator: ",")
  }

  private func unresolvedProxyHostSummary(_ hosts: [String]) -> String {
    guard !hosts.isEmpty else {
      return "none"
    }
    let summary = hosts.prefix(8).joined(separator: ",")
    return summary + (hosts.count > 8 ? ",… (\(hosts.count) candidates deferred/unresolved)" : "")
  }

  private func makeNetworkSettings(plan: PacketTunnelNetworkPlan, exclusions: PacketTunnelRouteExclusions) -> NEPacketTunnelNetworkSettings {
    let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: plan.tunnelRemoteAddress)
    settings.mtu = NSNumber(value: plan.effectiveMTU)
    settings.ipv4Settings = NEIPv4Settings(
      addresses: [plan.ipv4Address],
      subnetMasks: [plan.ipv4SubnetMask]
    )
    settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
    settings.ipv4Settings?.excludedRoutes = exclusions.ipv4Routes

    let ipv6Policy = PacketTunnelIPv6Policy(plan: plan)
    settings.ipv6Settings = NEIPv6Settings(
      addresses: [ipv6Policy.captureAddress],
      networkPrefixLengths: [NSNumber(value: ipv6Policy.prefixLength)]
    )
    settings.ipv6Settings?.includedRoutes = [NEIPv6Route.default()]
    settings.ipv6Settings?.excludedRoutes = exclusions.ipv6Routes
    // A disabled core IPv6 family remains captured and is dropped by the
    // packet-flow bridge. It must not fall back to the physical IPv6 route.
    // includeAllNetworks is the system enforcement; excludedRoutes are not a
    // firewall nor an exemption mechanism for provider-originated sockets.

    settings.dnsSettings = NEDNSSettings(servers: plan.dnsServers)
    settings.dnsSettings?.matchDomains = [""]
    settings.dnsSettings?.matchDomainsNoSearch = true
    return settings
  }

  private func handleNetworkSettingsMessage(_ command: String, completion: ((Data?) -> Void)?) {
    let reply: (Error?) -> Void = { error in
      completion?(try? JSONEncoder().encode(TunnelNetworkSettingsReply(error: error?.localizedDescription)))
    }
    runtimeBootstrapQueue.async { [weak self] in
      guard let self else { return }
      if command == "commit-network-settings" {
        if let flow = self.retainedPacketFlow {
          MihomoPacketFlowBridge.setDropIPv6(self.activeIPv6DropPolicy, for: flow)
        }
        self.rollbackNetworkSettings = nil
        self.rollbackIPv6DropPolicy = nil
        reply(nil)
        return
      }
      if command == "restore-network-settings" {
        guard let old = self.rollbackNetworkSettings, let flow = self.retainedPacketFlow else { reply(nil); return }
        self.setTunnelNetworkSettings(old) { error in
          guard self.retainedPacketFlow === flow else { reply(CancellationError()); return }
          if error == nil {
            self.activeNetworkSettings = old
            self.activeIPv6DropPolicy = self.rollbackIPv6DropPolicy ?? self.activeIPv6DropPolicy
            if let flow = self.retainedPacketFlow {
              MihomoPacketFlowBridge.setDropIPv6(self.activeIPv6DropPolicy, for: flow)
            }
            self.rollbackNetworkSettings = nil
            self.rollbackIPv6DropPolicy = nil
          }
          reply(error)
        }
        return
      }
      Task {
       do {
        guard let flow = self.retainedPacketFlow, MihomoPacketFlowBridge.isAttached else {
          throw NSError(domain: "ClashParty.NetworkSettings", code: 1, userInfo: [NSLocalizedDescriptionKey: "The VPN tunnel is not active."])
        }
        let start = Date()
        let bundle = try SharedStore.readPublishedConfigurationBundle()
        let plan = self.compatibilityService.makePacketTunnelNetworkPlan(from: bundle.runtimeConfig)
        let exclusions = try await self.resolveProxyServerHostRouteExclusions(from: bundle.runtimeConfig, networkPlan: plan)
        guard self.retainedPacketFlow === flow, MihomoPacketFlowBridge.isAttached else {
          throw NSError(domain: "ClashParty.NetworkSettings", code: 1, userInfo: [NSLocalizedDescriptionKey: "The VPN session changed during encrypted bootstrap."])
        }
        guard Date().timeIntervalSince(start) < 25 else {
          throw NSError(domain: "ClashParty.NetworkSettings", code: 2, userInfo: [NSLocalizedDescriptionKey: "Resolving VPN settings took too long."])
        }
        guard try SharedStore.readPublishedConfigurationBundle().generation == bundle.generation else {
          throw NSError(domain: "ClashParty.NetworkSettings", code: 3, userInfo: [NSLocalizedDescriptionKey: "The published configuration changed during encrypted bootstrap."])
        }
        let bootstrapped = self.compatibilityService.injectingResolvedProxyServerHosts(
          in: bundle.runtimeConfig, resolvedHosts: exclusions.resolvedProxyHosts
        )
        try self.writeBootstrappedRuntimeConfigIfNeeded(bootstrapped,
          originalRuntimeConfig: bundle.runtimeConfig, runtimeConfigURL: bundle.runtimeConfigURL)
        let settings = self.makeNetworkSettings(plan: plan, exclusions: exclusions)
        let nextIPv6DropPolicy = PacketTunnelIPv6Policy(plan: plan).dropsIPv6
        self.rollbackNetworkSettings = self.activeNetworkSettings
        self.rollbackIPv6DropPolicy = self.activeIPv6DropPolicy
        // Disable immediately when moving to a disabled family; enabling waits
        // for core commit, so reload/rollback cannot create a forwarding gap.
        guard MihomoPacketFlowBridge.setDropIPv6(self.activeIPv6DropPolicy || nextIPv6DropPolicy, for: flow) else {
          throw NSError(domain: "ClashParty.NetworkSettings", code: 1, userInfo: [NSLocalizedDescriptionKey: "The VPN packet flow is no longer active."])
        }
        self.setTunnelNetworkSettings(settings) { error in
          guard self.retainedPacketFlow === flow else { reply(CancellationError()); return }
          if error == nil {
            self.activeNetworkSettings = settings
            self.activeIPv6DropPolicy = nextIPv6DropPolicy
            self.appendLog(level: "info", message: "Applied updated iOS network settings before core reload. mtu=\(plan.effectiveMTU) ipv6=\(plan.ipv6Address ?? "disabled").")
          } else {
            MihomoPacketFlowBridge.setDropIPv6(self.activeIPv6DropPolicy, for: flow)
            self.rollbackNetworkSettings = nil
            self.rollbackIPv6DropPolicy = nil
          }
          reply(error)
        }
       } catch { reply(error) }
      }
    }
  }

  private func startNetworkPathMonitoring() {
    stopNetworkPathMonitoring()
    let monitor = NWPathMonitor()
    let generation = UUID()
    networkPathLock.lock()
    networkPathMonitor = monitor
    networkPathGeneration = generation
    observedNetworkPath = nil
    networkPathLock.unlock()
    monitor.pathUpdateHandler = { [weak self] path in
      guard let self else { return }
      let status: String
      switch path.status {
      case .satisfied: status = "satisfied"
      case .unsatisfied: status = "unsatisfied"
      case .requiresConnection: status = "requiresConnection"
      @unknown default: status = "unknown"
      }
      let types: [(NWInterface.InterfaceType, String)] = [(.wifi, "Wi-Fi"), (.cellular, "Cellular"), (.wiredEthernet, "Ethernet")]
      let interfaces = types.compactMap { path.usesInterfaceType($0.0) ? $0.1 : nil }
      let next = NetworkPathSnapshot(status: status, interfaces: interfaces, expensive: path.isExpensive,
        constrained: path.isConstrained, supportsIPv4: path.supportsIPv4, supportsIPv6: path.supportsIPv6)
      self.networkPathLock.lock()
      guard self.networkPathGeneration == generation else { self.networkPathLock.unlock(); return }
      let previous = self.observedNetworkPath
      let changed = previous?.status != next.status || previous?.interfaces != next.interfaces
        || previous?.expensive != next.expensive || previous?.constrained != next.constrained
        || previous?.supportsIPv4 != next.supportsIPv4 || previous?.supportsIPv6 != next.supportsIPv6
      if changed { self.observedNetworkPath = next }
      self.networkPathLock.unlock()
      guard changed else { return }
      self.appendLog(level: status == "satisfied" ? "info" : "warning",
        message: "Network path changed: status=\(status) interfaces=\(interfaces.joined(separator: ",")) expensive=\(next.expensive) constrained=\(next.constrained) ipv4=\(next.supportsIPv4) ipv6=\(next.supportsIPv6).")
      // The core already observes interface changes. Keep forwarding and its
      // existing connections under that owner; this observer does not restart TUN.
    }
    monitor.start(queue: networkPathQueue)
  }

  private func stopNetworkPathMonitoring() {
    networkPathLock.lock()
    let monitor = networkPathMonitor
    networkPathMonitor = nil
    networkPathGeneration = nil
    networkPathLock.unlock()
    monitor?.cancel()
  }

  private func currentNetworkPath() -> NetworkPathSnapshot? {
    networkPathLock.lock()
    defer { networkPathLock.unlock() }
    return observedNetworkPath
  }

  override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    startupIdentityLock.lock()
    startupIdentity = nil
    startupIdentityLock.unlock()
    startupTask?.cancel()
    startupTask = nil
    let stopReason = stopReasonDescription(reason)
    recordProviderHealth(event: "stopReceived", phase: "stopping", stopReason: stopReason, finish: true)
    let previousStatus = SharedStore.readRuntimeStatus()
    // Persist the OS reason before potentially blocking core cleanup. Keep it
    // available even if cleanup fails or the extension exits during shutdown.
    updateRuntimeState(
      .stopping,
      startupPhase: "stopping",
      startupMessage: "Packet Tunnel is stopping.",
      lastStopReason: stopReason,
      previousStatus: previousStatus
    )
    appendLog(level: "info", message: "Packet Tunnel received stopTunnel(with:) reason: \(stopReason)")
    stopStartupPhaseTimer()
    stopNetworkPathMonitoring()
    appendLog(level: "info", message: "Packet flow counters at stop: \(MihomoPacketFlowBridge.queueStatistics)")
    try? runtime.stop()
    MihomoPacketFlowBridge.clear()
    retainedPacketFlow = nil
    activeNetworkSettings = nil
    rollbackNetworkSettings = nil
    rollbackIPv6DropPolicy = nil
    activeIPv6DropPolicy = false
    updateRuntimeState(
      .stopped,
      startupPhase: "idle",
      startupMessage: "Packet Tunnel stopped.",
      lastFailureReason: previousStatus.lastFailureReason,
      lastFailurePhase: previousStatus.lastFailurePhase,
      lastStopReason: stopReason,
      previousStatus: previousStatus
    )
    recordProviderHealth(event: "stopped", phase: "stopped", stopReason: stopReason, finish: true)
    appendLog(level: "info", message: "Packet Tunnel stopped. stopTunnel(with:) reason: \(stopReason)")
    completionHandler()
  }

  override func handleAppMessage(
    _ messageData: Data,
    completionHandler: ((Data?) -> Void)? = nil
  ) {
    if let command = String(data: messageData, encoding: .utf8),
       ["apply-network-settings", "restore-network-settings", "commit-network-settings"].contains(command) {
      handleNetworkSettingsMessage(command, completion: completionHandler)
      return
    }
    let snapshot = currentExtensionSnapshot()
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    completionHandler?(try? encoder.encode(snapshot))
  }

  private func updateRuntimeState(
    _ state: RuntimeConnectionState,
    startupPhase: String? = nil,
    startupMessage: String? = nil,
    lastFailureReason: String? = nil,
    lastFailurePhase: String? = nil,
    clearLastFailure: Bool = false,
    lastStopReason: String? = nil,
    clearLastStopReason: Bool = false,
    previousStatus: RuntimeStatus? = nil
  ) {
    recordProviderHealth(event: "state:" + state.rawValue, phase: startupPhase)
    let previous = previousStatus ?? SharedStore.readRuntimeStatus()
    let nextStatus = RuntimeStatus(
        state: state,
        mode: previous.mode,
        vpnConnected: state == .running,
        fakeDnsEnabled: previous.fakeDnsEnabled,
        activeProfileId: previous.activeProfileId,
        dnsMode: previous.dnsMode,
        backend: previous.backend,
        dataPlaneReady: state == .running,
        startupPhase: startupPhase ?? previous.startupPhase,
        startupMessage: startupMessage ?? previous.startupMessage,
        lastFailureReason: clearLastFailure ? nil : (lastFailureReason ?? previous.lastFailureReason),
        lastFailurePhase: clearLastFailure ? nil : (lastFailurePhase ?? previous.lastFailurePhase),
        lastStopReason: clearLastStopReason ? nil : (lastStopReason ?? previous.lastStopReason),
        updatedAt: previous.updatedAt
      ).updatingTimestampIfNeeded(comparedTo: previous)
    _ = try? SharedStore.writeRuntimeStatusIfChanged(nextStatus)
  }

  private func currentExtensionSnapshot() -> TunnelExtensionSnapshot {
    let previous = SharedStore.readRuntimeStatus()
    let phase = MihomoCoreFFI.startupPhase()
    let message = MihomoCoreFFI.startupMessage()
    let failureReason = MihomoCoreFFI.lastStartupError() ?? previous.lastFailureReason
    let failurePhase = failureReason == nil ? previous.lastFailurePhase : phase
    let controllerAddress = MihomoCoreFFI.controllerAddress()
    publishPendingControllerAddressIfNeeded(controllerAddress)
    let running = MihomoCoreFFI.isRunning()
    let state: RuntimeConnectionState = running ? .running : (previous.state == .failed ? .failed : previous.state)
    let nextStatus = RuntimeStatus(
      state: state,
      mode: previous.mode,
      vpnConnected: running,
      fakeDnsEnabled: previous.fakeDnsEnabled,
      activeProfileId: previous.activeProfileId,
      dnsMode: previous.dnsMode,
      backend: previous.backend,
      dataPlaneReady: running,
      startupPhase: phase.isEmpty ? previous.startupPhase : phase,
      startupMessage: message.isEmpty ? previous.startupMessage : message,
      lastFailureReason: failureReason,
      lastFailurePhase: failurePhase,
      lastStopReason: previous.lastStopReason,
      updatedAt: previous.updatedAt
    )
    let status = nextStatus.updatingTimestampIfNeeded(comparedTo: previous)
    return TunnelExtensionSnapshot(
      runtimeStatus: status,
      startupPhase: status.startupPhase,
      startupMessage: status.startupMessage,
      lastFailureReason: status.lastFailureReason,
      lastFailurePhase: status.lastFailurePhase,
      lastStopReason: status.lastStopReason,
      controllerAddress: controllerAddress,
      phaseUpdatedAt: status.updatedAt,
      running: running,
      networkPath: currentNetworkPath(),
      packetFlowStatistics: MihomoPacketFlowBridge.queueStatistics
    )
  }

  private func publishPendingControllerAddressIfNeeded(_ controllerAddress: String?) {
    let trimmedAddress = controllerAddress?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard !trimmedAddress.isEmpty else { return }

    var metadata = SharedStore.readControllerMetadata()
    let expectedBaseURL = "http://\(trimmedAddress)"
    var didChange = false

    if metadata.listenAddress != trimmedAddress {
      metadata.listenAddress = trimmedAddress
      didChange = true
    }

    if metadata.baseURLString != expectedBaseURL {
      metadata.baseURLString = expectedBaseURL
      didChange = true
    }

    guard didChange else { return }

    metadata.updatedAt = .now
    _ = try? SharedStore.writeControllerMetadataIfChanged(metadata)
    appendLog(
      level: "debug",
      message: "Packet Tunnel published the embedded controller endpoint \(expectedBaseURL) before controller metadata became active."
    )
  }

  private func appendLog(level: String, message: String) {
    SharedStore.appendLogNonBlocking(level: level, message: message)
  }

  private func resetControllerMetadataForStartup() {
    let metadata = SharedStore.readControllerMetadata()
    let hadPersistedControllerEndpoint =
      metadata.active
      || !metadata.listenAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      || !metadata.baseURLString.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      || !metadata.version.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty

    guard hadPersistedControllerEndpoint else { return }

    _ = try? SharedStore.writeControllerMetadataIfChanged(ControllerRuntimeMetadata())
    appendLog(
      level: "debug",
      message: "Packet Tunnel cleared previously persisted controller metadata before bootstrapping a new embedded runtime, so app-side controller warmup will not reuse a stale endpoint."
    )
  }

  private func bootstrapRuntimeAsync(configPath: String) {
    stopStartupPhaseTimer()
    let attemptID = UUID().uuidString
    startStartupPhaseTimer(attemptID: attemptID)
    appendLog(level: "info", message: "Scheduling embedded runtime bootstrap on the packet tunnel bootstrap queue.")

    let stateLock = NSLock()
    var finished = false

    func finish(_ operation: @escaping () -> Void) -> Bool {
      stateLock.lock()
      let shouldRun = !finished
      if shouldRun {
        finished = true
      }
      stateLock.unlock()

      guard shouldRun else { return false }
      operation()
      return true
    }

    func snapshotSignalsReady(_ snapshot: TunnelExtensionSnapshot) -> Bool {
      snapshot.running
        || snapshot.runtimeStatus.state == .running
        || (
          snapshot.startupPhase == "warmingProviders"
            && (snapshot.lastFailureReason?.isEmpty ?? true)
        )
    }

    func persistSuccessfulBootstrap(snapshot: TunnelExtensionSnapshot, source: String) {
      self.stopStartupPhaseTimer()
      var persistedStatus = snapshot.runtimeStatus
      persistedStatus.state = .running
      persistedStatus.vpnConnected = true
      persistedStatus.dataPlaneReady = true
      persistedStatus.lastFailureReason = nil
      persistedStatus.lastFailurePhase = nil
      persistedStatus.lastStopReason = nil
      persistedStatus.updatedAt = .now
      self.updateRuntimeState(
        .running,
        startupPhase: persistedStatus.startupPhase,
        startupMessage: persistedStatus.startupMessage,
        clearLastFailure: true,
        clearLastStopReason: true
      )
      self.appendLog(
        level: "info",
        message: "\(source) Phase: \(snapshot.startupPhase). Running: \(snapshot.running ? "yes" : "no")."
      )
      _ = try? SharedStore.writeRuntimeStatusIfChanged(persistedStatus)
    }

    func recordLateStartupError(_ error: Error, snapshot: TunnelExtensionSnapshot) {
      let phase = snapshot.lastFailurePhase ?? snapshot.startupPhase
      let reason = snapshot.lastFailureReason ?? error.localizedDescription
      self.appendLog(
        level: "error",
        message: "Embedded runtime returned a late startup error after the provider already marked the tunnel ready. Phase: \(phase). Reason: \(reason)"
      )
      self.updateRuntimeState(
        .running,
        startupPhase: snapshot.startupPhase,
        startupMessage: snapshot.startupMessage,
        lastFailureReason: "Late startup error: \(reason)",
        lastFailurePhase: phase
      )
    }

    func scheduleRunningProbe() {
      startupPhaseQueue.asyncAfter(deadline: .now() + .milliseconds(250)) { [weak self] in
        guard let self else { return }

        stateLock.lock()
        let alreadyFinished = finished
        stateLock.unlock()
        guard !alreadyFinished else { return }

        let snapshot = self.currentExtensionSnapshot()
        if snapshotSignalsReady(snapshot) {
          _ = finish {
            persistSuccessfulBootstrap(
              snapshot: snapshot,
              source: "Provider probe observed the critical runtime path ready before runtime.start returned."
            )
          }
          return
        }

        if let failure = snapshot.lastFailureReason, !failure.isEmpty {
          _ = finish {
            self.handleRuntimeBootstrapFailure(
              PacketTunnelError.startupTimedOut(phase: snapshot.startupPhase, reason: failure),
              phase: snapshot.lastFailurePhase ?? snapshot.startupPhase,
              reason: failure
            )
          }
          return
        }

        scheduleRunningProbe()
      }
    }

    runtimeBootstrapQueue.async { [weak self] in
      guard let self else { return }
      self.prepareGeoResourcesBeforeCoreStart(configPath: configPath)
      self.appendLog(level: "info", message: "Calling runtime.start(configPath:) for the embedded core.")
      do {
        try self.runtime.start(configPath: configPath)
        let snapshot = self.currentExtensionSnapshot()
        if !finish({
          persistSuccessfulBootstrap(
            snapshot: snapshot,
            source: "Embedded runtime startup returned and the provider accepted the runtime as ready."
          )
        }) {
          self.appendLog(
            level: "info",
            message: "runtime.start returned after the provider had already accepted the tunnel startup. Phase: \(snapshot.startupPhase). Running: \(snapshot.running ? "yes" : "no")."
          )
        }
      } catch {
        let snapshot = self.currentExtensionSnapshot()
        if !finish({
          self.handleRuntimeBootstrapFailure(
            error,
            phase: MihomoCoreFFI.startupPhase(),
            reason: MihomoCoreFFI.lastStartupError() ?? error.localizedDescription
          )
        }) {
          recordLateStartupError(error, snapshot: snapshot)
        }
      }
    }

    scheduleRunningProbe()

    startupPhaseQueue.asyncAfter(deadline: .now() + runtimeBootstrapTimeout) { [weak self] in
      guard let self else { return }
      _ = finish {
        let phase = MihomoCoreFFI.startupPhase()
        let reason = MihomoCoreFFI.lastStartupError()
          ?? "Embedded runtime did not complete startup before the watchdog timeout."
        let error = PacketTunnelError.startupTimedOut(phase: phase, reason: reason)
        self.handleRuntimeBootstrapFailure(
          error,
          phase: phase,
          reason: reason
        )
      }
    }
  }

  private func prepareGeoResourcesBeforeCoreStart(configPath: String) {
    do {
      let runtimeConfig = try String(contentsOfFile: configPath, encoding: .utf8)
      let summary = try GeoResourceManager.seedBundledResourcesIfNeeded(from: runtimeConfig)
      guard summary.preparedCount > 0 || !summary.failedMessages.isEmpty else { return }

      if summary.failedMessages.isEmpty {
        appendLog(
          level: "info",
          message: "Packet Tunnel prepared GeoResources before core startup. ready=\(summary.readyCount) seeded=\(summary.seededCount)."
        )
      } else {
        appendLog(
          level: "warning",
          message: "Packet Tunnel could not prepare all GeoResources before core startup. ready=\(summary.readyCount) seeded=\(summary.seededCount) missing=\(summary.missingNames.joined(separator: ","))"
        )
      }
    } catch {
      appendLog(
        level: "warning",
        message: "Packet Tunnel skipped GeoResource preparation before core startup: \(error.localizedDescription)"
      )
    }
  }

  private func startStartupPhaseTimer(attemptID: String) {
    var lastSignature = ""
    let timer = DispatchSource.makeTimerSource(queue: startupPhaseQueue)
    timer.schedule(deadline: .now(), repeating: .milliseconds(500))
    timer.setEventHandler { [weak self] in
      guard let self else { return }

      let phase = MihomoCoreFFI.startupPhase()
      let message = MihomoCoreFFI.startupMessage()
      let failure = MihomoCoreFFI.lastStartupError()
      let running = MihomoCoreFFI.isRunning()
      let signature = [attemptID, phase, message, failure ?? "", running ? "1" : "0"].joined(separator: "|")

      guard signature != lastSignature else { return }
      lastSignature = signature

      let state: RuntimeConnectionState = failure == nil
        ? (running ? .running : .starting)
        : .failed

      self.updateRuntimeState(
        state,
        startupPhase: phase,
        startupMessage: message,
        lastFailureReason: failure,
        lastFailurePhase: failure == nil ? nil : phase,
        clearLastFailure: failure == nil
      )

      if !message.isEmpty {
        self.appendLog(level: failure == nil ? "debug" : "error", message: "Startup phase [\(phase)]: \(message)")
      }

      if let failure, !failure.isEmpty {
        self.appendLog(level: "error", message: "Embedded runtime reported startup failure during \(phase): \(failure)")
      }
    }
    timer.resume()
    startupPhaseTimer = timer
  }

  private func stopStartupPhaseTimer() {
    startupPhaseTimer?.cancel()
    startupPhaseTimer = nil
  }

  private func waitForPacketFlowAttachment() -> Bool {
    let deadline = Date().addingTimeInterval(packetFlowAttachTimeout)
    while Date() < deadline {
      if MihomoPacketFlowBridge.isAttached {
        return true
      }
      Thread.sleep(forTimeInterval: 0.05)
    }
    return MihomoPacketFlowBridge.isAttached
  }

  private func handleRuntimeBootstrapFailure(
    _ error: Error,
    phase: String,
    reason: String,
    cancelTunnel: Bool = true
  ) {
    recordProviderHealth(event: "bootstrapFailed", phase: phase, stopReason: reason, finish: true)
    stopStartupPhaseTimer()
    stopNetworkPathMonitoring()
    appendLog(level: "info", message: "Packet flow counters at stop: \(MihomoPacketFlowBridge.queueStatistics)")
    try? runtime.stop()
    MihomoPacketFlowBridge.clear()
    retainedPacketFlow = nil
    updateRuntimeState(
      .failed,
      startupPhase: "failed",
      startupMessage: "Embedded runtime failed during tunnel startup.",
      lastFailureReason: reason,
      lastFailurePhase: phase,
      clearLastStopReason: true
    )
    appendLog(level: "error", message: "Embedded runtime failed during \(phase): \(reason)")
    if cancelTunnel {
      cancelTunnelWithError(error)
    }
  }

  private func stopReasonDescription(_ reason: NEProviderStopReason) -> String {
    switch reason {
    case .none:
      return TunnelStopReason.none.rawValue
    case .userInitiated:
      return TunnelStopReason.userInitiated.rawValue
    case .providerFailed:
      return TunnelStopReason.providerFailed.rawValue
    case .noNetworkAvailable:
      return TunnelStopReason.noNetworkAvailable.rawValue
    case .unrecoverableNetworkChange:
      return TunnelStopReason.unrecoverableNetworkChange.rawValue
    case .providerDisabled:
      return TunnelStopReason.providerDisabled.rawValue
    case .internalError:
      return TunnelStopReason.internalError.rawValue
    case .authenticationCanceled:
      return TunnelStopReason.authenticationCanceled.rawValue
    case .configurationFailed:
      return TunnelStopReason.configurationFailed.rawValue
    case .idleTimeout:
      return TunnelStopReason.idleTimeout.rawValue
    case .configurationDisabled:
      return TunnelStopReason.configurationDisabled.rawValue
    case .configurationRemoved:
      return TunnelStopReason.configurationRemoved.rawValue
    case .superceded:
      return TunnelStopReason.superseded.rawValue
    case .userLogout:
      return TunnelStopReason.userLogout.rawValue
    case .userSwitch:
      return TunnelStopReason.userSwitch.rawValue
    case .connectionFailed:
      return TunnelStopReason.connectionFailed.rawValue
    case .sleep:
      return TunnelStopReason.sleep.rawValue
    case .appUpdate:
      return TunnelStopReason.appUpdate.rawValue
    @unknown default:
      return "The provider stopped for an unknown reason (\(reason.rawValue))."
    }
  }
}

enum PacketTunnelError: LocalizedError {
  case invalidConfiguration(String)
  case packetFlowAttachTimedOut
  case startupTimedOut(phase: String, reason: String)

  var errorDescription: String? {
    switch self {
    case .invalidConfiguration(let message):
      return "Tunnel configuration is invalid.\n\(message)"
    case .packetFlowAttachTimedOut:
      return "Packet flow bridge attachment timed out before the embedded core could start."
    case .startupTimedOut(let phase, let reason):
      return "Embedded runtime startup timed out during \(phase).\n\(reason)"
    }
  }
}
