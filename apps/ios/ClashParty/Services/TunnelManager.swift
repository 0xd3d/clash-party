import Foundation
import NetworkExtension

final class TunnelManager {
  static let shared = TunnelManager()

  private enum TunnelCommand {
    case start
    case stop
  }

  struct RuntimeObservation {
    let runtimeStatus: RuntimeStatus
    let extensionSnapshot: TunnelExtensionSnapshot?
  }

  private var providerBundleIdentifier: String {
    (Bundle.main.bundleIdentifier ?? "org.mihomo.party.ios") + ".tunnel"
  }
  private let localizedDescription = "Clash Party iOS"
  private let serverAddress = "Clash Party iOS"
  private let statusLogQueue = DispatchQueue(label: "org.mihomo.party.ios.tunnel-status-log")
  private let commandQueue = DispatchQueue(label: "org.mihomo.party.ios.tunnel-command")
  private let startupGracePeriod: TimeInterval = 6
  private var lastLoggedVPNStatusRawValue: Int?
  private var lastLoggedVPNDiagnostic: TunnelStatusDiagnostic?
  private var hasObservedLiveTunnelContext = false
  private var activeCommand: TunnelCommand?

  private init() {}

  func prepareManagerForForeground() async {
    do {
      guard let manager = try await loadExistingManager() else { return }
      _ = try await configureManager(manager)
    } catch {
      SharedStore.appendLog(
        level: "warning",
        message: "TunnelManager could not sanitize the system VPN configuration during app launch: \(error.localizedDescription)"
      )
    }
  }

  func loadManager(enableForExplicitStart: Bool = false) async throws -> NETunnelProviderManager {
    let managers = try await NETunnelProviderManager.loadAllFromPreferences()
    let existing = matchingManager(in: managers)

    return try await configureManager(existing ?? NETunnelProviderManager(), enableForExplicitStart: enableForExplicitStart)
  }

  func startTunnel() async throws {
    guard claimCommand(.start) else {
      SharedStore.appendLog(
        level: "info",
        message: "TunnelManager ignored a duplicate VPN start request because another tunnel command is still in flight."
      )
      return
    }
    defer { releaseCommand(.start) }

    let manager = try await loadManager(enableForExplicitStart: true)
    let connectionStatus = manager.connection.status
    let fallbackStatus = SharedStore.readRuntimeStatus()
    let startupStillSettling = fallbackStatus.state == .starting
      && (fallbackStatus.lastFailureReason?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
      && Date().timeIntervalSince(fallbackStatus.updatedAt) < startupGracePeriod

    if startupStillSettling {
      _ = try? SharedStore.writeRuntimeStatusIfChanged(fallbackStatus)
      SharedStore.appendLog(
        level: "info",
        message: "TunnelManager ignored a duplicate VPN start request because the previous startup attempt is still within the app-side startup grace period."
      )
      return
    }

    switch connectionStatus {
    case .connected, .connecting, .reasserting:
      let currentStatus = runtimeStatus(from: connectionStatus, fallback: fallbackStatus)
      _ = try? SharedStore.writeRuntimeStatusIfChanged(currentStatus)
      SharedStore.appendLog(
        level: "info",
        message: "TunnelManager ignored a duplicate VPN start request because the system VPN status is already \(statusText(for: connectionStatus))."
      )
      return
    case .disconnecting:
      let currentStatus = runtimeStatus(from: connectionStatus, fallback: fallbackStatus)
      _ = try? SharedStore.writeRuntimeStatusIfChanged(currentStatus)
      SharedStore.appendLog(
        level: "warning",
        message: "TunnelManager ignored a VPN start request because iOS is still disconnecting the previous tunnel session."
      )
      return
    case .invalid, .disconnected:
      break
    @unknown default:
      break
    }

    let pendingStartStatus = pendingStartRuntimeStatus(from: fallbackStatus)
    _ = try? SharedStore.writeRuntimeStatusIfChanged(pendingStartStatus)
    invalidateControllerMetadataForUpcomingStart()

    guard let session = manager.connection as? NETunnelProviderSession else {
      throw TunnelManagerError.invalidSession
    }

    do {
      try session.startTunnel()
      _ = try? SharedStore.writeRuntimeStatusIfChanged(
        runtimeStatus(from: manager.connection.status, fallback: pendingStartStatus)
      )
    } catch {
      guard let vpnError = error as? NEVPNError else {
        throw error
      }

      switch vpnError.code {
      case .configurationDisabled, .configurationInvalid, .configurationStale:
        let repairedManager = try await configureManager(manager, enableForExplicitStart: true)
        guard let repairedSession = repairedManager.connection as? NETunnelProviderSession else {
          throw TunnelManagerError.invalidSession
        }
        do {
          try repairedSession.startTunnel()
          _ = try? SharedStore.writeRuntimeStatusIfChanged(
            runtimeStatus(from: repairedManager.connection.status, fallback: pendingStartStatus)
          )
        } catch {
          throw TunnelManagerError.nevpn(error)
        }
      default:
        throw TunnelManagerError.nevpn(error)
      }
    }
  }

  func stopTunnel() async throws {
    guard claimCommand(.stop) else {
      SharedStore.appendLog(
        level: "info",
        message: "TunnelManager ignored a duplicate VPN stop request because another tunnel command is still in flight."
      )
      return
    }
    defer { releaseCommand(.stop) }

    let manager = try await loadManager()
    switch manager.connection.status {
    case .invalid, .disconnected:
      _ = try? SharedStore.writeRuntimeStatusIfChanged(
        runtimeStatus(from: manager.connection.status, fallback: SharedStore.readRuntimeStatus())
      )
      SharedStore.appendLog(
        level: "info",
        message: "TunnelManager ignored a VPN stop request because the system tunnel is already \(statusText(for: manager.connection.status))."
      )
      return
    default:
      break
    }
    manager.connection.stopVPNTunnel()
    _ = try? SharedStore.writeRuntimeStatusIfChanged(
      runtimeStatus(from: manager.connection.status, fallback: SharedStore.readRuntimeStatus())
    )
  }

  func currentRuntimeObservation(
    fallback: RuntimeStatus = SharedStore.readRuntimeStatus()
  ) async -> RuntimeObservation {
    do {
      guard let manager = try await loadExistingManager() else {
        let sanitizedStatus = runtimeStatusWithoutSystemManager(fallback: fallback)
        clearControllerMetadataIfTunnelInactive(vpnStatus: .invalid)
        _ = try? SharedStore.writeRuntimeStatusIfChanged(sanitizedStatus)
        return RuntimeObservation(runtimeStatus: sanitizedStatus, extensionSnapshot: nil)
      }

      let vpnStatus = manager.connection.status
      let status = runtimeStatus(from: vpnStatus, fallback: fallback)
      logVPNStatusIfNeeded(vpnStatus, connection: manager.connection, runtimeStatus: status)

      if shouldQueryExtensionSnapshot(for: vpnStatus),
         let session = manager.connection as? NETunnelProviderSession {
        do {
          if let snapshot = try await sendSnapshotRequest(session: session) {
            _ = try? SharedStore.writeRuntimeStatusIfChanged(snapshot.runtimeStatus)
            return RuntimeObservation(runtimeStatus: snapshot.runtimeStatus, extensionSnapshot: snapshot)
          }
        } catch {
          SharedStore.appendLog(
            level: "warning",
            message: "TunnelManager could not fetch the live Packet Tunnel snapshot while the system VPN status was \(statusText(for: vpnStatus)): \(error.localizedDescription). Falling back to the system VPN state until the next probe succeeds."
          )
        }
      }

      clearControllerMetadataIfTunnelInactive(vpnStatus: vpnStatus)
      _ = try? SharedStore.writeRuntimeStatusIfChanged(status)
      return RuntimeObservation(runtimeStatus: status, extensionSnapshot: nil)
    } catch {
      let sanitizedStatus = runtimeStatusWithoutSystemManager(fallback: fallback)
      clearControllerMetadataIfTunnelInactive(vpnStatus: .invalid)
      _ = try? SharedStore.writeRuntimeStatusIfChanged(sanitizedStatus)
      return RuntimeObservation(runtimeStatus: sanitizedStatus, extensionSnapshot: nil)
    }
  }

  func currentRuntimeStatus(fallback: RuntimeStatus = SharedStore.readRuntimeStatus()) async -> RuntimeStatus {
    let observation = await currentRuntimeObservation(fallback: fallback)
    return observation.runtimeStatus
  }

  func currentExtensionSnapshot() async -> TunnelExtensionSnapshot? {
    do {
      guard let manager = try await loadExistingManager() else {
        return nil
      }
      guard shouldQueryExtensionSnapshot(for: manager.connection.status) else {
        return nil
      }
      guard let session = manager.connection as? NETunnelProviderSession else {
        return nil
      }

      return try await sendSnapshotRequest(session: session)
    } catch {
      return nil
    }
  }

  private func configureManager(_ manager: NETunnelProviderManager, enableForExplicitStart: Bool = false) async throws -> NETunnelProviderManager {
    let runtimeConfigPath = try SharedStore.runtimeConfigURL().path

    let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
    let existingConfiguration = proto.providerConfiguration as? [String: String] ?? [:]

    var requiresSave = false
    var didUpdateRuntimeConfigPath = false

    if proto.providerBundleIdentifier != providerBundleIdentifier {
      proto.providerBundleIdentifier = providerBundleIdentifier
      requiresSave = true
    }

    if proto.serverAddress != serverAddress {
      proto.serverAddress = serverAddress
      requiresSave = true
    }

    // Capture application traffic before the core makes its DIRECT/proxy
    // decision. A default route alone can be bypassed by scoped connections.
    // includeAllNetworks supersedes enforceRoutes and still has Apple's
    // documented system-service exceptions; this is not managed Always On VPN.
    if !proto.includeAllNetworks {
      proto.includeAllNetworks = true
      requiresSave = true
    }
    if proto.excludeLocalNetworks {
      proto.excludeLocalNetworks = false
      requiresSave = true
    }
    if proto.disconnectOnSleep {
      proto.disconnectOnSleep = false
      requiresSave = true
    }

    if existingConfiguration["runtimeConfigPath"] != runtimeConfigPath {
      proto.providerConfiguration = ["runtimeConfigPath": runtimeConfigPath]
      requiresSave = true
      didUpdateRuntimeConfigPath = true
    }

    if manager.protocolConfiguration == nil {
      manager.protocolConfiguration = proto
      requiresSave = true
    } else {
      manager.protocolConfiguration = proto
    }

    if manager.localizedDescription != localizedDescription {
      manager.localizedDescription = localizedDescription
      requiresSave = true
    }

    if enableForExplicitStart && manager.isEnabled == false {
      manager.isEnabled = true
      requiresSave = true
    }

    // Preserve an explicitly configured On Demand policy. Starting the app
    // neither enables it nor silently deletes the user's reconnect intent.

    if requiresSave {
      if didUpdateRuntimeConfigPath {
        SharedStore.appendLog(
          level: "debug",
          message: "TunnelManager updated the system VPN configuration to point at the latest published runtime config bundle."
        )
      }
      try await manager.saveToPreferences()
    }

    try await manager.loadFromPreferences()

    if enableForExplicitStart && manager.isEnabled == false {
      manager.isEnabled = true
      try await manager.saveToPreferences()
      try await manager.loadFromPreferences()
    }

    return manager
  }

  private func matchingManager(in managers: [NETunnelProviderManager]) -> NETunnelProviderManager? {
    managers.first(where: { manager in
      let proto = manager.protocolConfiguration as? NETunnelProviderProtocol
      return proto?.providerBundleIdentifier == providerBundleIdentifier
    })
  }

  private func loadExistingManager() async throws -> NETunnelProviderManager? {
    let managers = try await NETunnelProviderManager.loadAllFromPreferences()
    return matchingManager(in: managers)
  }

  func syncPublishedNetworkSettings(_ command: String = "apply-network-settings") async throws {
    guard let manager = try await loadExistingManager(),
          [.connected, .reasserting].contains(manager.connection.status),
          let session = manager.connection as? NETunnelProviderSession else { return }
    guard let response = try await sendProviderRequest(session: session, command: command, timeout: 32) else {
      throw TunnelManagerError.invalidSession
    }
    let reply = try JSONDecoder().decode(TunnelNetworkSettingsReply.self, from: response)
    if let error = reply.error {
      throw NSError(domain: "ClashParty.NetworkSettings", code: 1, userInfo: [NSLocalizedDescriptionKey: error])
    }
  }

  private func sendProviderRequest(session: NETunnelProviderSession, command: String, timeout: TimeInterval) async throws -> Data? {
    try await withCheckedThrowingContinuation { continuation in
      let waiter = ProviderReplyWaiter(continuation)
      let deadline = DispatchWorkItem { waiter.finish(.failure(NSError(domain: "ClashParty.ProviderMessage", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "The VPN tunnel did not respond in time."]))) }
      waiter.deadline = deadline
      DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout, execute: deadline)
      do { try session.sendProviderMessage(Data(command.utf8)) { waiter.finish(.success($0)) } }
      catch { waiter.finish(.failure(error)) }
    }
  }

  private func sendSnapshotRequest(session: NETunnelProviderSession) async throws -> TunnelExtensionSnapshot? {
    guard let response = try await sendProviderRequest(session: session, command: "snapshot", timeout: 2) else { return nil }
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    return try decoder.decode(TunnelExtensionSnapshot.self, from: response)
  }

  private func runtimeStatus(from vpnStatus: NEVPNStatus, fallback: RuntimeStatus) -> RuntimeStatus {
    let mappedState: RuntimeConnectionState
    let vpnConnected: Bool
    let isInStartupGracePeriod = fallback.state == .starting
      && (fallback.lastFailureReason?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
      && Date().timeIntervalSince(fallback.updatedAt) < startupGracePeriod

    switch vpnStatus {
    case .invalid:
      mappedState = isInStartupGracePeriod ? .starting : (fallback.state == .starting ? .failed : .idle)
      vpnConnected = false
    case .disconnected:
      mappedState = isInStartupGracePeriod ? .starting : (fallback.state == .idle ? .idle : .stopped)
      vpnConnected = false
    case .connecting, .reasserting:
      mappedState = .starting
      vpnConnected = false
    case .connected:
      mappedState = fallback.state == .failed && fallback.startupPhase == "trafficBlocked" ? .failed : .running
      vpnConnected = true
    case .disconnecting:
      mappedState = .stopping
      vpnConnected = false
    @unknown default:
      mappedState = fallback.state
      vpnConnected = fallback.vpnConnected
    }

    let phaseContext = terminalPhaseContext(
      state: mappedState,
      fallback: fallback
    )
    let nextStatus = RuntimeStatus(
      state: mappedState,
      mode: fallback.mode,
      vpnConnected: vpnConnected,
      fakeDnsEnabled: fallback.fakeDnsEnabled,
      activeProfileId: fallback.activeProfileId,
      dnsMode: fallback.dnsMode,
      backend: fallback.backend,
      dataPlaneReady: vpnConnected ? fallback.dataPlaneReady : false,
      startupPhase: phaseContext.phase,
      startupMessage: phaseContext.message,
      lastFailureReason: mappedState == .running ? nil : fallback.lastFailureReason,
      lastFailurePhase: mappedState == .running ? nil : fallback.lastFailurePhase,
      lastStopReason: (mappedState == .running || mappedState == .starting) ? nil : fallback.lastStopReason,
      updatedAt: fallback.updatedAt
    )
    return nextStatus.updatingTimestampIfNeeded(comparedTo: fallback)
  }

  private func terminalPhaseContext(
    state: RuntimeConnectionState,
    fallback: RuntimeStatus
  ) -> (phase: String, message: String) {
    switch state {
    case .idle, .stopped:
      return ("idle", L10n.string("runtime.phase.idle", "Runtime is idle."))
    case .failed:
      return (fallback.startupPhase, fallback.startupMessage)
    case .starting, .running, .stopping:
      return (fallback.startupPhase, fallback.startupMessage)
    }
  }

  private func shouldQueryExtensionSnapshot(for vpnStatus: NEVPNStatus) -> Bool {
    switch vpnStatus {
    case .connected, .connecting, .reasserting:
      return true
    case .invalid, .disconnected, .disconnecting:
      return false
    @unknown default:
      return false
    }
  }

  private func clearControllerMetadataIfTunnelInactive(vpnStatus: NEVPNStatus) {
    switch vpnStatus {
    case .connected, .connecting, .reasserting:
      return
    case .invalid, .disconnected, .disconnecting:
      break
    @unknown default:
      break
    }

    let metadata = SharedStore.readControllerMetadata()
    let hasPersistedControllerEndpoint =
      metadata.active
      || !metadata.listenAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      || !metadata.baseURLString.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      || !metadata.version.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty

    guard hasPersistedControllerEndpoint else { return }

    _ = try? SharedStore.writeControllerMetadataIfChanged(ControllerRuntimeMetadata())
    SharedStore.appendLog(
      level: "debug",
      message: "TunnelManager cleared stale controller metadata after the system VPN reported an inactive state, so app-side reloads and proxy actions will not target an old embedded controller endpoint during the startup grace window."
    )
  }

  private func logVPNStatusIfNeeded(
    _ vpnStatus: NEVPNStatus,
    connection: NEVPNConnection,
    runtimeStatus: RuntimeStatus
  ) {
    statusLogQueue.async { [weak self] in
      guard let self else { return }
      let previousStatus = self.lastLoggedVPNStatusRawValue.flatMap(NEVPNStatus.init(rawValue:))
      let diagnostic = TunnelStatusDiagnostic.make(
        statusText: self.statusText(for: vpnStatus),
        isInactive: vpnStatus == .disconnected || vpnStatus == .invalid,
        runtimeStatus: runtimeStatus,
        isInitialObservation: !self.hasObservedLiveTunnelContext
      )
      self.lastLoggedVPNStatusRawValue = vpnStatus.rawValue
      if runtimeStatus.liveTunnelContext || vpnStatus == .connected
        || vpnStatus == .connecting || vpnStatus == .reasserting || vpnStatus == .disconnecting {
        self.hasObservedLiveTunnelContext = true
      }
      if self.lastLoggedVPNDiagnostic != diagnostic {
        self.lastLoggedVPNDiagnostic = diagnostic
        SharedStore.appendLog(level: diagnostic.level, message: diagnostic.message)
      }

      // Ask only after an observed live-to-inactive transition. An initial
      // inactive observation could expose an unrelated historical system error.
      let wasLive = previousStatus == .connected || previousStatus == .connecting
        || previousStatus == .reasserting || previousStatus == .disconnecting
      guard wasLive, vpnStatus == .disconnected || vpnStatus == .invalid else { return }
      let observedAt = ISO8601DateFormatter().string(from: Date())
      connection.fetchLastDisconnectError { error in
        guard let error else {
          SharedStore.appendLog(
            level: "debug",
            message: "iOS reported no last disconnect error after the VPN transition observed at \(observedAt)."
          )
          return
        }
        let systemError = error as NSError
        SharedStore.appendLog(
          level: "warning",
          message: "iOS last disconnect error fetched after the VPN transition observed at \(observedAt): domain=\(systemError.domain) code=\(systemError.code) detail=\(systemError.localizedDescription) causeChain=\(TunnelDisconnectErrorSummary.describe(systemError))."
        )
      }
    }
  }

  private func pendingStartRuntimeStatus(from fallback: RuntimeStatus) -> RuntimeStatus {
    let preserveExistingStartContext = fallback.state == .starting
      && !fallback.startupPhase.isEmpty
      && fallback.startupPhase != "idle"
    return RuntimeStatus(
      state: .starting,
      mode: fallback.mode,
      vpnConnected: false,
      fakeDnsEnabled: fallback.fakeDnsEnabled,
      activeProfileId: fallback.activeProfileId,
      dnsMode: fallback.dnsMode,
      backend: fallback.backend,
      dataPlaneReady: false,
      startupPhase: preserveExistingStartContext ? fallback.startupPhase : "requestingSystemStart",
      startupMessage: preserveExistingStartContext && !fallback.startupMessage.isEmpty
        ? fallback.startupMessage
        : "App asked iOS to start the VPN tunnel and is waiting for the system connection state to change.",
      lastFailureReason: nil,
      lastFailurePhase: nil,
      lastStopReason: nil,
      updatedAt: .now
    )
  }

  private func runtimeStatusWithoutSystemManager(fallback: RuntimeStatus) -> RuntimeStatus {
    let mappedState: RuntimeConnectionState
    switch fallback.state {
    case .running, .starting, .stopping:
      mappedState = .stopped
    case .idle, .stopped, .failed:
      mappedState = fallback.state == .failed ? .failed : .idle
    }

    let nextStatus = RuntimeStatus(
      state: mappedState,
      mode: fallback.mode,
      vpnConnected: false,
      fakeDnsEnabled: fallback.fakeDnsEnabled,
      activeProfileId: fallback.activeProfileId,
      dnsMode: fallback.dnsMode,
      backend: fallback.backend,
      dataPlaneReady: false,
      startupPhase: mappedState == .failed ? fallback.startupPhase : "idle",
      startupMessage: mappedState == .failed ? fallback.startupMessage : "",
      lastFailureReason: mappedState == .failed ? fallback.lastFailureReason : nil,
      lastFailurePhase: mappedState == .failed ? fallback.lastFailurePhase : nil,
      lastStopReason: mappedState == .stopped
        ? (fallback.lastStopReason ?? "System VPN manager was unavailable, so the app reset the stale tunnel state.")
        : fallback.lastStopReason,
      updatedAt: fallback.updatedAt
    )
    return nextStatus.updatingTimestampIfNeeded(comparedTo: fallback)
  }

  private func invalidateControllerMetadataForUpcomingStart() {
    let metadata = SharedStore.readControllerMetadata()
    let hadPersistedControllerEndpoint =
      metadata.active
      || !metadata.listenAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      || !metadata.baseURLString.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      || !metadata.version.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty

    guard hadPersistedControllerEndpoint else { return }

    _ = try? SharedStore.writeControllerMetadataIfChanged(ControllerRuntimeMetadata())
    SharedStore.appendLog(
      level: "debug",
      message: "TunnelManager cleared previously persisted controller metadata before requesting a new VPN startup, so app-side proxy actions will wait for the new embedded controller endpoint."
    )
  }

  private func claimCommand(_ command: TunnelCommand) -> Bool {
    commandQueue.sync {
      guard activeCommand == nil else {
        return false
      }
      activeCommand = command
      return true
    }
  }

  private func releaseCommand(_ command: TunnelCommand) {
    commandQueue.sync {
      guard activeCommand == command else { return }
      activeCommand = nil
    }
  }

  private func statusText(for vpnStatus: NEVPNStatus) -> String {
    switch vpnStatus {
    case .invalid:
      return "invalid"
    case .disconnected:
      return "disconnected"
    case .connecting:
      return "connecting"
    case .connected:
      return "connected"
    case .reasserting:
      return "reasserting"
    case .disconnecting:
      return "disconnecting"
    @unknown default:
      return "unknown(\(vpnStatus.rawValue))"
    }
  }
}

enum TunnelManagerError: LocalizedError {
  case invalidSession
  case nevpn(Error)

  var errorDescription: String? {
    switch self {
    case .invalidSession:
      return L10n.string("error.tunnel.invalid_session", "Tunnel session is unavailable.")
    case .nevpn(let error):
      if let vpnError = error as? NEVPNError {
        switch vpnError.code {
        case .configurationDisabled:
          return L10n.string(
            "error.tunnel.configuration_disabled",
            "The VPN configuration is disabled on this device. Open VPN settings, allow the Clash Party configuration, and try again."
          )
        case .configurationInvalid:
          return L10n.string(
            "error.tunnel.configuration_invalid",
            "The VPN configuration is invalid. Re-save the tunnel configuration and verify the Packet Tunnel capability is enabled."
          )
        case .configurationStale:
          return L10n.string(
            "error.tunnel.configuration_stale",
            "The VPN configuration is stale. Clash Party will refresh it automatically; try starting the tunnel again."
          )
        case .connectionFailed:
          return L10n.string(
            "error.tunnel.connection_failed",
            "The Packet Tunnel extension started but failed to establish a VPN connection."
          )
        case .configurationReadWriteFailed:
          return L10n.string(
            "error.tunnel.configuration_rw_failed",
            "The system refused to read or write the VPN configuration. Check device management permissions and try again."
          )
        case .configurationUnknown:
          return L10n.string(
            "error.tunnel.configuration_unknown",
            "The system reported an unknown VPN configuration error."
          )
        @unknown default:
          break
        }
      }
      return error.localizedDescription
    }
  }
}

private final class ProviderReplyWaiter: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Data?, Error>?
  var deadline: DispatchWorkItem?
  init(_ continuation: CheckedContinuation<Data?, Error>) { self.continuation = continuation }
  func finish(_ result: Result<Data?, Error>) {
    lock.lock()
    let pending = continuation
    continuation = nil
    let timer = deadline
    deadline = nil
    lock.unlock()
    guard let pending else { return }
    timer?.cancel()
    pending.resume(with: result)
  }
}
