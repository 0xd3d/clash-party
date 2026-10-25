import Foundation

enum ConsoleRuntimeSnapshotScope {
  case fast
  case full

  var refreshesControllerIfNeeded: Bool {
    switch self {
    case .fast:
      return false
    case .full:
      return true
    }
  }
}

struct ConsoleRuntimeSnapshot: Equatable {
  let proxyGroups: [ProxyGroupSnapshot]
  let traffic: TrafficSnapshot
  let connections: [ConnectionSnapshot]
  let routeExplanations: [RouteExplanation]
  let extensionSnapshot: TunnelExtensionSnapshot
  let logs: [RuntimeLogEntry]?
  let savedProfiles: [ProfileBundleRecord]?
  let backups: [BackupRecord]?
  let version: String?
}

struct RuntimeDataPlaneSnapshot: Equatable {
  let traffic: TrafficSnapshot
  let connections: [ConnectionSnapshot]
}

struct ConsoleStartupWorkspace {
  let publishedBundle: SharedStoreConfigurationBundle?
  let proxySelectionPreferences: [String: String]
  let routeExplanations: [RouteExplanation]
}

private struct RuntimeCacheFingerprint: Equatable {
  var signature: String

  static func file(at url: URL) -> RuntimeCacheFingerprint? {
    guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path) else {
      return nil
    }
    let modificationDate = (attributes[.modificationDate] as? Date)?.timeIntervalSinceReferenceDate ?? -1
    let fileSize = attributes[.size] as? NSNumber
    return RuntimeCacheFingerprint(signature: "file:\(modificationDate):\(fileSize?.int64Value ?? -1)")
  }

  static func directory(at url: URL) -> RuntimeCacheFingerprint? {
    guard let urls = try? FileManager.default.contentsOfDirectory(
      at: url,
      includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey],
      options: [.skipsHiddenFiles]
    ) else {
      return nil
    }

    let entries = urls.map { itemURL -> String in
      let values = try? itemURL.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
      let modificationDate = values?.contentModificationDate?.timeIntervalSinceReferenceDate ?? -1
      let fileSize = values?.fileSize ?? -1
      return "\(itemURL.lastPathComponent):\(modificationDate):\(fileSize)"
    }
      .sorted()
      .joined(separator: "|")

    return RuntimeCacheFingerprint(signature: "dir:\(urls.count):\(entries)")
  }
}

private struct CachedRuntimeFile<Value> {
  var fingerprint: RuntimeCacheFingerprint?
  var value: Value
}

final class ConsoleRuntimeIO: @unchecked Sendable {
  private let snapshotRuntime: RuntimeBridge
  private let controlRuntime: RuntimeBridge
  private let delayRuntime: RuntimeBridge
  private let snapshotQueue = DispatchQueue(
    label: "org.mihomo.party.ios.console.runtime-snapshot-io",
    qos: .userInitiated
  )
  private let controlQueue = DispatchQueue(
    label: "org.mihomo.party.ios.console.runtime-control-io",
    qos: .userInitiated
  )
  private let delayQueue = DispatchQueue(
    label: "org.mihomo.party.ios.console.runtime-delay-io",
    qos: .userInitiated
  )
  private var cachedProxyGroups: CachedRuntimeFile<[ProxyGroupSnapshot]>?
  private var cachedLogs: CachedRuntimeFile<[RuntimeLogEntry]>?
  private var cachedTraffic: CachedRuntimeFile<TrafficSnapshot>?
  private var cachedConnections: CachedRuntimeFile<[ConnectionSnapshot]>?
  private var cachedRouteExplanations: CachedRuntimeFile<[RouteExplanation]>?
  private var cachedProfiles: CachedRuntimeFile<[ProfileBundleRecord]>?
  private var cachedBackups: CachedRuntimeFile<[BackupRecord]>?

  init(runtime: RuntimeBridge) {
    snapshotRuntime = runtime
    controlRuntime = RuntimeBridgeFactory.makeAppBridge()
    delayRuntime = RuntimeBridgeFactory.makeAppBridge()
  }

  func loadPersistedRuntimeStatus() async -> RuntimeStatus {
    await withCheckedContinuation { continuation in
      snapshotQueue.async {
        continuation.resume(returning: SharedStore.readRuntimeStatus())
      }
    }
  }

  func loadStartupWorkspace(routeExplanationLimit: Int) async -> ConsoleStartupWorkspace {
    await withCheckedContinuation { continuation in
      snapshotQueue.async {
        let explanations = Array(
          SharedStore.readRouteExplanations().prefix(routeExplanationLimit)
        )
        continuation.resume(
          returning: ConsoleStartupWorkspace(
            publishedBundle: try? SharedStore.readPublishedConfigurationBundle(),
            proxySelectionPreferences: SharedStore.readProxySelectionPreferences(),
            routeExplanations: explanations
          )
        )
      }
    }
  }

  func loadRuntimeSnapshot(
    currentStatus: RuntimeStatus,
    extensionSnapshot: TunnelExtensionSnapshot?,
    forceControllerSnapshotRefresh: Bool = false,
    scope: ConsoleRuntimeSnapshotScope = .full
  ) async -> ConsoleRuntimeSnapshot {
    await withCheckedContinuation { continuation in
      snapshotQueue.async {
        if scope == .fast {
          if forceControllerSnapshotRefresh {
            self.snapshotRuntime.refreshDataPlaneSnapshotNow()
          }
        } else if forceControllerSnapshotRefresh {
          self.snapshotRuntime.refreshDataPlaneSnapshotNow()
        } else if scope.refreshesControllerIfNeeded && Self.shouldRefreshControllerSnapshot(
          currentStatus: currentStatus,
          extensionSnapshot: extensionSnapshot
        ) {
          self.snapshotRuntime.refreshSnapshotIfNeeded()
        }
        if scope == .full {
          self.refreshProxyGroupsSnapshotForRunningRuntimeIfNeeded(
            currentStatus: currentStatus,
            extensionSnapshot: extensionSnapshot
          )
        }
        let controllerMetadata = SharedStore.readControllerMetadata()
        let resolvedExtensionSnapshot = extensionSnapshot
          ?? TunnelExtensionSnapshot(
            runtimeStatus: currentStatus,
            startupPhase: currentStatus.startupPhase,
            startupMessage: currentStatus.startupMessage,
            lastFailureReason: currentStatus.lastFailureReason,
            lastFailurePhase: currentStatus.lastFailurePhase,
            lastStopReason: currentStatus.lastStopReason,
            controllerAddress: controllerMetadata.listenAddress.isEmpty ? nil : controllerMetadata.listenAddress,
            phaseUpdatedAt: currentStatus.updatedAt,
            running: currentStatus.state == .running
          )
        let dataPlaneSnapshot = self.cachedDataPlaneSnapshotValue(
          forceReload: forceControllerSnapshotRefresh
        )
        let liveConnections = Self.shouldExposeLiveConnections(
          currentStatus: currentStatus,
          extensionSnapshot: resolvedExtensionSnapshot
        ) ? dataPlaneSnapshot.connections : []

        let proxyGroups = scope == .full
          ? self.cachedProxyGroupsValue()
          : (self.cachedProxyGroups?.value ?? [])
        let runtimeVersion = scope == .full ? self.snapshotRuntime.version() : ""
        let displayVersion: String? = scope == .full
          ? (
            runtimeVersion.isEmpty
              ? L10n.string("runtime.version.uninitialized", "Uninitialized")
              : runtimeVersion
          )
          : nil

        continuation.resume(
          returning: ConsoleRuntimeSnapshot(
            proxyGroups: proxyGroups,
            traffic: dataPlaneSnapshot.traffic,
            connections: liveConnections,
            routeExplanations: self.cachedRouteExplanationsValue(forceReload: forceControllerSnapshotRefresh),
            extensionSnapshot: resolvedExtensionSnapshot,
            logs: scope == .full ? self.cachedLogsValue() : nil,
            savedProfiles: scope == .full ? self.cachedProfilesValue() : nil,
            backups: scope == .full ? self.cachedBackupsValue() : nil,
            version: displayVersion
          )
        )
      }
    }
  }

  private func cachedProxyGroupsValue() -> [ProxyGroupSnapshot] {
    cachedValue(
      cache: &cachedProxyGroups,
      url: try? SharedStore.proxyGroupsURL(),
      fallback: [],
      load: { self.snapshotRuntime.getProxies() }
    )
  }

  private static func shouldExposeLiveConnections(
    currentStatus: RuntimeStatus,
    extensionSnapshot: TunnelExtensionSnapshot
  ) -> Bool {
    currentStatus.state == .running
      || currentStatus.liveTunnelContext
      || extensionSnapshot.running
      || extensionSnapshot.startupAcceptedForAppOperations
  }

  private func refreshProxyGroupsSnapshotForRunningRuntimeIfNeeded(
    currentStatus: RuntimeStatus,
    extensionSnapshot: TunnelExtensionSnapshot?
  ) {
    let shouldHaveRuntimeGroups =
      currentStatus.state == .running
      || currentStatus.liveTunnelContext
      || extensionSnapshot?.running == true
      || extensionSnapshot?.startupAcceptedForAppOperations == true

    guard shouldHaveRuntimeGroups else { return }

    let groups = cachedProxyGroupsValue()
    guard groups.isEmpty else { return }

    snapshotRuntime.refreshProxyGroupsSnapshotIfNeeded()
    cachedProxyGroups = nil
  }

  private func cachedLogsValue() -> [RuntimeLogEntry] {
    cachedValue(
      cache: &cachedLogs,
      url: try? SharedStore.logsURL(),
      fallback: [],
      load: { self.snapshotRuntime.subscribeLogs() }
    )
  }

  private func cachedTrafficValue() -> TrafficSnapshot {
    cachedValue(
      cache: &cachedTraffic,
      url: try? SharedStore.trafficURL(),
      fallback: .init(),
      load: { self.snapshotRuntime.subscribeTraffic() }
    )
  }

  private func cachedDataPlaneSnapshotValue(forceReload: Bool = false) -> RuntimeDataPlaneSnapshot {
    let connections = cachedConnectionsValue(forceReload: forceReload)
    let persistedTraffic = cachedTrafficValue()
    return RuntimeDataPlaneSnapshot(traffic: persistedTraffic, connections: connections)
  }

  private func cachedConnectionsValue(forceReload: Bool = false) -> [ConnectionSnapshot] {
    cachedValue(
      cache: &cachedConnections,
      url: try? SharedStore.connectionsURL(),
      fallback: [],
      forceReload: forceReload,
      load: { self.snapshotRuntime.getConnections() }
    )
  }

  private func cachedRouteExplanationsValue(forceReload: Bool = false) -> [RouteExplanation] {
    cachedValue(
      cache: &cachedRouteExplanations,
      url: try? SharedStore.routeExplanationsURL(),
      fallback: [],
      forceReload: forceReload,
      load: { SharedStore.readRouteExplanations() }
    )
  }

  private func cachedProfilesValue() -> [ProfileBundleRecord] {
    cachedValue(
      cache: &cachedProfiles,
      url: try? SharedStore.profileLibraryURL(),
      fallback: [],
      load: { SharedStore.readProfileLibrary() }
    )
  }

  private func cachedBackupsValue() -> [BackupRecord] {
    cachedDirectoryValue(
      cache: &cachedBackups,
      url: try? SharedStore.backupsDirectoryURL(),
      fallback: [],
      load: { SharedStore.readBackups() }
    )
  }

  private func cachedValue<Value>(
    cache: inout CachedRuntimeFile<Value>?,
    url: URL?,
    fallback: @autoclosure () -> Value,
    forceReload: Bool = false,
    load: () -> Value
  ) -> Value {
    guard let url else {
      return cache?.value ?? fallback()
    }

    let fingerprint = RuntimeCacheFingerprint.file(at: url)
    if !forceReload, let cache, cache.fingerprint == fingerprint {
      return cache.value
    }

    let value = fingerprint == nil ? fallback() : load()
    cache = CachedRuntimeFile(fingerprint: fingerprint, value: value)
    return value
  }

  private func cachedDirectoryValue<Value>(
    cache: inout CachedRuntimeFile<Value>?,
    url: URL?,
    fallback: @autoclosure () -> Value,
    load: () -> Value
  ) -> Value {
    guard let url else {
      return cache?.value ?? fallback()
    }

    let fingerprint = RuntimeCacheFingerprint.directory(at: url)
    if let cache, cache.fingerprint == fingerprint {
      return cache.value
    }

    let value = fingerprint == nil ? fallback() : load()
    cache = CachedRuntimeFile(fingerprint: fingerprint, value: value)
    return value
  }

  func selectProxy(group: String, proxy: String) async throws {
    try await withCheckedThrowingContinuation { continuation in
      controlQueue.async {
        do {
          try self.controlRuntime.selectProxy(group: group, proxy: proxy)
          continuation.resume(returning: ())
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  func measureProxyDelay(
    name: String,
    url: String,
    timeoutMilliseconds: Int
  ) async throws -> Int {
    try await withCheckedThrowingContinuation { continuation in
      delayQueue.async {
        do {
          let delay = try self.delayRuntime.getProxyDelay(
            name: name,
            url: url,
            timeoutMilliseconds: timeoutMilliseconds
          )
          continuation.resume(returning: delay)
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  func measureGroupDelays(
    name: String,
    url: String,
    timeoutMilliseconds: Int
  ) async throws -> [String: Int] {
    try await withCheckedThrowingContinuation { continuation in
      delayQueue.async {
        do {
          let delays = try self.delayRuntime.getGroupDelays(
            name: name,
            url: url,
            timeoutMilliseconds: timeoutMilliseconds
          )
          continuation.resume(returning: delays)
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  func reloadRuntime() async throws {
    try await TunnelManager.shared.syncPublishedNetworkSettings()
    do {
      try await reloadCoreRuntime()
    } catch {
      try? await TunnelManager.shared.syncPublishedNetworkSettings("restore-network-settings")
      throw error
    }
    // A failed commit acknowledgement must not restore old system settings
    // after the core has already accepted the new configuration.
    try await TunnelManager.shared.syncPublishedNetworkSettings("commit-network-settings")
  }

  private func reloadCoreRuntime() async throws {
    try await withCheckedThrowingContinuation { continuation in
      controlQueue.async {
        do {
          try self.controlRuntime.reload()
          continuation.resume(returning: ())
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  private static func shouldRefreshControllerSnapshot(
    currentStatus: RuntimeStatus,
    extensionSnapshot: TunnelExtensionSnapshot?
  ) -> Bool {
    if currentStatus.state == .starting || currentStatus.startupAcceptedForControllerWarmup {
      return true
    }
    if currentStatus.state == .running || currentStatus.liveTunnelContext {
      return true
    }
    if extensionSnapshot?.startupAcceptedForAppOperations == true || extensionSnapshot?.running == true {
      return true
    }
    return false
  }
}
