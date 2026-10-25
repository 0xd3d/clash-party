import Foundation

final class ConsoleDiagnosticsWriter: @unchecked Sendable {
  static let shared = ConsoleDiagnosticsWriter()

  private let queue = DispatchQueue(
    label: "org.mihomo.party.ios.console.diagnostics-writer",
    qos: .utility
  )

  private init() {}

  func writeSharedStoreDiagnostics(_ diagnostics: SharedStoreAppGroupDiagnostics) {
    queue.async {
      Self.writeSharedStoreDiagnosticsToAppSandbox(diagnostics)
    }
  }

  func writeRuntimeDiagnostics(
    status: RuntimeStatus,
    snapshot: ConsoleRuntimeSnapshot,
    routeExplanations: [RouteExplanation],
    routeExplanationMetrics: RouteExplanationMetrics
  ) {
    queue.async {
      Self.writeRuntimeDiagnosticsToAppSandbox(
        status: status,
        snapshot: snapshot,
        routeExplanations: routeExplanations,
        routeExplanationMetrics: routeExplanationMetrics
      )
    }
  }

  func writeRouteExplanationsIfChanged(_ routeExplanations: [RouteExplanation]) {
    guard !routeExplanations.isEmpty else { return }
    queue.async {
      _ = try? SharedStore.writeRouteExplanationsIfChanged(routeExplanations)
    }
  }

  private static var localDiagnosticsDateEncodingStrategy: JSONEncoder.DateEncodingStrategy {
    .custom { date, encoder in
      let formatter = ISO8601DateFormatter()
      formatter.formatOptions = [.withInternetDateTime]
      formatter.timeZone = TimeZone.autoupdatingCurrent
      var container = encoder.singleValueContainer()
      try container.encode(formatter.string(from: date))
    }
  }

  private static func makeDiagnosticsEncoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    encoder.dateEncodingStrategy = localDiagnosticsDateEncodingStrategy
    return encoder
  }

  private static func writeSharedStoreDiagnosticsToAppSandbox(
    _ diagnostics: SharedStoreAppGroupDiagnostics
  ) {
    guard let documentsURL = FileManager.default.urls(
      for: .documentDirectory,
      in: .userDomainMask
    ).first else {
      return
    }

    let diagnosticsURL = documentsURL.appendingPathComponent(
      "clashparty-shared-store-diagnostics.json"
    )
    let encoder = makeDiagnosticsEncoder()
    do {
      let data = try encoder.encode(diagnostics)
      try data.write(to: diagnosticsURL, options: [.atomic])
    } catch {
      assertionFailure("Could not write shared store diagnostics: \(error.localizedDescription)")
    }
  }

  private struct RuntimeDiagnosticsSnapshot: Codable {
    var capturedAt: Date
    var providerHealth: TunnelHealthRecord?
    var previousProviderHealth: TunnelHealthRecord?
    var status: RuntimeStatus
    var extensionSnapshot: TunnelExtensionSnapshot
    var sharedStore: RuntimeSharedStoreDiagnosticsSnapshot
    var proxyGroups: [ProxyGroupSnapshot]
    var logs: [RuntimeLogEntry]
    var traffic: TrafficSnapshot
    var connections: [ConnectionSnapshot]
    var routeExplanations: [RouteExplanation]
    var routeExplanationMetrics: RouteExplanationMetrics
  }

  private struct RuntimeSharedStoreDiagnosticsSnapshot: Codable {
    var status: RuntimeStatus
    var controller: ControllerRuntimeMetadata
    var proxyGroups: [ProxyGroupSnapshot]
    var proxySelectionPreferences: [String: String]
    var logs: [RuntimeLogEntry]
    var traffic: TrafficSnapshot
    var connections: [ConnectionSnapshot]
    var routeExplanations: [RouteExplanation]
  }

  private static func writeRuntimeDiagnosticsToAppSandbox(
    status: RuntimeStatus,
    snapshot: ConsoleRuntimeSnapshot,
    routeExplanations: [RouteExplanation],
    routeExplanationMetrics: RouteExplanationMetrics
  ) {
    guard let documentsURL = FileManager.default.urls(
      for: .documentDirectory,
      in: .userDomainMask
    ).first else {
      return
    }

    let diagnosticsURL = documentsURL.appendingPathComponent(
      "clashparty-runtime-diagnostics.json"
    )
    let resolvedProxyGroups = snapshot.proxyGroups.isEmpty
      ? SharedStore.readProxyGroups()
      : snapshot.proxyGroups
    let resolvedLogs = snapshot.logs ?? SharedStore.readLogs()
    let healthStore = (try? SharedStore.containerURL()).map { TunnelHealthStore(directoryURL: $0.appendingPathComponent("runtime", isDirectory: true)) }
    let payload = RuntimeDiagnosticsSnapshot(
      capturedAt: .now,
      providerHealth: healthStore?.read(),
      previousProviderHealth: healthStore?.read(previous: true),
      status: status,
      extensionSnapshot: snapshot.extensionSnapshot,
      sharedStore: RuntimeSharedStoreDiagnosticsSnapshot(
        status: SharedStore.readRuntimeStatus(),
        controller: SharedStore.readControllerMetadata(),
        proxyGroups: SharedStore.readProxyGroups(),
        proxySelectionPreferences: SharedStore.readProxySelectionPreferences(),
        logs: SharedStore.readLogs(),
        traffic: SharedStore.readTraffic(),
        connections: SharedStore.readConnections(),
        routeExplanations: SharedStore.readRouteExplanations()
      ),
      proxyGroups: resolvedProxyGroups,
      logs: resolvedLogs,
      traffic: snapshot.traffic,
      connections: snapshot.connections,
      routeExplanations: routeExplanations,
      routeExplanationMetrics: routeExplanationMetrics
    )
    let encoder = makeDiagnosticsEncoder()
    do {
      let data = try encoder.encode(payload)
      try data.write(to: diagnosticsURL, options: [.atomic])
    } catch {
      assertionFailure("Could not write runtime diagnostics: \(error.localizedDescription)")
    }
  }
}
