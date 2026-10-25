import Darwin
import Foundation

public struct SharedStoreConfigurationBundle: Equatable {
  public var generation: String
  public var input: CompatibilityInput
  public var runtimeConfig: String
  public var runtimeConfigURL: URL
  public var createdAt: Date

  public init(
    generation: String,
    input: CompatibilityInput,
    runtimeConfig: String,
    runtimeConfigURL: URL,
    createdAt: Date
  ) {
    self.generation = generation
    self.input = input
    self.runtimeConfig = runtimeConfig
    self.runtimeConfigURL = runtimeConfigURL
    self.createdAt = createdAt
  }
}

public struct SharedStoreAppGroupDiagnostics: Codable, Equatable {
  public var appGroupIdentifier: String
  public var isAvailable: Bool
  public var containerPath: String?
  public var errorDescription: String?
  public var checkedPaths: [String]
  public var missingPaths: [String]

  public init(
    appGroupIdentifier: String,
    isAvailable: Bool,
    containerPath: String?,
    errorDescription: String?,
    checkedPaths: [String] = [],
    missingPaths: [String] = []
  ) {
    self.appGroupIdentifier = appGroupIdentifier
    self.isAvailable = isAvailable
    self.containerPath = containerPath
    self.errorDescription = errorDescription
    self.checkedPaths = checkedPaths
    self.missingPaths = missingPaths
  }
}

public enum SharedStore {
  public static let appGroupIdentifier: String = {
    let configured = Bundle.main.object(forInfoDictionaryKey: "ClashPartyAppGroupIdentifier") as? String
    let value = configured?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return value.isEmpty || value.contains("$(") ? "group.org.clashparty.ios" : value
  }()
  private static let fileManager = FileManager.default
  private static let directoryQueue = DispatchQueue(
    label: "org.mihomo.party.ios.shared-store.directories",
    qos: .utility
  )
  private static let logAppendQueue = DispatchQueue(
    label: "org.mihomo.party.ios.shared-store.log-append",
    qos: .utility
  )
  private static let logFlushDelay: DispatchTimeInterval = .milliseconds(750)
  private static let immediateLogFlushThreshold = 80
  private static let configurationBundleDirectoryName = "bundles"
  private static let configurationBundlePointerFileName = "current-bundle.json"
  private static let configurationBundleLockFileName = ".configuration-bundle.lock"
  private static var cachedContainerURL: URL?
  private static var directoriesPrepared = false
  private static var pendingLogEntries: [RuntimeLogEntry] = []
  private static var pendingLogLimit = 1200
  private static var logFlushScheduled = false

  private struct ConfigurationBundlePointer: Codable {
    var generation: String
    var createdAt: Date
  }

  private struct AppGroupHealthMarker: Codable {
    var appGroupIdentifier: String
    var containerPath: String
    var checkedAt: Date
  }

  private struct ConfigurationBundleURLs {
    var profileURL: URL
    var controlledConfigURL: URL
    var appConfigURL: URL
    var overrideYAMLURL: URL
    var overrideJavaScriptURL: URL
    var runtimeConfigURL: URL
  }

  private static func resolvedContainerURL() throws -> URL {
    if let cachedContainerURL {
      return cachedContainerURL
    }

    guard let url = fileManager.containerURL(
      forSecurityApplicationGroupIdentifier: appGroupIdentifier
    ) else {
      throw SharedStoreError.missingAppGroupContainer
    }
    cachedContainerURL = url
    return url
  }

  public static func containerURL() throws -> URL {
    try directoryQueue.sync {
      try resolvedContainerURL()
    }
  }

  public static func ensureDirectories() throws {
    try directoryQueue.sync {
      if directoriesPrepared {
        return
      }

      let base = try resolvedContainerURL()
      for folder in sharedDirectoryURLs(base: base) {
        try fileManager.createDirectory(at: folder, withIntermediateDirectories: true)
      }

      directoriesPrepared = true
    }
  }

  public static func appGroupDiagnostics() -> SharedStoreAppGroupDiagnostics {
    do {
      try ensureDirectories()
      let url = try containerURL()
      let expectedDirectoryURLs = sharedDirectoryURLs(base: url)
      let healthURL = appGroupHealthCheckURL(base: url)
      let checkedPaths = expectedDirectoryURLs.map(\.path) + [healthURL.path]
      let missingDirectories = missingDirectoryPaths(expectedDirectoryURLs)
      if !missingDirectories.isEmpty {
        return SharedStoreAppGroupDiagnostics(
          appGroupIdentifier: appGroupIdentifier,
          isAvailable: false,
          containerPath: url.path,
          errorDescription: "SharedStore could not create required App Group directories.",
          checkedPaths: checkedPaths,
          missingPaths: missingDirectories
        )
      }

      let marker = AppGroupHealthMarker(
        appGroupIdentifier: appGroupIdentifier,
        containerPath: url.path,
        checkedAt: .now
      )
      let data = try makeEncoder().encode(marker)
      try data.write(to: healthURL, options: [.atomic])
      let missingPaths = fileManager.fileExists(atPath: healthURL.path) ? [] : [healthURL.path]
      if !missingPaths.isEmpty {
        return SharedStoreAppGroupDiagnostics(
          appGroupIdentifier: appGroupIdentifier,
          isAvailable: false,
          containerPath: url.path,
          errorDescription: "SharedStore wrote the App Group health marker but could not verify it on disk.",
          checkedPaths: checkedPaths,
          missingPaths: missingPaths
        )
      }

      return SharedStoreAppGroupDiagnostics(
        appGroupIdentifier: appGroupIdentifier,
        isAvailable: true,
        containerPath: url.path,
        errorDescription: nil,
        checkedPaths: checkedPaths,
        missingPaths: []
      )
    } catch {
      return SharedStoreAppGroupDiagnostics(
        appGroupIdentifier: appGroupIdentifier,
        isAvailable: false,
        containerPath: nil,
        errorDescription: error.localizedDescription
      )
    }
  }

  private static func sharedDirectoryURLs(base: URL) -> [URL] {
    [
      base.appendingPathComponent("runtime", isDirectory: true),
      base.appendingPathComponent("configs", isDirectory: true),
      base.appendingPathComponent("configs/\(configurationBundleDirectoryName)", isDirectory: true),
      base.appendingPathComponent("imports", isDirectory: true),
      base.appendingPathComponent("exports", isDirectory: true)
    ]
  }

  private static func appGroupHealthCheckURL(base: URL) -> URL {
    base
      .appendingPathComponent("runtime", isDirectory: true)
      .appendingPathComponent("shared-store-health.json")
  }

  private static func missingDirectoryPaths(_ urls: [URL]) -> [String] {
    urls.compactMap { url in
      var isDirectory = ObjCBool(false)
      guard fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory),
            isDirectory.boolValue else {
        return url.path
      }
      return nil
    }
  }

  public static func runtimeConfigURL() throws -> URL {
    try readPublishedConfigurationBundle().runtimeConfigURL
  }

  public static func recordAppActivity(_ lease: AppActivityLease) throws {
    try ensureDirectories()
    try writeJSON(lease, to: containerURL().appendingPathComponent("runtime/app-activity.json"))
  }

  public static func isAppForeground(at now: Date = .now) -> Bool {
    guard let url = try? containerURL().appendingPathComponent("runtime/app-activity.json"),
          let lease = try? readJSON(AppActivityLease.self, from: url) else { return false }
    return lease.isFresh(at: now)
  }

  public static func runtimeHomeURL() throws -> URL {
    try ensureDirectories()
    let url = try containerURL().appendingPathComponent("runtime/mihomo-home", isDirectory: true)
    try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
    return url
  }

  public static func profileURL() throws -> URL {
    try legacyProfileURL()
  }

  public static func controlledConfigURL() throws -> URL {
    try legacyControlledConfigURL()
  }

  public static func appConfigURL() throws -> URL {
    try legacyAppConfigURL()
  }

  public static func overrideYAMLURL() throws -> URL {
    try legacyOverrideYAMLURL()
  }

  public static func overrideJavaScriptURL() throws -> URL {
    try legacyOverrideJavaScriptURL()
  }

  public static func runtimeStatusURL() throws -> URL {
    try ensureDirectories()
    return try containerURL().appendingPathComponent("runtime/status.json")
  }

  public static func controllerMetadataURL() throws -> URL {
    try ensureDirectories()
    return try containerURL().appendingPathComponent("runtime/controller.json")
  }

  public static func proxyGroupsURL() throws -> URL {
    try ensureDirectories()
    return try containerURL().appendingPathComponent("runtime/proxies.json")
  }

  public static func proxySelectionPreferencesURL() throws -> URL {
    try ensureDirectories()
    return try containerURL().appendingPathComponent("runtime/proxy-selection-preferences.json")
  }

  private static func runtimeHomeProxySelectionPreferencesURL() throws -> URL {
    try runtimeHomeURL().appendingPathComponent("proxy-selection-preferences.json")
  }

  public static func logsURL() throws -> URL {
    try ensureDirectories()
    return try containerURL().appendingPathComponent("runtime/logs.json")
  }

  public static func trafficURL() throws -> URL {
    try ensureDirectories()
    return try containerURL().appendingPathComponent("runtime/traffic.json")
  }

  public static func connectionsURL() throws -> URL {
    try ensureDirectories()
    return try containerURL().appendingPathComponent("runtime/connections.json")
  }

  public static func routeExplanationsURL() throws -> URL {
    try ensureDirectories()
    return try containerURL().appendingPathComponent("runtime/route-explanations.json")
  }

  public static func geoResourceStatusURL() throws -> URL {
    try ensureDirectories()
    return try containerURL().appendingPathComponent("runtime/geodata-resources.json")
  }

  public static func desktopRoutingSnapshotURL() throws -> URL {
    try ensureDirectories()
    return try containerURL().appendingPathComponent("runtime/desktop-routing-snapshot.json")
  }

  public static func profileLibraryURL() throws -> URL {
    try ensureDirectories()
    return try containerURL().appendingPathComponent("imports/profile-library.json")
  }

  public static func backupsDirectoryURL() throws -> URL {
    try ensureDirectories()
    let url = try containerURL().appendingPathComponent("imports/backups", isDirectory: true)
    try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
    return url
  }

  public static func exportsDirectoryURL() throws -> URL {
    try ensureDirectories()
    let url = try containerURL().appendingPathComponent("exports", isDirectory: true)
    try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
    return url
  }

  public static func fileModificationDate(at url: URL) -> Date? {
    (try? fileManager.attributesOfItem(atPath: url.path)[.modificationDate]) as? Date
  }

  @discardableResult
  public static func publishConfigurationBundle(
    input: CompatibilityInput,
    runtimeConfig: String
  ) throws -> SharedStoreConfigurationBundle {
    try withConfigurationBundleLock(mode: .exclusive) {
      let pointer = ConfigurationBundlePointer(
        generation: UUID().uuidString.lowercased(),
        createdAt: .now
      )
      let stagingDirectoryURL = try stagingConfigurationBundleURL(generation: pointer.generation)
      if fileManager.fileExists(atPath: stagingDirectoryURL.path) {
        try fileManager.removeItem(at: stagingDirectoryURL)
      }
      try fileManager.createDirectory(at: stagingDirectoryURL, withIntermediateDirectories: true)

      let urls = configurationBundleURLs(for: stagingDirectoryURL)
      try writeText(input.profileYaml, to: urls.profileURL)
      try writeText(input.controlledConfigYaml, to: urls.controlledConfigURL)
      try writeText(input.appConfigJson, to: urls.appConfigURL)
      try writeText(input.overrideYaml, to: urls.overrideYAMLURL)
      try writeText(input.overrideJavaScript, to: urls.overrideJavaScriptURL)
      try writeText(runtimeConfig, to: urls.runtimeConfigURL)

      let bundleDirectoryURL = try configurationBundleURL(generation: pointer.generation)
      if fileManager.fileExists(atPath: bundleDirectoryURL.path) {
        try fileManager.removeItem(at: bundleDirectoryURL)
      }
      try fileManager.moveItem(at: stagingDirectoryURL, to: bundleDirectoryURL)

      let pointerData = try makeEncoder().encode(pointer)
      try pointerData.write(to: currentConfigurationBundlePointerURL(), options: [.atomic])

      return try readPublishedConfigurationBundleUnlocked(pointer: pointer)
    }
  }

  public static func readPublishedConfigurationBundle() throws -> SharedStoreConfigurationBundle {
    try withConfigurationBundleLock(mode: .shared) {
      try readPublishedConfigurationBundleUnlocked()
    }
  }

  public static func readPublishedConfigurationBundle(
    forRuntimeConfigPath path: String
  ) throws -> SharedStoreConfigurationBundle {
    try readPublishedConfigurationBundle(forRuntimeConfigURL: URL(fileURLWithPath: path))
  }

  public static func readPublishedConfigurationBundle(
    forRuntimeConfigURL runtimeConfigURL: URL
  ) throws -> SharedStoreConfigurationBundle {
    try withConfigurationBundleLock(mode: .shared) {
      if let generation = try configurationGeneration(forRuntimeConfigURL: runtimeConfigURL) {
        let createdAt = currentBundleCreationDate(for: generation)
          ?? fileCreationDate(at: runtimeConfigURL.deletingLastPathComponent())
          ?? .now
        return try readPublishedConfigurationBundleUnlocked(
          pointer: ConfigurationBundlePointer(generation: generation, createdAt: createdAt)
        )
      }

      if fileManager.fileExists(atPath: runtimeConfigURL.path) {
        return try legacyConfigurationBundle(runtimeConfigURL: runtimeConfigURL)
      }

      return try readPublishedConfigurationBundleUnlocked()
    }
  }

  public static func writeCompatibilityInput(_ input: CompatibilityInput) throws {
    try ensureDirectories()
    try writeText(input.profileYaml, to: legacyProfileURL())
    try writeText(input.controlledConfigYaml, to: legacyControlledConfigURL())
    try writeText(input.appConfigJson, to: legacyAppConfigURL())
    try writeText(input.overrideYaml, to: legacyOverrideYAMLURL())
    try writeText(input.overrideJavaScript, to: legacyOverrideJavaScriptURL())
  }

  public static func readCompatibilityInput() throws -> CompatibilityInput {
    try readPublishedConfigurationBundle().input
  }

  public static func writeRuntimeConfig(_ content: String) throws {
    try writeText(content, to: legacyRuntimeConfigURL())
  }

  public static func writeRuntimeStatus(_ status: RuntimeStatus) throws {
    try writeJSON(status, to: runtimeStatusURL())
  }

  @discardableResult
  public static func writeRuntimeStatusIfChanged(_ status: RuntimeStatus) throws -> Bool {
    let url = try runtimeStatusURL()
    return try withFileLock(for: url, mode: .exclusive) {
      let existing = try readJSONValue(RuntimeStatus.self, from: url)
      guard existing != status else {
        return false
      }

      let data = try makeEncoder().encode(status)
      try data.write(to: url, options: [.atomic])
      return true
    }
  }

  public static func readRuntimeStatus() -> RuntimeStatus {
    (try? readJSON(RuntimeStatus.self, from: runtimeStatusURL())) ?? RuntimeStatus()
  }

  public static func writeControllerMetadata(_ metadata: ControllerRuntimeMetadata) throws {
    try writeJSON(metadata, to: controllerMetadataURL())
  }

  @discardableResult
  public static func writeControllerMetadataIfChanged(_ metadata: ControllerRuntimeMetadata) throws -> Bool {
    let url = try controllerMetadataURL()
    return try withFileLock(for: url, mode: .exclusive) {
      let existing = try readJSONValue(ControllerRuntimeMetadata.self, from: url)
      guard existing != metadata else {
        return false
      }

      let data = try makeEncoder().encode(metadata)
      try data.write(to: url, options: [.atomic])
      return true
    }
  }

  public static func readControllerMetadata() -> ControllerRuntimeMetadata {
    (try? readJSON(ControllerRuntimeMetadata.self, from: controllerMetadataURL()))
      ?? ControllerRuntimeMetadata()
  }

  public static func writeProxyGroups(_ groups: [ProxyGroupSnapshot]) throws {
    try writeJSON(groups, to: proxyGroupsURL())
  }

  @discardableResult
  public static func writeProxyGroupsIfChanged(_ groups: [ProxyGroupSnapshot]) throws -> Bool {
    let url = try proxyGroupsURL()
    return try withFileLock(for: url, mode: .exclusive) {
      let existing = try readJSONValue([ProxyGroupSnapshot].self, from: url) ?? []
      guard existing != groups else {
        return false
      }

      let data = try makeEncoder().encode(groups)
      try data.write(to: url, options: [.atomic])
      return true
    }
  }

  public static func readProxyGroups() -> [ProxyGroupSnapshot] {
    (try? readJSON([ProxyGroupSnapshot].self, from: proxyGroupsURL())) ?? []
  }

  public static func writeProxySelectionPreferences(_ preferences: [String: String]) throws {
    let runtimeURL = try proxySelectionPreferencesURL()
    let runtimeHomeURL = try runtimeHomeProxySelectionPreferencesURL()
    try writeJSON(preferences, to: runtimeURL)
    try writeJSON(preferences, to: runtimeHomeURL)
    appendLogNonBlocking(
      level: "debug",
      message: "Saved \(preferences.count) proxy selection preference(s) to \(runtimeURL.path) and \(runtimeHomeURL.path)."
    )
  }

  public static func readProxySelectionPreferences() -> [String: String] {
    if let runtimePreferences = try? readJSON([String: String].self, from: proxySelectionPreferencesURL()) {
      return runtimePreferences
    }
    return (try? readJSON([String: String].self, from: runtimeHomeProxySelectionPreferencesURL())) ?? [:]
  }

  public static func writeTraffic(_ traffic: TrafficSnapshot) throws {
    try writeJSON(traffic, to: trafficURL())
  }

  @discardableResult
  public static func writeTrafficIfChanged(_ traffic: TrafficSnapshot) throws -> Bool {
    let url = try trafficURL()
    return try withFileLock(for: url, mode: .exclusive) {
      let existing = try readJSONValue(TrafficSnapshot.self, from: url)
      guard existing?.equivalentIgnoringUpdatedAt(to: traffic) != true else {
        return false
      }

      let data = try makeEncoder().encode(traffic)
      try data.write(to: url, options: [.atomic])
      return true
    }
  }

  public static func readTraffic() -> TrafficSnapshot {
    (try? readJSON(TrafficSnapshot.self, from: trafficURL())) ?? TrafficSnapshot()
  }

  public static func writeLogs(_ logs: [RuntimeLogEntry]) throws {
    try writeJSON(logs, to: logsURL())
  }

  public static func readLogs() -> [RuntimeLogEntry] {
    (try? readJSON([RuntimeLogEntry].self, from: logsURL())) ?? []
  }

  public static func appendLog(
    level: String,
    message: String,
    limit: Int = 1200
  ) {
    appendLogSync(level: level, message: message, limit: limit)
  }

  public static func appendLogNonBlocking(
    level: String,
    message: String,
    limit: Int = 1200
  ) {
    let entry = RuntimeLogEntry(level: level, message: message)
    logAppendQueue.async {
      pendingLogEntries.append(entry)
      pendingLogLimit = max(pendingLogLimit, limit)

      if pendingLogEntries.count >= immediateLogFlushThreshold {
        flushPendingLogs()
      } else {
        scheduleLogFlush()
      }
    }
  }

  private static func appendLogSync(
    level: String,
    message: String,
    limit: Int
  ) {
    appendLogBatchSync([RuntimeLogEntry(level: level, message: message)], limit: limit)
  }

  private static func scheduleLogFlush() {
    guard !logFlushScheduled else {
      return
    }

    logFlushScheduled = true
    logAppendQueue.asyncAfter(deadline: .now() + logFlushDelay) {
      flushPendingLogs()
    }
  }

  private static func flushPendingLogs() {
    guard !pendingLogEntries.isEmpty else {
      logFlushScheduled = false
      return
    }

    let entries = pendingLogEntries
    let limit = pendingLogLimit
    pendingLogEntries.removeAll(keepingCapacity: true)
    logFlushScheduled = false
    appendLogBatchSync(entries, limit: limit)
  }

  private static func appendLogBatchSync(
    _ entries: [RuntimeLogEntry],
    limit: Int
  ) {
    guard !entries.isEmpty else {
      return
    }

    _ = try? mutateJSON([RuntimeLogEntry].self, at: logsURL(), defaultValue: []) { logs in
      logs.append(contentsOf: entries)
      if logs.count > limit {
        logs.removeFirst(logs.count - limit)
      }
    }
  }

  public static func clearLogs() throws {
    try writeLogs([])
  }

  public static func writeConnections(_ connections: [ConnectionSnapshot]) throws {
    try writeJSON(connections, to: connectionsURL())
  }

  @discardableResult
  public static func writeConnectionsIfChanged(_ connections: [ConnectionSnapshot]) throws -> Bool {
    let url = try connectionsURL()
    return try withFileLock(for: url, mode: .exclusive) {
      let existing = try readJSONValue([ConnectionSnapshot].self, from: url) ?? []
      guard existing != connections else {
        return false
      }

      let data = try makeEncoder().encode(connections)
      try data.write(to: url, options: [.atomic])
      return true
    }
  }

  public static func readConnections() -> [ConnectionSnapshot] {
    (try? readJSON([ConnectionSnapshot].self, from: connectionsURL())) ?? []
  }

  public static func writeRouteExplanations(_ explanations: [RouteExplanation]) throws {
    try writeJSON(explanations, to: routeExplanationsURL())
  }

  @discardableResult
  public static func writeRouteExplanationsIfChanged(_ explanations: [RouteExplanation]) throws -> Bool {
    let url = try routeExplanationsURL()
    return try withFileLock(for: url, mode: .exclusive) {
      let existing = try readJSONValue([RouteExplanation].self, from: url) ?? []
      guard existing != explanations else {
        return false
      }

      let data = try makeEncoder().encode(explanations)
      try data.write(to: url, options: [.atomic])
      return true
    }
  }

  public static func readRouteExplanations() -> [RouteExplanation] {
    guard let url = try? routeExplanationsURL(),
          fileManager.fileExists(atPath: url.path) else {
      return []
    }
    do {
      return try readJSON([RouteExplanation].self, from: url)
    } catch {
      _ = try? writeRouteExplanations([])
      appendLog(
        level: "warning",
        message: "Discarded stale route explanation cache because its schema is incomplete or unreadable. Fresh controller route decisions will repopulate it automatically."
      )
      return []
    }
  }

  public static func resetRuntimeSnapshots() throws {
    try writeRuntimeStatus(RuntimeStatus())
    try writeControllerMetadata(ControllerRuntimeMetadata())
    try writeProxyGroups([])
    try writeLogs([])
    try writeTraffic(TrafficSnapshot())
    try writeConnections([])
    try writeRouteExplanations([])
  }

  public static func readProfileLibrary() -> [ProfileBundleRecord] {
    guard let url = try? profileLibraryURL(),
          let records = try? readJSON([ProfileBundleRecord].self, from: url) else {
      return []
    }
    return records.sorted { $0.updatedAt > $1.updatedAt }
  }

  public static func saveProfileRecord(_ record: ProfileBundleRecord) throws {
    _ = try mutateJSON([ProfileBundleRecord].self, at: profileLibraryURL(), defaultValue: []) { records in
      if let index = records.firstIndex(where: { $0.id == record.id }) {
        records[index] = record
      } else {
        records.append(record)
      }
      records.sort { $0.updatedAt > $1.updatedAt }
    }
  }

  public static func deleteProfileRecord(id: String) throws {
    _ = try mutateJSON([ProfileBundleRecord].self, at: profileLibraryURL(), defaultValue: []) { records in
      records.removeAll { $0.id == id }
    }
  }

  public static func createBackupRecord(
    name: String,
    input: CompatibilityInput,
    runtimeStatus: RuntimeStatus
  ) throws -> BackupRecord {
    let record = BackupRecord(name: name, input: input, runtimeStatus: runtimeStatus)
    let fileURL = try backupsDirectoryURL().appendingPathComponent("\(record.id).json")
    try writeJSON(record, to: fileURL)
    return record
  }

  public static func readBackups() -> [BackupRecord] {
    guard let dir = try? backupsDirectoryURL(),
          let files = try? fileManager.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: nil
          ) else {
      return []
    }

    let records = files.compactMap { try? readJSON(BackupRecord.self, from: $0) }
    return records.sorted { $0.createdAt > $1.createdAt }
  }

  public static func restoreBackup(id: String) throws -> BackupRecord {
    let fileURL = try backupsDirectoryURL().appendingPathComponent("\(id).json")
    return try readJSON(BackupRecord.self, from: fileURL)
  }

  public static func deleteBackup(id: String) throws {
    let fileURL = try backupsDirectoryURL().appendingPathComponent("\(id).json")
    if fileManager.fileExists(atPath: fileURL.path) {
      try fileManager.removeItem(at: fileURL)
    }
  }

  public static func exportCurrentBundle(
    name: String,
    input: CompatibilityInput,
    runtimeStatus: RuntimeStatus,
    validationReport: CompatibilityValidationReport
  ) throws -> URL {
    let sanitizedName = name
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .replacingOccurrences(of: "/", with: "-")
      .replacingOccurrences(of: ":", with: "-")
    let fileName = sanitizedName.isEmpty ? "clash-party-ios-export" : sanitizedName
    let payload = ExportBundleRecord(
      name: fileName,
      exportedAt: .now,
      runtimeStatus: runtimeStatus,
      validationReport: validationReport,
      input: input
    )
    let url = try exportsDirectoryURL().appendingPathComponent("\(fileName).json")
    try writeJSON(payload, to: url)
    return url
  }

  private static func legacyConfigsDirectoryURL() throws -> URL {
    try ensureDirectories()
    return try containerURL().appendingPathComponent("configs", isDirectory: true)
  }

  private static func legacyRuntimeConfigURL() throws -> URL {
    try legacyConfigsDirectoryURL().appendingPathComponent("runtime-config.yaml")
  }

  private static func legacyProfileURL() throws -> URL {
    try legacyConfigsDirectoryURL().appendingPathComponent("profile.yaml")
  }

  private static func legacyControlledConfigURL() throws -> URL {
    try legacyConfigsDirectoryURL().appendingPathComponent("mihomo.yaml")
  }

  private static func legacyAppConfigURL() throws -> URL {
    try legacyConfigsDirectoryURL().appendingPathComponent("app-config.json")
  }

  private static func legacyOverrideYAMLURL() throws -> URL {
    try legacyConfigsDirectoryURL().appendingPathComponent("override.yaml")
  }

  private static func legacyOverrideJavaScriptURL() throws -> URL {
    try legacyConfigsDirectoryURL().appendingPathComponent("override.js")
  }

  private static func configurationBundlesDirectoryURL() throws -> URL {
    try ensureDirectories()
    let url = try containerURL()
      .appendingPathComponent("configs", isDirectory: true)
      .appendingPathComponent(configurationBundleDirectoryName, isDirectory: true)
    try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
    return url
  }

  private static func currentConfigurationBundlePointerURL() throws -> URL {
    try ensureDirectories()
    return try containerURL()
      .appendingPathComponent("configs", isDirectory: true)
      .appendingPathComponent(configurationBundlePointerFileName)
  }

  private static func configurationBundleLockURL() throws -> URL {
    try ensureDirectories()
    return try containerURL()
      .appendingPathComponent("configs", isDirectory: true)
      .appendingPathComponent(configurationBundleLockFileName)
  }

  private static func configurationBundleURL(generation: String) throws -> URL {
    try configurationBundlesDirectoryURL().appendingPathComponent(generation, isDirectory: true)
  }

  private static func stagingConfigurationBundleURL(generation: String) throws -> URL {
    try configurationBundlesDirectoryURL().appendingPathComponent(".staging-\(generation)", isDirectory: true)
  }

  private static func configurationBundleURLs(for bundleDirectoryURL: URL) -> ConfigurationBundleURLs {
    ConfigurationBundleURLs(
      profileURL: bundleDirectoryURL.appendingPathComponent("profile.yaml"),
      controlledConfigURL: bundleDirectoryURL.appendingPathComponent("mihomo.yaml"),
      appConfigURL: bundleDirectoryURL.appendingPathComponent("app-config.json"),
      overrideYAMLURL: bundleDirectoryURL.appendingPathComponent("override.yaml"),
      overrideJavaScriptURL: bundleDirectoryURL.appendingPathComponent("override.js"),
      runtimeConfigURL: bundleDirectoryURL.appendingPathComponent("runtime-config.yaml")
    )
  }

  private static func readPublishedConfigurationBundleUnlocked() throws -> SharedStoreConfigurationBundle {
    if let pointer = try readJSONValue(
      ConfigurationBundlePointer.self,
      from: currentConfigurationBundlePointerURL()
    ) {
      return try readPublishedConfigurationBundleUnlocked(pointer: pointer)
    }
    return try legacyConfigurationBundle()
  }

  private static func readPublishedConfigurationBundleUnlocked(
    pointer: ConfigurationBundlePointer
  ) throws -> SharedStoreConfigurationBundle {
    let bundleDirectoryURL = try configurationBundleURL(generation: pointer.generation)
    let urls = configurationBundleURLs(for: bundleDirectoryURL)

    guard fileManager.fileExists(atPath: urls.runtimeConfigURL.path) else {
      return try legacyConfigurationBundle()
    }

    return try SharedStoreConfigurationBundle(
      generation: pointer.generation,
      input: CompatibilityInput(
        profileYaml: readText(from: urls.profileURL),
        controlledConfigYaml: readText(from: urls.controlledConfigURL),
        appConfigJson: readText(from: urls.appConfigURL),
        overrideYaml: (try? readText(from: urls.overrideYAMLURL)) ?? "",
        overrideJavaScript: (try? readText(from: urls.overrideJavaScriptURL)) ?? ""
      ),
      runtimeConfig: readText(from: urls.runtimeConfigURL),
      runtimeConfigURL: urls.runtimeConfigURL,
      createdAt: pointer.createdAt
    )
  }

  private static func legacyConfigurationBundle(
    runtimeConfigURL: URL? = nil
  ) throws -> SharedStoreConfigurationBundle {
    let resolvedRuntimeConfigURL: URL
    if let runtimeConfigURL {
      resolvedRuntimeConfigURL = runtimeConfigURL
    } else {
      resolvedRuntimeConfigURL = try legacyRuntimeConfigURL()
    }
    return try SharedStoreConfigurationBundle(
      generation: "legacy",
      input: CompatibilityInput(
        profileYaml: readText(from: legacyProfileURL()),
        controlledConfigYaml: readText(from: legacyControlledConfigURL()),
        appConfigJson: readText(from: legacyAppConfigURL()),
        overrideYaml: (try? readText(from: legacyOverrideYAMLURL())) ?? "",
        overrideJavaScript: (try? readText(from: legacyOverrideJavaScriptURL())) ?? ""
      ),
      runtimeConfig: readText(from: resolvedRuntimeConfigURL),
      runtimeConfigURL: resolvedRuntimeConfigURL,
      createdAt: fileCreationDate(at: resolvedRuntimeConfigURL) ?? .now
    )
  }

  private static func configurationGeneration(forRuntimeConfigURL runtimeConfigURL: URL) throws -> String? {
    let bundlesDirectoryURL = try configurationBundlesDirectoryURL().standardizedFileURL
    let standardizedRuntimeConfigURL = runtimeConfigURL.standardizedFileURL
    let bundleDirectoryURL = standardizedRuntimeConfigURL.deletingLastPathComponent()

    guard standardizedRuntimeConfigURL.lastPathComponent == "runtime-config.yaml",
          bundleDirectoryURL.deletingLastPathComponent().path == bundlesDirectoryURL.path else {
      return nil
    }

    return bundleDirectoryURL.lastPathComponent
  }

  private static func currentBundleCreationDate(for generation: String) -> Date? {
    guard let pointerURL = try? currentConfigurationBundlePointerURL(),
          let pointer = try? readJSON(ConfigurationBundlePointer.self, from: pointerURL),
          pointer.generation == generation else {
      return nil
    }
    return pointer.createdAt
  }

  private static func fileCreationDate(at url: URL) -> Date? {
    (try? fileManager.attributesOfItem(atPath: url.path)[.creationDate]) as? Date
  }

  private static func writeJSON<T: Encodable>(_ value: T, to url: URL) throws {
    try withFileLock(for: url, mode: .exclusive) {
      let data = try makeEncoder().encode(value)
      try data.write(to: url, options: [.atomic])
    }
  }

  private static func readJSON<T: Decodable>(_ type: T.Type, from url: URL) throws -> T {
    try withFileLock(for: url, mode: .shared) {
      let data = try Data(contentsOf: url)
      return try makeDecoder().decode(type, from: data)
    }
  }

  @discardableResult
  private static func mutateJSON<T: Codable>(
    _ type: T.Type,
    at url: URL,
    defaultValue: @autoclosure () -> T,
    mutate: (inout T) throws -> Void
  ) throws -> T {
    try withFileLock(for: url, mode: .exclusive) {
      var value = try readJSONValue(type, from: url) ?? defaultValue()
      try mutate(&value)
      let data = try makeEncoder().encode(value)
      try data.write(to: url, options: [.atomic])
      return value
    }
  }

  private static func writeText(_ content: String, to url: URL) throws {
    try withFileLock(for: url, mode: .exclusive) {
      guard let data = content.data(using: .utf8) else {
        throw SharedStoreError.invalidTextEncoding(url.path)
      }
      try data.write(to: url, options: [.atomic])
    }
  }

  private static func readText(from url: URL) throws -> String {
    try withFileLock(for: url, mode: .shared) {
      let data = try Data(contentsOf: url)
      guard let text = String(data: data, encoding: .utf8) else {
        throw SharedStoreError.invalidTextEncoding(url.path)
      }
      return text
    }
  }

  private static func readJSONValue<T: Decodable>(_ type: T.Type, from url: URL) throws -> T? {
    guard fileManager.fileExists(atPath: url.path) else {
      return nil
    }
    let data = try Data(contentsOf: url)
    return try makeDecoder().decode(type, from: data)
  }

  private static func makeEncoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    encoder.dateEncodingStrategy = .iso8601
    return encoder
  }

  private static func makeDecoder() -> JSONDecoder {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    return decoder
  }

  private static func withFileLock<T>(
    for url: URL,
    mode: SharedStoreLockMode,
    _ body: () throws -> T
  ) throws -> T {
    let lockURL = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).lock")
    return try withLock(at: lockURL, mode: mode, body)
  }

  private static func withConfigurationBundleLock<T>(
    mode: SharedStoreLockMode,
    _ body: () throws -> T
  ) throws -> T {
    try withLock(at: configurationBundleLockURL(), mode: mode, body)
  }

  private static func withLock<T>(
    at lockURL: URL,
    mode: SharedStoreLockMode,
    _ body: () throws -> T
  ) throws -> T {
    try ensureDirectories()
    let descriptor = lockURL.path.withCString { pointer in
      open(pointer, O_CREAT | O_RDWR, mode_t(S_IRUSR | S_IWUSR))
    }
    if descriptor == -1 {
      throw SharedStoreError.fileLockUnavailable(lockURL.path, errno)
    }

    if flock(descriptor, mode.rawValue) != 0 {
      let errorCode = errno
      close(descriptor)
      throw SharedStoreError.fileLockUnavailable(lockURL.path, errorCode)
    }

    defer {
      flock(descriptor, LOCK_UN)
      close(descriptor)
    }

    return try body()
  }
}

@objc(SharedStoreObjCBridge)
public final class SharedStoreObjCBridge: NSObject {
  @objc(appendSharedLogLevel:message:)
  public static func appendSharedLog(level: String, message: String) {
    SharedStore.appendLog(level: level, message: message)
  }

  @objc(appendSharedLogNonBlockingLevel:message:)
  public static func appendSharedLogNonBlocking(level: String, message: String) {
    SharedStore.appendLogNonBlocking(level: level, message: message)
  }
}

private enum SharedStoreLockMode {
  case shared
  case exclusive

  var rawValue: Int32 {
    switch self {
    case .shared:
      return LOCK_SH
    case .exclusive:
      return LOCK_EX
    }
  }
}

private struct ExportBundleRecord: Codable {
  var name: String
  var exportedAt: Date
  var runtimeStatus: RuntimeStatus
  var validationReport: CompatibilityValidationReport
  var input: CompatibilityInput
}

public enum SharedStoreError: LocalizedError {
  case missingAppGroupContainer
  case invalidTextEncoding(String)
  case fileLockUnavailable(String, Int32)

  public var errorDescription: String? {
    switch self {
    case .missingAppGroupContainer:
      return L10n.string(
        "error.shared_store.missing_app_group",
        "App Group container is unavailable. Verify the entitlement and simulator or device setup."
      )
    case .invalidTextEncoding(let path):
      return L10n.format(
        "error.shared_store.invalid_text_encoding",
        "Failed to encode or decode UTF-8 text at %@.",
        path
      )
    case .fileLockUnavailable(let path, let code):
      return L10n.format(
        "error.shared_store.file_lock_unavailable",
        "Failed to acquire the shared store file lock for %@ (errno %d).",
        path,
        code
      )
    }
  }
}
