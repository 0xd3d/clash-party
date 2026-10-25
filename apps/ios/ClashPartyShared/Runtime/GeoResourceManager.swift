import Foundation

enum GeoResourceDownloadError: Error {
  case requiresCoreClient
}

public struct GeoResourceSeedSummary: Equatable {
  public var readyCount: Int
  public var seededCount: Int
  public var missingNames: [String]
  public var failedMessages: [String]

  public init(
    readyCount: Int = 0,
    seededCount: Int = 0,
    missingNames: [String] = [],
    failedMessages: [String] = []
  ) {
    self.readyCount = readyCount
    self.seededCount = seededCount
    self.missingNames = missingNames
    self.failedMessages = failedMessages
  }

  public var preparedCount: Int {
    readyCount + seededCount
  }
}

public enum GeoResourceManager {
  public static let resourceIDs: [String] = ["geoip", "geosite", "mmdb", "asn"]
  private static let fileManager = FileManager.default

  /// Extension-owned sockets are outside includeAllNetworks. Geo downloads in
  /// that process belong to the core's existing rule-aware HTTP client; this
  /// Swift helper only downloads in the main app, whose live VPN captures it.
  static func downloadInApplication(
    from url: URL,
    bundle: Bundle = .main,
    perform: ((URL) async throws -> (URL, URLResponse))? = nil
  ) async throws -> (URL, URLResponse) {
    guard bundle.bundleURL.pathExtension.lowercased() != "appex",
          bundle.object(forInfoDictionaryKey: "NSExtension") == nil else {
      throw GeoResourceDownloadError.requiresCoreClient
    }
    if let perform { return try await perform(url) }
    let session = URLSession(configuration: .ephemeral)
    defer { session.finishTasksAndInvalidate() }
    return try await session.download(from: url)
  }

  public static func hydrateStatuses(_ resources: [ResourceRecord]) -> [ResourceRecord] {
    let statuses = readStatusesByID()
    return resources.map { resource in
      guard let status = statuses[resource.id] else {
        return resource
      }

      var hydrated = resource
      hydrated.localStatus = status.localStatus
      hydrated.localSize = status.localSize
      hydrated.updatedAt = status.updatedAt
      hydrated.lastError = status.lastError
      return hydrated
    }
  }

  @discardableResult
  public static func seedBundledResourcesIfNeeded(from runtimeConfig: String) throws -> GeoResourceSeedSummary {
    try seedBundledResourcesIfNeeded(
      from: runtimeConfig,
      homeURL: SharedStore.runtimeHomeURL(),
      persistRuntimeStatus: true
    )
  }

  @discardableResult
  public static func seedBundledResourcesIfNeeded(
    from runtimeConfig: String,
    homeURL: URL
  ) throws -> GeoResourceSeedSummary {
    try seedBundledResourcesIfNeeded(
      from: runtimeConfig,
      homeURL: homeURL,
      persistRuntimeStatus: false
    )
  }

  @discardableResult
  private static func seedBundledResourcesIfNeeded(
    from runtimeConfig: String,
    homeURL: URL,
    persistRuntimeStatus: Bool
  ) throws -> GeoResourceSeedSummary {
    _ = try RoutingRuleResources.seedIfNeeded(runtimeConfig: runtimeConfig, homeURL: homeURL)
    let resources = builtInResources(from: runtimeConfig)
    guard !resources.isEmpty else { return GeoResourceSeedSummary() }

    try fileManager.createDirectory(at: homeURL, withIntermediateDirectories: true)
    var summary = GeoResourceSeedSummary()
    for resource in resources {
      let destinationURL = homeURL.appendingPathComponent(resource.path)
      if isUsableFile(at: destinationURL) {
        if persistRuntimeStatus {
          persistStatus(for: resource, status: "ready", fileURL: destinationURL)
        }
        summary.readyCount += 1
        continue
      }

      if seedResource(resource, to: destinationURL, persistRuntimeStatus: persistRuntimeStatus) {
        if persistRuntimeStatus {
          persistStatus(for: resource, status: "ready", fileURL: destinationURL)
        }
        summary.seededCount += 1
        continue
      }

      let message = "Missing usable bundled seed for \(resource.name) at GeoResources/\(resource.path)."
      if persistRuntimeStatus {
        persistStatus(for: resource, status: "missing-bundle", error: message)
      }
      summary.missingNames.append(resource.name)
      summary.failedMessages.append(message)
    }

    return summary
  }

  public static func refreshBuiltInResourcesIfNeeded(from runtimeConfig: String) async {
    let resources = builtInResources(from: runtimeConfig)
    guard !resources.isEmpty else { return }

    do {
      let homeURL = try SharedStore.runtimeHomeURL()
      for resource in resources {
        await refresh(resource, homeURL: homeURL)
      }
    } catch {
      persistStatus(
        for: resources,
        status: "unavailable",
        error: error.localizedDescription
      )
    }
  }

  private static func builtInResources(from runtimeConfig: String) -> [ResourceRecord] {
    let lines = runtimeConfig.components(separatedBy: .newlines)
    var insideGeoXURL = false
    var values: [String: String] = [:]

    for rawLine in lines {
      let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
      let indent = rawLine.prefix { $0 == " " }.count

      if indent == 0, trimmed == "geox-url:" {
        insideGeoXURL = true
        continue
      }

      if insideGeoXURL, indent == 0, !trimmed.isEmpty, trimmed.contains(":") {
        break
      }

      guard insideGeoXURL, indent >= 2 else { continue }
      let parts = trimmed.split(separator: ":", maxSplits: 1).map(String.init)
      guard parts.count == 2 else { continue }
      let key = parts[0].trimmingCharacters(in: .whitespaces)
      let value = parts[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
      guard resourceIDs.contains(key), !value.isEmpty else { continue }
      values[key] = value
    }

    let definitions: [(id: String, name: String, path: String)] = [
      ("geoip", "GeoIP Lite", "geoip-lite.dat"),
      ("geosite", "GeoSite", "geosite.dat"),
      ("mmdb", "Country Lite MMDB", "country-lite.mmdb"),
      ("asn", "ASN MMDB", "GeoLite2-ASN.mmdb")
    ]

    return definitions.compactMap { definition in
      guard let source = values[definition.id] else { return nil }
      return ResourceRecord(
        name: definition.name,
        kind: "geodata",
        behavior: "route database",
        source: source,
        path: definition.path,
        interval: "manual/background"
      )
    }
  }

  private static func refresh(_ resource: ResourceRecord, homeURL: URL) async {
    let destinationURL = homeURL.appendingPathComponent(resource.path)
    if isUsableFile(at: destinationURL) {
      persistStatus(for: resource, status: "ready", fileURL: destinationURL)
      return
    }

    if seedResource(resource, to: destinationURL, persistRuntimeStatus: true) {
      persistStatus(for: resource, status: "ready", fileURL: destinationURL)
      SharedStore.appendLog(
        level: "info",
        message: "Seeded \(resource.name) from the app bundle into \(destinationURL.path)."
      )
      return
    }

    guard let sourceURL = URL(string: resource.source) else {
      persistStatus(for: resource, status: "invalid-url", error: resource.source)
      return
    }

    persistStatus(for: resource, status: "downloading")
    do {
      let temporaryURL = homeURL.appendingPathComponent(".\(resource.path).download")
      let (downloadedURL, response) = try await downloadInApplication(from: sourceURL)
      if let response = response as? HTTPURLResponse, !(200...299).contains(response.statusCode) {
        throw URLError(.badServerResponse)
      }

      if fileManager.fileExists(atPath: temporaryURL.path) {
        try fileManager.removeItem(at: temporaryURL)
      }
      try fileManager.moveItem(at: downloadedURL, to: temporaryURL)
      guard isUsableFile(at: temporaryURL) else {
        throw URLError(.cannotDecodeContentData)
      }
      if fileManager.fileExists(atPath: destinationURL.path) {
        try fileManager.removeItem(at: destinationURL)
      }
      try fileManager.moveItem(at: temporaryURL, to: destinationURL)
      persistStatus(for: resource, status: "ready", fileURL: destinationURL)
      SharedStore.appendLog(
        level: "info",
        message: "Prepared \(resource.name) at \(destinationURL.path) for rule matching."
      )
    } catch GeoResourceDownloadError.requiresCoreClient {
      // Existing cache/bundle files were already checked above. Missing data
      // stays deferred until the core's routed client is ready; never retry via
      // a provider-originated URLSession or a direct fallback.
      persistStatus(for: resource, status: "deferred-to-core")
    } catch {
      let temporaryURL = homeURL.appendingPathComponent(".\(resource.path).download")
      if fileManager.fileExists(atPath: temporaryURL.path) {
        try? fileManager.removeItem(at: temporaryURL)
      }
      persistStatus(for: resource, status: "failed", error: error.localizedDescription)
      SharedStore.appendLog(
        level: "warning",
        message: "Could not prepare \(resource.name): \(error.localizedDescription)"
      )
    }
  }

  private static func seedResource(
    _ resource: ResourceRecord,
    to destinationURL: URL,
    persistRuntimeStatus: Bool
  ) -> Bool {
    guard let bundleURL = bundledResourceURL(for: resource),
          isUsableFile(at: bundleURL) else {
      return false
    }

    do {
      if fileManager.fileExists(atPath: destinationURL.path) {
        try fileManager.removeItem(at: destinationURL)
      }
      try fileManager.copyItem(at: bundleURL, to: destinationURL)
      return true
    } catch {
      if persistRuntimeStatus {
        persistStatus(for: resource, status: "seed-failed", error: error.localizedDescription)
      }
      return false
    }
  }

  private static func bundledResourceURL(for resource: ResourceRecord) -> URL? {
    let resourceURL = URL(fileURLWithPath: resource.path)
    let filename = resourceURL.deletingPathExtension().lastPathComponent
    let ext = resourceURL.pathExtension
    return Bundle.main.url(
      forResource: filename,
      withExtension: ext.isEmpty ? nil : ext,
      subdirectory: "GeoResources"
    )
  }

  private static func isUsableFile(at url: URL) -> Bool {
    guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]),
          values.isRegularFile == true,
          let size = values.fileSize else {
      return false
    }
    return size > 1024
  }

  private static func persistStatus(
    for resources: [ResourceRecord],
    status: String,
    error: String?
  ) {
    for resource in resources {
      persistStatus(for: resource, status: status, error: error)
    }
  }

  private static func persistStatus(
    for resource: ResourceRecord,
    status: String,
    fileURL: URL? = nil,
    error: String? = nil
  ) {
    var statuses = readStatusesByID()
    var updated = resource
    updated.localStatus = status
    updated.lastError = error
    updated.updatedAt = .now
    if let fileURL,
       let values = try? fileURL.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey]) {
      updated.localSize = Int64(values.fileSize ?? 0)
      updated.updatedAt = values.contentModificationDate ?? updated.updatedAt
    }
    statuses[resource.id] = updated
    writeStatuses(Array(statuses.values))
  }

  private static func readStatusesByID() -> [String: ResourceRecord] {
    guard let url = try? SharedStore.geoResourceStatusURL(),
          let data = try? Data(contentsOf: url) else {
      return [:]
    }
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    guard let records = try? decoder.decode([ResourceRecord].self, from: data) else { return [:] }
    return Dictionary(uniqueKeysWithValues: records.map { ($0.id, $0) })
  }

  private static func writeStatuses(_ statuses: [ResourceRecord]) {
    guard let url = try? SharedStore.geoResourceStatusURL() else { return }
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    guard let data = try? encoder.encode(statuses.sorted { $0.id < $1.id }) else { return }
    try? data.write(to: url, options: [.atomic])
  }
}
