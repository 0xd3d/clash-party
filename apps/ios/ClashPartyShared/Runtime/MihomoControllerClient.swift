import Foundation

enum MihomoControllerClientError: LocalizedError {
  case invalidMetadata
  case invalidResponse
  case httpError(Int, String)
  case timeout

  var errorDescription: String? {
    switch self {
    case .invalidMetadata:
      return L10n.string("error.controller.invalid_metadata", "Runtime controller metadata is missing.")
    case .invalidResponse:
      return L10n.string("error.controller.invalid_response", "Runtime controller returned an invalid response.")
    case .httpError(let status, let body):
      return L10n.format(
        "error.controller.http",
        "Runtime controller request failed with HTTP %d.\n%@",
        status,
        body
      )
    case .timeout:
      return L10n.string("error.controller.timeout", "Runtime controller request timed out.")
    }
  }
}

final class MihomoControllerClient {
  private let metadata: ControllerRuntimeMetadata
  private let session: URLSession

  init(metadata: ControllerRuntimeMetadata, session: URLSession = .shared) {
    self.metadata = metadata
    self.session = session
  }

  var baseURLStringForLogging: String {
    metadata.baseURLString
  }

  func fetchVersion() throws -> String {
    let payload = try requestJSON(path: "/version")
    return payload["version"] as? String ?? metadata.version
  }

  func probeVersion(timeout: TimeInterval) throws -> String {
    let payload = try requestJSON(path: "/version", timeout: timeout)
    return payload["version"] as? String ?? metadata.version
  }

  func fetchRuntimeStatus(
    fallback: RuntimeStatus
  ) throws -> RuntimeStatus {
    let payload = try requestJSON(path: "/configs")
    let runtimeState: RuntimeConnectionState = fallback.vpnConnected ? .running : fallback.state
    let startupPhase = fallback.vpnConnected ? "running" : fallback.startupPhase
    let startupMessage = fallback.vpnConnected
      ? L10n.string("runtime.phase.running", "Runtime is running.")
      : fallback.startupMessage
    let nextStatus = RuntimeStatus(
      state: runtimeState,
      mode: payload["mode"] as? String ?? fallback.mode,
      vpnConnected: fallback.vpnConnected,
      fakeDnsEnabled: fallback.fakeDnsEnabled,
      activeProfileId: fallback.activeProfileId,
      dnsMode: fallback.dnsMode,
      backend: fallback.backend,
      dataPlaneReady: fallback.dataPlaneReady,
      startupPhase: startupPhase,
      startupMessage: startupMessage,
      lastFailureReason: fallback.vpnConnected ? nil : fallback.lastFailureReason,
      lastFailurePhase: fallback.vpnConnected ? nil : fallback.lastFailurePhase,
      lastStopReason: fallback.vpnConnected ? nil : fallback.lastStopReason,
      updatedAt: fallback.updatedAt
    )
    return nextStatus.updatingTimestampIfNeeded(comparedTo: fallback)
  }

  func fetchProxyGroups() throws -> [ProxyGroupSnapshot] {
    let payload = try requestJSON(path: "/proxies")
    guard let proxies = payload["proxies"] as? [String: Any] else {
      throw MihomoControllerClientError.invalidResponse
    }

    let groups = proxies.compactMap { name, value -> ProxyGroupSnapshot? in
      guard let details = value as? [String: Any],
            let all = details["all"] as? [String] else {
        return nil
      }

      let uniqueOptions = ProxyNameNormalizer.uniqueDisplayOptions(from: all)
      let selected = details["now"] as? String
        ?? details["history"] as? String
        ?? uniqueOptions.first
      let type = details["type"] as? String
      let testURL = details["testUrl"] as? String
        ?? details["url"] as? String
        ?? details["test-url"] as? String
      return ProxyGroupSnapshot(
        name: name,
        selected: selected,
        all: uniqueOptions,
        type: type,
        testURL: testURL
      )
    }

    return groups.sorted { $0.name.localizedCompare($1.name) == .orderedAscending }
  }

  func selectProxy(group: String, proxy: String) throws {
    try requestNoContent(
      path: "/proxies/\(escaped(group))",
      method: "PUT",
      body: ["name": proxy]
    )
  }

  func fetchProxyDelay(
    name: String,
    url: String,
    timeoutMilliseconds: Int
  ) throws -> Int {
    let payload = try requestJSON(
      path: "/proxies/\(escaped(name))/delay",
      queryItems: delayQueryItems(url: url, timeoutMilliseconds: timeoutMilliseconds),
      timeout: delayRequestTimeout(for: timeoutMilliseconds)
    )
    guard let delay = intValue(payload["delay"]) else {
      throw MihomoControllerClientError.invalidResponse
    }
    return delay
  }

  func fetchGroupDelays(
    name: String,
    url: String,
    timeoutMilliseconds: Int
  ) throws -> [String: Int] {
    let payload = try requestJSONObject(
      path: "/group/\(escaped(name))/delay",
      queryItems: delayQueryItems(url: url, timeoutMilliseconds: timeoutMilliseconds),
      timeout: delayRequestTimeout(for: timeoutMilliseconds)
    )
    guard let dictionary = payload as? [String: Any] else {
      throw MihomoControllerClientError.invalidResponse
    }

    var measurements: [String: Int] = [:]
    for (proxyName, value) in dictionary {
      if let delay = intValue(value) {
        measurements[proxyName] = delay
      }
    }
    return measurements
  }

  func reloadConfig(payload: String) throws {
    try requestNoContent(
      path: "/configs",
      queryItems: [URLQueryItem(name: "force", value: "true")],
      method: "PUT",
      body: ["payload": payload]
    )
  }

  func fetchConnections() throws -> [ConnectionSnapshot] {
    try fetchConnectionsSnapshot().connections
  }

  func fetchRouteDecisions() throws -> [RouteDecisionSnapshot] {
    struct Payload: Decodable {
      var decisions: [RouteDecisionSnapshot]
    }

    let data = try requestData(path: "/route-decisions")
    do {
      return try JSONDecoder().decode(Payload.self, from: data).decisions
    } catch {
      throw MihomoControllerClientError.invalidResponse
    }
  }

  func fetchConnectionsSnapshot() throws -> RuntimeConnectionSnapshot {
    let payload = try requestJSON(path: "/connections")
    let controllerUploadTotal = int64Value(payload["uploadTotal"])
    let controllerDownloadTotal = int64Value(payload["downloadTotal"])
    guard let rawConnections = payload["connections"] as? [[String: Any]] else {
      return RuntimeConnectionSnapshot(
        uploadTotal: controllerUploadTotal,
        downloadTotal: controllerDownloadTotal
      )
    }

    let connections = rawConnections.map { item in
      let metadata = item["metadata"] as? [String: Any]
      let chains = item["chains"] as? [String] ?? []
      let chain = chains.joined(separator: " -> ")
      let destinationIP = stringValue(metadata?["destinationIP"]) ?? ""
      let destinationPort = intValue(metadata?["destinationPort"])
      let sourceIP = stringValue(metadata?["sourceIP"]) ?? ""
      let sourcePort = intValue(metadata?["sourcePort"])
      let metadataHost = stringValue(metadata?["host"]) ?? ""
      let sniffHost = stringValue(metadata?["sniffHost"]) ?? ""
      let host = firstNonEmpty([
        sniffHost,
        metadataHost,
        stringValue(metadata?["remoteDestination"]),
        endpointDisplay(ip: destinationIP, port: destinationPort),
        stringValue(item["id"]),
        endpointDisplay(ip: sourceIP, port: sourcePort)
      ]) ?? "Pending route"
      let rule = stringValue(item["rule"]) ?? stringValue(item["rulePayload"]) ?? "MATCH"
      let rulePayload = stringValue(item["rulePayload"]) ?? ""
      return ConnectionSnapshot(
        id: item["id"] as? String ?? UUID().uuidString,
        host: host,
        chain: chain.isEmpty ? "DIRECT" : chain,
        chainComponents: chains,
        rule: rule,
        rulePayload: rulePayload,
        metadata: ConnectionSnapshot.Metadata(
          network: stringValue(metadata?["network"]) ?? "",
          type: stringValue(metadata?["type"]) ?? "",
          sourceIP: sourceIP,
          sourcePort: sourcePort,
          destinationIP: destinationIP,
          destinationPort: destinationPort,
          destinationIPASN: stringValue(metadata?["destinationIPASN"]) ?? "",
          host: metadataHost,
          sniffHost: sniffHost
        ),
        upload: firstNonZeroInt64([item["upload"], item["uploadTotal"]]),
        download: firstNonZeroInt64([item["download"], item["downloadTotal"]])
      )
    }

    let uploadTotal = controllerUploadTotal > 0
      ? controllerUploadTotal
      : connections.reduce(Int64(0)) { $0 + $1.upload }
    let downloadTotal = controllerDownloadTotal > 0
      ? controllerDownloadTotal
      : connections.reduce(Int64(0)) { $0 + $1.download }

    return RuntimeConnectionSnapshot(
      connections: connections,
      uploadTotal: uploadTotal,
      downloadTotal: downloadTotal
    )
  }

  func makeWebSocketTask(path: String, queryItems: [URLQueryItem] = []) throws -> URLSessionWebSocketTask {
    guard var components = URLComponents(
      url: try baseURL().appendingPathComponent(normalizedPath(path)),
      resolvingAgainstBaseURL: false
    ) else {
      throw MihomoControllerClientError.invalidMetadata
    }

    let tokenItem = URLQueryItem(name: "token", value: metadata.secret)
    components.queryItems = queryItems + [tokenItem]
    guard let url = components.url else {
      throw MihomoControllerClientError.invalidMetadata
    }

    var request = URLRequest(url: url)
    request.timeoutInterval = 15
    return session.webSocketTask(with: request)
  }

  private func requestJSON(
    path: String,
    queryItems: [URLQueryItem] = [],
    timeout: TimeInterval? = nil
  ) throws -> [String: Any] {
    let data = try requestData(path: path, queryItems: queryItems, timeout: timeout)
    guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw MihomoControllerClientError.invalidResponse
    }
    return json
  }

  private func requestJSONObject(
    path: String,
    queryItems: [URLQueryItem] = [],
    timeout: TimeInterval? = nil
  ) throws -> Any {
    let data = try requestData(path: path, queryItems: queryItems, timeout: timeout)
    return try JSONSerialization.jsonObject(with: data)
  }

  private func requestNoContent(
    path: String,
    queryItems: [URLQueryItem] = [],
    method: String,
    body: [String: Any]
  ) throws {
    _ = try requestData(
      path: path,
      queryItems: queryItems,
      method: method,
      body: body,
      expectBody: false
    )
  }

  private func requestData(
    path: String,
    queryItems: [URLQueryItem] = [],
    method: String = "GET",
    body: [String: Any]? = nil,
    expectBody: Bool = true,
    timeout: TimeInterval? = nil
  ) throws -> Data {
    let requestTimeout = timeout ?? 5
    let semaphoreTimeout = timeout.map { max($0 + 1, $0) } ?? 6
    guard var components = URLComponents(
      url: try baseURL().appendingPathComponent(normalizedPath(path)),
      resolvingAgainstBaseURL: false
    ) else {
      throw MihomoControllerClientError.invalidMetadata
    }
    if !queryItems.isEmpty {
      components.queryItems = queryItems
    }
    guard let url = components.url else {
      throw MihomoControllerClientError.invalidMetadata
    }
    var request = URLRequest(url: url)
    request.httpMethod = method
    request.timeoutInterval = requestTimeout
    request.setValue("Bearer \(metadata.secret)", forHTTPHeaderField: "Authorization")
    request.setValue("application/json", forHTTPHeaderField: "Accept")

    if let body {
      request.httpBody = try JSONSerialization.data(withJSONObject: body)
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    }

    let semaphore = DispatchSemaphore(value: 0)
    var result: Result<Data, Error> = .failure(MihomoControllerClientError.timeout)
    let task = session.dataTask(with: request) { data, response, error in
      defer { semaphore.signal() }

      if let error {
        result = .failure(error)
        return
      }

      guard let http = response as? HTTPURLResponse else {
        result = .failure(MihomoControllerClientError.invalidResponse)
        return
      }

      let responseData = data ?? Data()
      guard (200..<300).contains(http.statusCode) else {
        let bodyText = String(data: responseData, encoding: .utf8) ?? ""
        result = .failure(MihomoControllerClientError.httpError(http.statusCode, bodyText))
        return
      }

      result = .success(expectBody ? responseData : Data())
    }

    task.resume()
    if semaphore.wait(timeout: .now() + semaphoreTimeout) == .timedOut {
      task.cancel()
      throw MihomoControllerClientError.timeout
    }

    return try result.get()
  }

  private func baseURL() throws -> URL {
    guard let baseURL = metadata.baseURL else {
      throw MihomoControllerClientError.invalidMetadata
    }
    return baseURL
  }

  private func escaped(_ value: String) -> String {
    value.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? value
  }

  private func normalizedPath(_ value: String) -> String {
    value.hasPrefix("/") ? String(value.dropFirst()) : value
  }

  private func delayQueryItems(
    url: String,
    timeoutMilliseconds: Int
  ) -> [URLQueryItem] {
    [
      URLQueryItem(name: "url", value: url),
      URLQueryItem(name: "timeout", value: String(timeoutMilliseconds))
    ]
  }

  private func delayRequestTimeout(for timeoutMilliseconds: Int) -> TimeInterval {
    let probeTimeoutSeconds = Double(max(timeoutMilliseconds, 0)) / 1_000
    return max(5, probeTimeoutSeconds + 2)
  }

  private func intValue(_ value: Any?) -> Int? {
    if let intValue = value as? Int {
      return intValue
    }
    if let number = value as? NSNumber {
      return number.intValue
    }
    return nil
  }

  private func stringValue(_ value: Any?) -> String? {
    if let stringValue = value as? String {
      let trimmed = stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
      return trimmed.isEmpty ? nil : trimmed
    }
    if let number = value as? NSNumber {
      return number.stringValue
    }
    return nil
  }

  private func firstNonEmpty(_ values: [String?]) -> String? {
    values.compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
      .first { !$0.isEmpty && $0.lowercased() != "unknown" }
  }

  private func endpointDisplay(ip: String, port: Int?) -> String? {
    let normalizedIP = ip.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalizedIP.isEmpty else { return nil }
    guard let port else { return normalizedIP }
    return "\(normalizedIP):\(port)"
  }

  private func int64Value(_ value: Any?) -> Int64 {
    if let int64Value = value as? Int64 {
      return int64Value
    }
    if let intValue = value as? Int {
      return Int64(intValue)
    }
    if let number = value as? NSNumber {
      return number.int64Value
    }
    return 0
  }

  private func firstNonZeroInt64(_ values: [Any?]) -> Int64 {
    for value in values {
      let number = int64Value(value)
      if number != 0 {
        return number
      }
    }
    return 0
  }
}
