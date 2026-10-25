import Foundation
import Darwin

enum EncryptedBootstrapError: LocalizedError, Sendable, Equatable {
  case invalidEndpoint, invalidHostname, invalidResponse, responseTooLarge, noEndpoint, unresolvedHost, timedOut, deferred

  var errorDescription: String? {
    switch self {
    case .invalidEndpoint: return "Proxy bootstrap requires an HTTPS DNS endpoint with a literal IP address."
    case .invalidHostname: return "A proxy hostname is invalid for encrypted bootstrap."
    case .invalidResponse: return "Encrypted bootstrap returned an invalid DNS response."
    case .responseTooLarge: return "Encrypted bootstrap returned an oversized DNS response."
    case .noEndpoint: return "No independent HTTPS DNS endpoint is configured for proxy bootstrap."
    case .unresolvedHost: return "A proxy hostname could not be resolved through encrypted bootstrap."
    case .timedOut: return "Encrypted proxy bootstrap exceeded its time limit."
    case .deferred: return "Candidate bootstrap is deferred until the node is selected."
    }
  }
}

struct EncryptedBootstrapResolution: Sendable {
  var addresses: [String: [String]] = [:]
  var failures: [String: EncryptedBootstrapError] = [:]
}

/// Independent bootstrap only: a proxy cannot resolve its own endpoint through
/// itself. Literal-IP HTTPS URLs avoid an implicit system-DNS lookup and retain
/// URLSession's default certificate and hostname validation. No trust override,
/// cookies, redirects, cleartext DNS or getaddrinfo fallback is permitted.
struct EncryptedBootstrapResolver {
  static let maximumResponseBytes = 65_535
  static let maximumWarmupHosts = 128
  private let timeout: TimeInterval
  private let configuration: URLSessionConfiguration

  init(timeout: TimeInterval = 12, configuration: URLSessionConfiguration = .ephemeral) {
    self.timeout = min(max(timeout, 0.1), 20)
    self.configuration = configuration
  }

  static func endpoint(_ value: String) -> URL? {
    guard var parts = URLComponents(string: value), parts.scheme?.lowercased() == "https",
          parts.user == nil, parts.password == nil, let host = parts.host,
          isIPAddress(host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))),
          !parts.path.isEmpty else { return nil }
    if let port = parts.port, !(1...65_535).contains(port) { return nil }
    if let rawFragment = parts.percentEncodedFragment {
      guard let fragment = rawFragment.removingPercentEncoding else { return nil }
      let adapter = fragment.split(separator: "&").last(where: { !$0.contains("=") }).map(String.init)
      if let adapter, !adapter.isEmpty, adapter.uppercased() != "DIRECT" { return nil }
    }
    parts.fragment = nil
    return parts.url
  }

  static func isIPAddress(_ value: String) -> Bool {
    var v4 = in_addr(), v6 = in6_addr()
    return value.withCString { inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 }
  }

  /// Prewarm candidates independently. Unused failed/deferred nodes must not
  /// prevent an already numeric selected node from starting. The mobile core
  /// enforces encrypted-only lookup when a candidate is actually selected.
  func resolve(hosts: [String], endpoints: [URL]) async -> EncryptedBootstrapResolution {
    var resolution = EncryptedBootstrapResolution()
    var candidates: [String] = []
    for host in Array(Set(hosts)).sorted() {
      if Self.isIPAddress(host) { resolution.addresses[host] = [host]; continue }
      do { _ = try BootstrapDNSMessage.query(host: host, type: 1, id: 1); candidates.append(host) }
      catch { resolution.failures[host] = .invalidHostname }
    }
    guard !candidates.isEmpty else { return resolution }
    guard !endpoints.isEmpty else {
      for host in candidates { resolution.failures[host] = .noEndpoint }
      return resolution
    }
    guard endpoints.allSatisfy({ Self.endpoint($0.absoluteString) == $0 }) else {
      for host in candidates { resolution.failures[host] = .invalidEndpoint }
      return resolution
    }
    for host in candidates.dropFirst(Self.maximumWarmupHosts) { resolution.failures[host] = .deferred }
    let warmed = Array(candidates.prefix(Self.maximumWarmupHosts))

    configuration.timeoutIntervalForRequest = min(timeout, 4)
    configuration.timeoutIntervalForResource = timeout
    configuration.waitsForConnectivity = false
    configuration.httpMaximumConnectionsPerHost = 4
    configuration.urlCache = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    configuration.httpCookieStorage = nil
    configuration.httpShouldSetCookies = false
    let delegate = BootstrapRedirectGuard()
    let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    defer { session.invalidateAndCancel() }

    await withTaskGroup(of: (String?, [String]?, EncryptedBootstrapError?).self) { group in
      var iterator = warmed.makeIterator()
      func addLookup(_ host: String) {
        group.addTask {
          do { return (host, try await resolveHost(host, endpoints: endpoints, session: session), nil) }
          catch { return (host, nil, .unresolvedHost) }
        }
      }
      for _ in 0..<min(4, warmed.count) { if let host = iterator.next() { addLookup(host) } }
      group.addTask {
        do { try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000)) } catch {}
        return (nil, nil, .timedOut)
      }
      var completed = 0
      for await (host, addresses, failure) in group {
        guard let host else {
          session.invalidateAndCancel()
          group.cancelAll()
          for unresolved in warmed where resolution.addresses[unresolved] == nil && resolution.failures[unresolved] == nil {
            resolution.failures[unresolved] = .timedOut
          }
          break
        }
        if let addresses { resolution.addresses[host] = addresses }
        else { resolution.failures[host] = failure ?? .unresolvedHost }
        completed += 1
        if completed == warmed.count { group.cancelAll(); break }
        if let next = iterator.next() { addLookup(next) }
      }
    }
    return resolution
  }

  private func resolveHost(_ host: String, endpoints: [URL], session: URLSession) async throws -> [String] {
    for endpoint in endpoints {
      try Task.checkCancellation()
      let addresses = await withTaskGroup(of: [String].self) { queries in
        for type: UInt16 in [1, 28] {
          queries.addTask { (try? await query(host: host, type: type, endpoint: endpoint, session: session)) ?? [] }
        }
        var addresses: [String] = []
        for await answer in queries { addresses.append(contentsOf: answer) }
        return Array(Set(addresses)).sorted()
      }
      if !addresses.isEmpty { return addresses }
    }
    try Task.checkCancellation()
    throw EncryptedBootstrapError.unresolvedHost
  }

  private func query(host: String, type: UInt16, endpoint: URL, session: URLSession) async throws -> [String] {
    let id = UInt16.random(in: 0...UInt16.max)
    var request = URLRequest(url: endpoint)
    request.httpMethod = "POST"
    request.httpBody = try BootstrapDNSMessage.query(host: host, type: type, id: id)
    request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
    request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
    let (bytes, response) = try await session.bytes(for: request)
    guard let response = response as? HTTPURLResponse, response.statusCode == 200,
          response.mimeType?.lowercased() == "application/dns-message",
          response.expectedContentLength <= Self.maximumResponseBytes else {
      throw EncryptedBootstrapError.invalidResponse
    }
    var body = Data()
    for try await byte in bytes {
      guard body.count < Self.maximumResponseBytes else { throw EncryptedBootstrapError.responseTooLarge }
      body.append(byte)
    }
    return try BootstrapDNSMessage.addresses(in: body, host: host, type: type, id: id)
  }
}

private final class BootstrapRedirectGuard: NSObject, URLSessionTaskDelegate {
  func urlSession(_ session: URLSession, task: URLSessionTask,
                  willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                  completionHandler: @escaping (URLRequest?) -> Void) {
    completionHandler(nil)
  }
}

enum BootstrapDNSMessage {
  static func query(host: String, type: UInt16, id: UInt16) throws -> Data {
    let host = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
    let labels = host.split(separator: ".", omittingEmptySubsequences: false)
    guard !host.isEmpty, host.utf8.count <= 253, [1, 28].contains(type),
          labels.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 63 && $0.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95
          } }) else { throw EncryptedBootstrapError.invalidHostname }
    var data = Data()
    for value: UInt16 in [id, 0x0100, 1, 0, 0, 0] { append(value, to: &data) }
    for label in labels { data.append(UInt8(label.utf8.count)); data.append(contentsOf: label.utf8) }
    data.append(0)
    append(type, to: &data)
    append(1, to: &data)
    return data
  }

  static func addresses(in data: Data, host: String, type: UInt16, id: UInt16) throws -> [String] {
    let bytes = Array(data)
    guard bytes.count >= 12, bytes.count <= EncryptedBootstrapResolver.maximumResponseBytes,
          word(bytes, 0) == id, let flags = word(bytes, 2), flags & 0x8000 != 0,
          flags & 0x7a00 == 0, [0, 3].contains(flags & 0xf), word(bytes, 4) == 1 else {
      throw EncryptedBootstrapError.invalidResponse
    }
    var cursor = 12
    let question = try name(bytes, cursor: &cursor)
    guard question == host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")),
          word(bytes, cursor) == type, word(bytes, cursor + 2) == 1 else {
      throw EncryptedBootstrapError.invalidResponse
    }
    cursor += 4
    if flags & 0xf == 3 { return [] }
    var records: [(String, UInt16, Int, Int)] = []
    for _ in 0..<Int(word(bytes, 6) ?? 0) {
      let owner = try name(bytes, cursor: &cursor)
      guard let kind = word(bytes, cursor), word(bytes, cursor + 2) == 1,
            let length = word(bytes, cursor + 8), cursor + 10 + Int(length) <= bytes.count else {
        throw EncryptedBootstrapError.invalidResponse
      }
      cursor += 10
      records.append((owner, kind, cursor, Int(length)))
      cursor += Int(length)
    }
    var aliases = Set([question])
    for _ in 0..<16 {
      var changed = false
      for (owner, kind, start, length) in records where kind == 5 && aliases.contains(owner) {
        var offset = start
        let target = try name(bytes, cursor: &offset)
        guard offset <= start + length else { throw EncryptedBootstrapError.invalidResponse }
        if aliases.insert(target).inserted { changed = true }
      }
      if !changed { break }
    }
    var addresses: [String] = []
    for (owner, kind, start, length) in records where kind == type && aliases.contains(owner) {
      let expected = type == 1 ? 4 : 16
      guard length == expected else { throw EncryptedBootstrapError.invalidResponse }
      var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
      let rendered = bytes.withUnsafeBytes { raw -> UnsafePointer<CChar>? in
        inet_ntop(type == 1 ? AF_INET : AF_INET6, raw.baseAddress!.advanced(by: start), &output, socklen_t(output.count))
      }
      guard rendered != nil else { throw EncryptedBootstrapError.invalidResponse }
      addresses.append(String(cString: output))
    }
    return Array(Set(addresses)).sorted()
  }

  private static func name(_ bytes: [UInt8], cursor: inout Int) throws -> String {
    var index = cursor, visited = Set<Int>(), labels: [String] = [], jumped = false
    while index < bytes.count, visited.insert(index).inserted, visited.count <= 128 {
      let length = Int(bytes[index])
      if length == 0 { if !jumped { cursor = index + 1 }; return labels.joined(separator: ".").lowercased() }
      if length & 0xc0 == 0xc0 {
        guard index + 1 < bytes.count else { break }
        let target = ((length & 0x3f) << 8) | Int(bytes[index + 1])
        if !jumped { cursor = index + 2 }; jumped = true; index = target; continue
      }
      guard length <= 63, index + 1 + length <= bytes.count,
            let label = String(bytes: bytes[(index + 1)..<(index + 1 + length)], encoding: .ascii) else { break }
      labels.append(label)
      guard labels.joined(separator: ".").utf8.count <= 253 else { break }
      index += 1 + length
    }
    throw EncryptedBootstrapError.invalidResponse
  }

  private static func word(_ bytes: [UInt8], _ offset: Int) -> UInt16? {
    guard offset >= 0, offset + 1 < bytes.count else { return nil }
    return UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
  }

  private static func append(_ value: UInt16, to data: inout Data) {
    data.append(UInt8(value >> 8)); data.append(UInt8(value & 0xff))
  }
}
