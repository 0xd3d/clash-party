import Foundation

private final class BootstrapMockProtocol: URLProtocol {
  static let lock = NSLock()
  static var mode = "valid"
  static var observed: [URLRequest] = []
  static var cancellations = 0

  override class func canInit(with request: URLRequest) -> Bool { true }
  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

  override func startLoading() {
    Self.lock.lock()
    Self.observed.append(request)
    let mode = Self.mode
    Self.lock.unlock()
    if mode == "hang" { return }
    var body = request.httpBody ?? Data()
    if body.isEmpty, let stream = request.httpBodyStream {
      stream.open()
      var buffer = [UInt8](repeating: 0, count: 1024)
      while stream.hasBytesAvailable {
        let count = stream.read(&buffer, maxLength: buffer.count)
        if count <= 0 { break }
        body.append(contentsOf: buffer.prefix(count))
      }
      stream.close()
    }
    guard body.count >= 16 else { client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse)); return }
    var reply = Self.reply(to: body)
    if mode == "partial", Self.hostname(in: body) == "unused.invalid" {
      reply = body
      reply[2] = 0x81; reply[3] = 0x83 // NXDOMAIN for only this unused candidate.
    }
    if mode == "wrong-id" { reply[0] ^= 0xff }
    if mode == "oversized" { reply.append(Data(repeating: 0, count: 65_536)) }
    let response = HTTPURLResponse(url: request.url!, statusCode: mode == "redirect" ? 302 : 200,
      httpVersion: "HTTP/1.1", headerFields: ["Content-Type": mode == "mime" ? "text/html" : "application/dns-message"] )!
    client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
    client?.urlProtocol(self, didLoad: reply)
    client?.urlProtocolDidFinishLoading(self)
  }

  override func stopLoading() {
    Self.lock.lock(); Self.cancellations += 1; Self.lock.unlock()
  }

  static func reset(_ mode: String) {
    lock.lock(); Self.mode = mode; observed = []; cancellations = 0; lock.unlock()
  }

  static func reply(to query: Data) -> Data {
    var reply = query
    reply[2] = 0x81; reply[3] = 0x80
    reply[6] = 0; reply[7] = 1
    let type = query[query.count - 3]
    reply.append(contentsOf: [0xc0, 0x0c, 0, type, 0, 1, 0, 0, 0, 30])
    if type == 1 {
      reply.append(contentsOf: [0, 4, 203, 0, 113, 8])
    } else {
      reply.append(contentsOf: [0, 16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8])
    }
    return reply
  }

  static func hostname(in query: Data) -> String {
    var cursor = 12, labels: [String] = []
    while cursor < query.count {
      let count = Int(query[cursor]); cursor += 1
      if count == 0 { break }
      guard cursor + count <= query.count else { break }
      labels.append(String(decoding: query[cursor..<(cursor + count)], as: UTF8.self))
      cursor += count
    }
    return labels.joined(separator: ".")
  }
}

@main
struct EncryptedBootstrapChecks {
  static func main() async throws {
    let full = "https://192.0.2.1:4443/custom/dns-query?version=1#DIRECT"
    let endpoint = EncryptedBootstrapResolver.endpoint(full)!
    precondition(endpoint.absoluteString == "https://192.0.2.1:4443/custom/dns-query?version=1")
    for invalid in ["223.5.5.5", "udp://192.0.2.1:53", "http://192.0.2.1/dns-query",
                    "https://dns.example/dns-query", "https://u:p@192.0.2.1/dns-query",
                    "https://192.0.2.1/dns-query#TestProxy", "https://192.0.2.1:70000/dns-query"] {
      precondition(EncryptedBootstrapResolver.endpoint(invalid) == nil)
    }
    precondition(EncryptedBootstrapResolver.endpoint("https://[2001:db8::1]/dns-query") != nil)
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [BootstrapMockProtocol.self]
    let resolver = EncryptedBootstrapResolver(timeout: 1, configuration: configuration)
    BootstrapMockProtocol.reset("valid")
    let answers = await resolver.resolve(hosts: ["proxy.example", "proxy.example"], endpoints: [endpoint])
    precondition(answers.addresses["proxy.example"] == ["2001:db8::8", "203.0.113.8"] && answers.failures.isEmpty)
    precondition(BootstrapMockProtocol.observed.count == 2)
    for request in BootstrapMockProtocol.observed {
      precondition(request.url == endpoint && request.httpMethod == "POST")
      precondition(request.value(forHTTPHeaderField: "Accept") == "application/dns-message")
      precondition(request.value(forHTTPHeaderField: "Content-Type") == "application/dns-message")
      precondition(request.value(forHTTPHeaderField: "Cookie") == nil)
    }
    for mode in ["wrong-id", "mime", "oversized", "redirect"] {
      BootstrapMockProtocol.reset(mode)
      let result = await resolver.resolve(hosts: ["proxy.example"], endpoints: [endpoint])
      precondition(result.addresses.isEmpty && result.failures["proxy.example"] != nil)
      precondition(BootstrapMockProtocol.observed.count == 2)
    }
    BootstrapMockProtocol.reset("hang")
    let start = Date()
    let timeoutResult = await EncryptedBootstrapResolver(timeout: 0.15, configuration: configuration)
      .resolve(hosts: ["proxy.example"], endpoints: [endpoint])
    precondition(timeoutResult.failures["proxy.example"] == .timedOut)
    precondition(Date().timeIntervalSince(start) < 2 && BootstrapMockProtocol.observed.count == 2)

    BootstrapMockProtocol.reset("valid")
    let numericOnly = await resolver.resolve(hosts: ["203.0.113.9"], endpoints: [])
    precondition(numericOnly.addresses == ["203.0.113.9": ["203.0.113.9"]] && BootstrapMockProtocol.observed.isEmpty)
    let noEndpoint = await resolver.resolve(hosts: ["proxy.example"], endpoints: [])
    precondition(noEndpoint.failures["proxy.example"] == .noEndpoint && BootstrapMockProtocol.observed.isEmpty)
    let invalidHost = await resolver.resolve(hosts: ["bad..example"], endpoints: [endpoint])
    precondition(invalidHost.failures["bad..example"] == .invalidHostname && BootstrapMockProtocol.observed.isEmpty)

    BootstrapMockProtocol.reset("partial")
    let partial = await resolver.resolve(hosts: ["healthy.example", "unused.invalid", "203.0.113.9"], endpoints: [endpoint])
    precondition(partial.addresses["203.0.113.9"] == ["203.0.113.9"])
    precondition(partial.addresses["healthy.example"] == ["2001:db8::8", "203.0.113.8"])
    precondition(partial.failures["unused.invalid"] == .unresolvedHost)
    precondition(BootstrapMockProtocol.observed.count == 4) // No query for the selected IP node.

    BootstrapMockProtocol.reset("wrong-id")
    let large = await resolver.resolve(hosts: (0..<129).map { "candidate\($0).example" } + ["203.0.113.9"], endpoints: [endpoint])
    precondition(large.addresses["203.0.113.9"] == ["203.0.113.9"] && large.failures.count == 129)
    precondition(large.failures.values.contains(.deferred))
    precondition(BootstrapMockProtocol.observed.count <= EncryptedBootstrapResolver.maximumWarmupHosts * 2)

    let query = try BootstrapDNSMessage.query(host: "proxy.example", type: 1, id: 42)
    let valid = BootstrapMockProtocol.reply(to: query)
    let decoded = try BootstrapDNSMessage.addresses(in: valid, host: "proxy.example", type: 1, id: 42)
    precondition(decoded == ["203.0.113.8"])
    for mutation in ["truncated", "wrong-question", "compression-loop"] {
      var invalid = valid
      if mutation == "truncated" { invalid[2] |= 0x02 }
      if mutation == "wrong-question" { invalid[13] = 120 }
      if mutation == "compression-loop" { invalid[12] = 0xc0; invalid[13] = 12 }
      do { _ = try BootstrapDNSMessage.addresses(in: invalid, host: "proxy.example", type: 1, id: 42); preconditionFailure(mutation) }
      catch {}
    }
    let disabled = PacketTunnelIPv6Policy(plan: PacketTunnelNetworkPlan(ipv6Address: nil, ipv6PrefixLength: nil))
    precondition(disabled.dropsIPv6 && disabled.captureAddress == "fdfe:dcba:9876::1" && disabled.prefixLength == 126)
    let enabled = PacketTunnelIPv6Policy(plan: PacketTunnelNetworkPlan(ipv6Address: "fd00::1", ipv6PrefixLength: 120))
    precondition(!enabled.dropsIPv6 && enabled.captureAddress == "fd00::1" && enabled.prefixLength == 120)
    print("PASS: HTTPS bootstrap validates and bounds requests; literal selected nodes survive failed unused candidates and >128 subscriptions; successes remain per-host, no cleartext fallback; disabled IPv6 stays captured.")
  }
}
