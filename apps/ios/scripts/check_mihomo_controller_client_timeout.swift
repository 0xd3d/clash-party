import Foundation

private final class TimeoutCaptureURLProtocol: URLProtocol {
  static var observedTimeout: TimeInterval?

  override class func canInit(with request: URLRequest) -> Bool {
    true
  }

  override class func canonicalRequest(for request: URLRequest) -> URLRequest {
    request
  }

  override func startLoading() {
    Self.observedTimeout = request.timeoutInterval

    let body = #"{"delay":42}"#.data(using: .utf8) ?? Data()
    let response = HTTPURLResponse(
      url: request.url ?? URL(string: "http://127.0.0.1")!,
      statusCode: 200,
      httpVersion: nil,
      headerFields: ["Content-Type": "application/json"]
    )!
    client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
    client?.urlProtocol(self, didLoad: body)
    client?.urlProtocolDidFinishLoading(self)
  }

  override func stopLoading() {}
}

@main
struct TimeoutCheckMain {
  static func main() throws {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [TimeoutCaptureURLProtocol.self]
    let session = URLSession(configuration: configuration)

    let client = MihomoControllerClient(
      metadata: ControllerRuntimeMetadata(
        baseURLString: "http://127.0.0.1:9090",
        listenAddress: "127.0.0.1:9090",
        secret: "token",
        version: "test",
        active: true
      ),
      session: session
    )

    let delay = try client.fetchProxyDelay(
      name: "Proxy-A",
      url: "https://www.gstatic.com/generate_204",
      timeoutMilliseconds: 7_000
    )

    guard delay == 42 else {
      fputs("Expected delay 42, got \(delay)\n", stderr)
      Foundation.exit(1)
    }

    let observedTimeout = TimeoutCaptureURLProtocol.observedTimeout ?? 0
    guard observedTimeout >= 7 else {
      fputs(
        "Expected request timeout to honor the 7000 ms probe budget, but observed \(observedTimeout) seconds.\n",
        stderr
      )
      Foundation.exit(1)
    }

    print("Observed timeout: \(observedTimeout)s")
  }
}
