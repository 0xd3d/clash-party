import Foundation

@main
struct GeoResourceDownloadContextChecks {
  static func main() async throws {
    let manager = FileManager.default
    let root = manager.temporaryDirectory.appendingPathComponent("geo-download-context-\(UUID().uuidString)", isDirectory: true)
    try manager.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? manager.removeItem(at: root) }

    func fixture(_ name: String, extensionMetadata: Bool) throws -> Bundle {
      let directory = root.appendingPathComponent(name, isDirectory: true)
      try manager.createDirectory(at: directory, withIntermediateDirectories: true)
      var info: [String: Any] = ["CFBundleIdentifier": "org.clashparty.fixture", "CFBundleVersion": "1"]
      if extensionMetadata { info["NSExtension"] = ["NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel"] }
      let data = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
      try data.write(to: directory.appendingPathComponent("Info.plist"))
      let contents = directory.appendingPathComponent("Contents", isDirectory: true)
      try manager.createDirectory(at: contents, withIntermediateDirectories: true)
      try data.write(to: contents.appendingPathComponent("Info.plist"))
      return Bundle(url: directory)!
    }

    let app = try fixture("Fixture.app", extensionMetadata: false)
    let provider = try fixture("Fixture.appex", extensionMetadata: true)
    let extensionByMetadata = try fixture("Metadata.bundle", extensionMetadata: true)
    let home = root.appendingPathComponent("cache", isDirectory: true)
    try manager.createDirectory(at: home, withIntermediateDirectories: true)
    let cache = home.appendingPathComponent("geoip-lite.dat")
    let cachedBytes = Data(repeating: 0x2a, count: 2048)
    try cachedBytes.write(to: cache)
    let configuration = "geox-url:\n  geoip: https://resources.example/geoip-lite.dat\n"
    let seeded = try GeoResourceManager.seedBundledResourcesIfNeeded(from: configuration, homeURL: home)
    precondition(seeded.readyCount == 1 && seeded.seededCount == 0)

    let source = URL(string: "https://resources.example/geoip-lite.dat")!
    var calls = 0
    let download: (URL) async throws -> (URL, URLResponse) = { url in
      calls += 1
      precondition(url == source)
      let payload = root.appendingPathComponent("download.fixture")
      try cachedBytes.write(to: payload)
      return (payload, HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:])!)
    }
    for bundle in [provider, extensionByMetadata] {
      do {
        _ = try await GeoResourceManager.downloadInApplication(from: source, bundle: bundle, perform: download)
        preconditionFailure("Provider downloads must defer to the existing routed core client.")
      } catch GeoResourceDownloadError.requiresCoreClient {}
      precondition(calls == 0)
      let unchanged = try Data(contentsOf: cache)
      precondition(unchanged == cachedBytes)
    }
    try manager.removeItem(at: cache)
    do {
      _ = try await GeoResourceManager.downloadInApplication(from: source, bundle: provider, perform: download)
      preconditionFailure("A missing cache cannot enable a direct provider fallback.")
    } catch GeoResourceDownloadError.requiresCoreClient {}
    precondition(calls == 0 && !manager.fileExists(atPath: cache.path))

    let (downloaded, _) = try await GeoResourceManager.downloadInApplication(from: source, bundle: app, perform: download)
    let downloadedBytes = try Data(contentsOf: downloaded)
    precondition(calls == 1 && downloadedBytes == cachedBytes)
    print("PASS: provider/extension Geo downloads never invoke URLSession or a direct fallback; cache is preserved, missing files defer, main-app download path remains available.")
  }
}
