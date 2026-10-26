import Foundation
@main
struct UnifiedProfileCheck {
  static func main() throws {
    let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
    let fixtures = try JSONSerialization.jsonObject(with: data) as! [[String: Any]]
    var results: [[String: Any]] = []
    for fixture in fixtures {
      for platform in UnifiedProfile.platforms {
        let name = fixture["name"] as! String
        let valid = (fixture["validPlatforms"] as! [String]).contains(platform)
        do {
          let profile = try UnifiedProfile.compile(fixture["input"]!, platform: platform)
          guard valid else { fatalError("Unexpected acceptance: \(name)/\(platform)") }
          results.append(["name":name, "platform":platform, "profile":profile, "yaml":try UnifiedProfile.yaml(profile)])
        } catch {
          guard !valid else { throw error }
          results.append(["name":name, "platform":platform, "rejected":true])
        }
      }
    }
    guard try UnifiedProfile.importedYAML("proxies: []\nrules: []") == nil else { fatalError("Legacy YAML changed") }
    try JSONSerialization.data(withJSONObject: results, options: [.sortedKeys]).write(to: URL(fileURLWithPath: CommandLine.arguments[2]))
    print("Swift unified-profile fixtures passed (including explicit rejections).")
  }
}
