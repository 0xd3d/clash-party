import Foundation

// Run with the shared Models, CompatibilityService and SharedStore sources.
@main
struct IOSRuntimeOverlayCheck {
  static func main() {
    let profile = """
    geodata-mode: true
    mode: global
    mixed-port: 1234
    proxies:
      - name: Test
        type: vless
        server: 127.0.0.1
        port: 443
        reality-opts:
          support-x25519mlkem768: true
    proxy-groups:
      - name: TestGroup
        type: select
        proxies:
          - Test
    rules:
      - MATCH,TestGroup
    """
    for controlledGeo in ["", "geodata-mode: false\n", "geodata-mode: true\n"] {
      for overrideGeo in ["", "geodata-mode: true\n"] {
        let input = CompatibilityInput(
          profileYaml: profile,
          controlledConfigYaml: controlledGeo + "mode: rule\ndns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.19.0.1/16\n",
          appConfigJson: "{}",
          overrideYaml: overrideGeo
        )
        let result = CompatibilityService().buildRuntimeConfig(from: input)
        var keys = Set<String>()
        for line in result.split(separator: "\n") {
          guard let first = line.first, !first.isWhitespace, first != "#", let colon = line.firstIndex(of: ":") else { continue }
          let key = String(line[..<colon])
          precondition(keys.insert(key).inserted, "duplicate runtime root key: \(key)")
        }
        precondition(result.contains("geodata-mode: false"))
        precondition(!result.contains("geodata-mode: true"))
        precondition(result.contains("mixed-port: 0"))
        precondition(!result.contains("mixed-port: 1234"))
        precondition(result.contains("mode: rule"))
        precondition(result.contains("support-x25519mlkem768: true"))
        precondition(result.contains("- MATCH,TestGroup"))
      }
    }
    print("PASS: six profile/controlled/override cases have unique root keys and preserve routing and ML-KEM options.")
  }
}
