import Foundation

@main
struct IOSProxyProjectionChecks {
  static func main() throws {
    let service = CompatibilityService()
    let variants = [
      """
      proxies:
        - name: Node # a valid YAML comment
          type: 'vless'
          server: 198.51.100.10
          port: 443
          transport-options:
            type: direct
            name: not-a-node
      proxy-groups:
        - type: select
          name: Safe
          proxies:
            - Node
      rules:
        - MATCH,Safe
      """,
      """
      proxies:
      - name: 'Node'
        type: vless
        server: 198.51.100.10
        port: 443
      proxy-groups:
      - name: Safe
        type: select
        proxies:
        - 'Node'
      rules:
      - MATCH,Safe
      """,
      """
      proxies: [{name: 'Node', type: vless, server: 198.51.100.10, port: 443, ws-opts: {path: '/a,b', headers: {name: nested, type: direct}}}]
      proxy-groups: [{name: Safe, type: select, proxies: ['Node']}]
      rules: ['DOMAIN-SUFFIX,example.org,Safe', 'MATCH,Safe']
      """,
      """
      proxies:
        - {name: Node, type: vless, server: 198.51.100.10, port: 443}
      proxy-groups:
        - {name: Safe, type: select, proxies: [Node]}
      rules: ["MATCH,Safe"]
      """,
      """
      proxies: [{"name":"Node","type":"vless","server":"198.51.100.10","port":443}]
      proxy-groups: [{"name":"Safe","type":"select","proxies":["Node"]}]
      rules: ["MATCH,Safe"]
      """
    ]
    for profile in variants {
      let nodes = service.extractProxyNodes(from: profile)
      precondition(service.extractProxyServerEndpointHosts(from: profile) == ["198.51.100.10"], "Bootstrap endpoint discovery must use the same root projection")
      precondition(nodes.count == 1 && nodes[0].name == "Node" && nodes[0].type == "vless", "Only root proxy fields are node metadata")
      let group = service.extractProxyGroups(from: profile).first!
      precondition(group.name == "Safe" && group.all == ["Node"], "Block, indentless and flow groups must agree")
      precondition(service.protectedDNSProxyTarget(in: profile) == "Safe", "Valid YAML representation must not change the protected target")
      let originalRules = RoutingPolicyService.ruleStrings(in: profile)
      let routed = try RoutingPolicyService.rewrite(profile, policy: .profile)
      precondition(Array(RoutingPolicyService.ruleStrings(in: routed).suffix(originalRules.count)) == originalRules, "Privacy rules must preserve the original TCP rules and MATCH")
    }
    let safe = variants[0]
    for control in ["\u{0000}", "\u{0001}", "\u{007F}", "\u{0085}"] {
      let invalidName = variants[2].replacingOccurrences(of: "'Node'", with: "'Node\(control)'")
      precondition(service.protectedDNSProxyTarget(in: invalidName) == nil, "Control characters remain ineligible proxy names")
    }
    let trailingComma = variants[2]
      .replacingOccurrences(of: "headers: {name: nested, type: direct}}}]", with: "headers: {name: nested, type: direct},},},]")
      .replacingOccurrences(of: "proxies: ['Node']}", with: "proxies: ['Node',],}")
      .replacingOccurrences(of: "'MATCH,Safe']", with: "'MATCH,Safe',]")
    precondition(service.extractProxyNodes(from: trailingComma).first?.type == "vless")
    precondition(service.protectedDNSProxyTarget(in: trailingComma) == "Safe")
    precondition(RoutingPolicyService.ruleStrings(in: trailingComma).last == "MATCH,Safe")
    let plainApostrophe = variants[2].replacingOccurrences(of: "'Node'", with: "O'Brien")
    precondition(service.extractProxyNodes(from: plainApostrophe).first?.name == "O'Brien")
    precondition(service.protectedDNSProxyTarget(in: plainApostrophe) == "Safe")
    let commentedApostrophe = safe.replacingOccurrences(of: "Node # a valid YAML comment", with: "O'Brien # comment").replacingOccurrences(of: "- Node", with: "- O'Brien")
    precondition(service.extractProxyNodes(from: commentedApostrophe).first?.name == "O'Brien")
    precondition(service.protectedDNSProxyTarget(in: commentedApostrophe) == "Safe")
    for rules in ["rules: []", "rules:\n  - DOMAIN-SUFFIX,qq.com,DIRECT", ""] {
      let missingMatch = safe.replacingOccurrences(of: "rules:\n  - MATCH,Safe", with: rules)
      let completed = try RoutingPolicyService.rewrite(missingMatch, policy: .profile)
      precondition(RoutingPolicyService.ruleStrings(in: completed).last == "MATCH,Safe", "An unmatched TCP request must have an explicit protected fallback")
      if rules.contains("qq.com") { precondition(RoutingPolicyService.ruleStrings(in: completed).contains("DOMAIN-SUFFIX,qq.com,DIRECT")) }
    }
    let preparedInput = CompatibilityInput(profileYaml: safe, controlledConfigYaml: "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver: [https://1.1.1.1/dns-query]", appConfigJson: "{\"iosRoutingPolicy\":\"profile\"}")
    let prepared = service.prepareConfiguration(preparedInput)
    precondition(prepared.report.isValid && prepared.input == service.sanitizedMobileInput(preparedInput))
    precondition(prepared.runtimeConfig == service.buildRuntimeConfig(from: preparedInput), "Preparing configuration is pure and retains the validated runtime")
    let variableSpacing = safe.replacingOccurrences(of: "  - name:", with: "  -  name:").replacingOccurrences(of: "    type:", with: "     type:").replacingOccurrences(of: "    server:", with: "     server:").replacingOccurrences(of: "    port:", with: "     port:").replacingOccurrences(of: "    transport-options:", with: "     transport-options:")
    precondition(service.extractProxyNodes(from: variableSpacing).first?.type == "vless", "Sequence content indentation follows the dash spacing")
    let apostrophe = safe.replacingOccurrences(of: "Node # a valid YAML comment", with: "'O''Brien Node' # comment").replacingOccurrences(of: "- Node", with: "- \"O'Brien Node\"")
    precondition(service.extractProxyNodes(from: apostrophe).first?.name == "O'Brien Node")
    precondition(service.protectedDNSProxyTarget(in: apostrophe) == "Safe")

    let unsafe = """
    proxies:
      - name: Node
        type: vless
        server: 198.51.100.10
        port: 443
    proxy-groups:
      - name: Safe
        type: select
        proxies:
          - Node
      - name: Unsafe
        type: select
        proxies: [DIRECT, Node]
    rules: ['MATCH,Unsafe']
    """
    precondition(service.extractProxyNodes(from: unsafe).map(\.name) == ["Node"], "Nested group members must not start a second proxy-node section")
    precondition(service.protectedDNSProxyTarget(in: unsafe) == "Safe", "A DIRECT group must never become a trusted leaf")
    precondition(service.protectedDNSProxyTarget(in: safe.replacingOccurrences(of: "'vless'", with: "'direct'")) == nil)
    precondition(service.protectedDNSProxyTarget(in: safe.replacingOccurrences(of: "name: Safe", with: "name: Node")) == nil, "Duplicate graph names cannot be proved")
    let dynamic = safe.replacingOccurrences(of: "type: select", with: "type: select\n    use: [Remote]")
    precondition(service.protectedDNSProxyTarget(in: dynamic) == "Node", "Opaque providers cannot establish group safety")
    let opaqueRules = safe.replacingOccurrences(of: "rules:\n  - MATCH,Safe", with: "rules: *someAlias")
    precondition(service.parsedRuleStrings(from: opaqueRules) == nil)
    do {
      _ = try RoutingPolicyService.rewrite(opaqueRules, policy: .profile)
      preconditionFailure("Unsupported rule representation must fail rather than silently erase MATCH")
    } catch RoutingPolicyError.unsupportedRulesSyntax {}

    var sharedGraph = "proxies: [{name: Node, type: vless, server: 198.51.100.10, port: 443}]\nproxy-groups:\n"
    for index in 0..<23 {
      let members = index < 2 ? "Node" : "G\(index - 1), G\(index - 2)"
      sharedGraph += "  - {name: G\(index), type: select, proxies: [\(members)]}\n"
    }
    sharedGraph += "rules: ['MATCH,G22']\n"
    precondition(service.protectedDNSProxyTarget(in: sharedGraph) == "G22")
    print("PASS: root-only proxy graph, flow/block/indentless YAML, quotes/comments, static safety, duplicate/provider rejection, preserved inline rules and shared subgroups.")
  }
}
