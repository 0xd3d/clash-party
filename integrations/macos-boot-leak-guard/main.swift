// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Darwin

private let installedTool = "/Library/PrivilegedHelperTools/party.mihomo.boot-guard"
private let stateDirectory = "/private/var/db/party.mihomo.boot-guard"
private let anchorName = "com.apple/000.ClashPartyBootLeak"
private let pfctl = "/sbin/pfctl"
private let lsof = "/usr/sbin/lsof"
private let usersRoot = "/Users"
private let policyRelative = "Library/Application Support/mihomo-party/boot-leak-policy.json"

private struct GuardState: Codable {
  var armed = false
  var boot = ""
  var token: String?
}

private struct CommandResult { let code: Int32; let output: String; let errors: String }

private func bootIdentifier() -> String {
  var size = 0
  guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1, size < 128 else {
    return "unknown"
  }
  var bytes = [CChar](repeating: 0, count: size)
  guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0 else { return "unknown" }
  return String(cString: bytes)
}

private func run(_ executable: String, _ arguments: [String], input: String? = nil) throws -> CommandResult {
  guard [pfctl, lsof, "/usr/sbin/networksetup"].contains(executable) else {
    throw NSError(domain: "BootLeak", code: 1, userInfo: [NSLocalizedDescriptionKey: "Blocked executable"])
  }
  var out = [Int32](repeating: 0, count: 2), err = out, stdinPipe = out
  guard pipe(&out) == 0, pipe(&err) == 0, pipe(&stdinPipe) == 0 else {
    throw NSError(domain: "BootLeak", code: 1, userInfo: [NSLocalizedDescriptionKey: "Cannot create pipes"])
  }
  defer { for fd in out + err + stdinPipe where fd >= 0 { close(fd) } }
  var actions: posix_spawn_file_actions_t?
  posix_spawn_file_actions_init(&actions)
  defer { posix_spawn_file_actions_destroy(&actions) }
  posix_spawn_file_actions_adddup2(&actions, stdinPipe[0], STDIN_FILENO)
  posix_spawn_file_actions_adddup2(&actions, out[1], STDOUT_FILENO)
  posix_spawn_file_actions_adddup2(&actions, err[1], STDERR_FILENO)
  for fd in out + err + stdinPipe { posix_spawn_file_actions_addclose(&actions, fd) }
  var argv = ([executable] + arguments).map { strdup($0) } + [nil]
  var environment: [UnsafeMutablePointer<CChar>?] = (["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C"] as [String]).map { strdup($0) } + [nil]
  defer { for pointer in argv + environment { if let pointer { free(pointer) } } }
  var pid: pid_t = 0
  guard posix_spawn(&pid, executable, &actions, nil, &argv, &environment) == 0 else {
    throw NSError(domain: "BootLeak", code: 1, userInfo: [NSLocalizedDescriptionKey: "Cannot spawn utility"])
  }
  close(stdinPipe[0])
  if let input {
    let bytes = Array(input.utf8)
    _ = write(stdinPipe[1], bytes, bytes.count)
  }
  close(stdinPipe[1])
  close(out[1]); close(err[1])
  var outData = Data(), errData = Data(), status: Int32 = 0
  while waitpid(pid, &status, 0) != pid { usleep(1_000) }
  for (index, fd) in [out[0], err[0]].enumerated() {
    var chunk = [UInt8](repeating: 0, count: 8192)
    while true {
      let count = read(fd, &chunk, chunk.count)
      if count <= 0 { break }
      if index == 0 { outData.append(contentsOf: chunk.prefix(count)) }
      else { errData.append(contentsOf: chunk.prefix(count)) }
    }
  }
  let code = (status >> 8) & 0xff
  return CommandResult(
    code: (status & 0x7f) == 0 ? code : 128 + (status & 0x7f),
    output: String(decoding: outData, as: UTF8.self),
    errors: String(decoding: errData, as: UTF8.self)
  )
}

private func pfChecked(_ arguments: [String], input: String? = nil) throws -> String {
  let result = try run(pfctl, arguments, input: input)
  guard result.code == 0 else {
    throw NSError(domain: "BootLeak", code: 1, userInfo: [NSLocalizedDescriptionKey: String(result.errors.prefix(300))])
  }
  return result.output
}

private func loadState() -> GuardState {
  let path = stateDirectory + "/state.json"
  guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
        let state = try? JSONDecoder().decode(GuardState.self, from: data) else {
    return GuardState(boot: bootIdentifier())
  }
  return state
}

private func saveState(_ state: GuardState) {
  try? FileManager.default.createDirectory(atPath: stateDirectory, withIntermediateDirectories: true)
  if let data = try? JSONEncoder().encode(state) {
    try? data.write(to: URL(fileURLWithPath: stateDirectory + "/state.json"), options: .atomic)
  }
}

private func discoverPolicies() -> BootLeakPolicy {
  var policies = [(path: String, policy: BootLeakPolicy)]()
  if let entries = try? FileManager.default.contentsOfDirectory(atPath: usersRoot) {
    for user in entries where user != "Shared" && !user.hasPrefix(".") {
      let path = "\(usersRoot)/\(user)/\(policyRelative)"
      guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
            let policy = try? parseBootLeakPolicyData(data) else { continue }
      policies.append((path, policy))
    }
  }
  return policies.isEmpty ? BootLeakPolicy() : mergedBootLeakPolicy(from: policies)
}

private func listNetworkServices() throws -> [String] {
  let result = try run("/usr/sbin/networksetup", ["-listnetworkserviceorder"])
  guard result.code == 0 else { throw NSError(domain: "BootLeak", code: 1, userInfo: [NSLocalizedDescriptionKey: "Cannot list network services"]) }
  var services = [String]()
  for line in result.output.split(separator: "\n") {
    let text = String(line)
    if text.hasPrefix("(") && text.contains(")") && !text.contains("Hardware Port:") {
      guard let close = text.range(of: ") ") else { continue }
      var service = String(text[close.upperBound...]).trimmingCharacters(in: .whitespaces)
      if !service.isEmpty {
        if service.hasPrefix("*") { service.removeFirst() }
        service = service.trimmingCharacters(in: .whitespaces)
        if service != "*" { services.append(service) }
      }
    }
  }
  return services
}

private func applyLoopbackDNS() {
  guard let services = try? listNetworkServices() else { return }
  for service in services {
    _ = try? run("/usr/sbin/networksetup", ["-setdnsservers", service, "127.0.0.1"])
  }
}

private func coreIsListening(_ policy: BootLeakPolicy) -> Bool {
  let ports: Set<UInt16> = [UInt16(policy.mixedPort), UInt16(policy.dnsListenPort)]
  guard let tcp = try? run(lsof, ["-nP", "-a", "-iTCP", "-sTCP:LISTEN"]),
        let udp = try? run(lsof, ["-nP", "-a", "-iUDP"]) else { return false }
  return loopbackListeners(from: tcp.output, ports: ports) || loopbackListeners(from: udp.output, ports: ports)
}

private func arm(_ policy: BootLeakPolicy) throws {
  let source = bootLeakRuleSource(policy: policy)
  _ = try pfChecked(["-a", anchorName, "-f", "-"], input: source)
  applyLoopbackDNS()
  var state = loadState()
  state.armed = true
  state.boot = bootIdentifier()
  saveState(state)
}

private func disarmEgressDeny() throws {
  _ = try? pfChecked(["-a", anchorName, "-F", "rules"])
  var state = loadState()
  state.armed = false
  saveState(state)
}

private func tick() {
  let policy = discoverPolicies()
  let listening = coreIsListening(policy)
  let armNow = shouldArmBootLeak(disabled: policy.disabled, coreListening: listening)
  let state = loadState()
  do {
    if armNow && !state.armed { try arm(policy) }
    else if !armNow && state.armed { try disarmEgressDeny() }
    else if armNow && state.armed { applyLoopbackDNS() }
  } catch {
    fputs("Boot leak guard tick failed: \(error)\n", stderr)
  }
}

private func serve() {
  _ = umask(0o077)
  tick()
  while true {
    sleep(2)
    tick()
  }
}

private func main() -> Int32 {
  let args = Array(CommandLine.arguments.dropFirst())
  if args == ["--self-test"] {
    do { try policySelfTest(); return 0 } catch {
      fputs("Self-test failed: \(error)\n", stderr)
      return 1
    }
  }
  guard geteuid() == 0 else {
    fputs("Boot leak guard requires root\n", stderr)
    return 1
  }
  if args == ["serve"] || args.isEmpty {
    serve()
    return 0
  }
  fputs("Expected serve or --self-test\n", stderr)
  return 1
}

exit(main())