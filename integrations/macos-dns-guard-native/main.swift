// SPDX-License-Identifier: GPL-3.0-only
// Fixed-purpose, opt-in macOS PF DNS guard. Never executes caller commands or rules.
import Foundation
import Darwin
import Security

private let appPath = "/Applications/Clash Party.app"
private let appExecutable = appPath + "/Contents/MacOS/Clash Party"
private let installedTool = "/Library/PrivilegedHelperTools/party.mihomo.dns-guard"
private let stateDirectory = "/private/var/db/party.mihomo.dns-guard"
private let fixedRules = "block return out quick on ! lo0 proto { udp tcp } from any to any port 53 label \"ClashPartyAutoDNS\"\n"
private let pfctl = "/sbin/pfctl"

private struct GuardError: Error, CustomStringConvertible {
  let description: String
  init(_ message: String) { description = message }
}
private func require(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
  if try !condition() { throw GuardError(message) }
}
// The same absolute budget covers authentication, locking, every utility and readback.
// SIGALRM is a final in-process bound, including unexpected Security.framework stalls.
private var commandDeadline = ProcessInfo.processInfo.systemUptime + 3.4
private var runningChild: Int32 = 0
private var emergencyJSON: UnsafeMutablePointer<CChar>?
private func deadlineHandler(_ signal: Int32) {
  if runningChild > 1 { kill(runningChild, SIGKILL) }
  if let bytes = emergencyJSON { _ = write(STDOUT_FILENO, bytes, strlen(bytes)) }
  _exit(1)
}
private func setDeadline(uid: UInt32, stopping: Bool) {
  let seconds = stopping ? 1.4 : 3.4
  commandDeadline = ProcessInfo.processInfo.systemUptime + seconds
  emergencyJSON = strdup("{\"active\":false,\"ownerUid\":\(uid),\"corePid\":null,\"reason\":\"Native DNS guard operation timed out; verify actual protection state\"}\n")
  _ = signal(SIGALRM, deadlineHandler)
  var timer = itimerval(it_interval: timeval(tv_sec: 0, tv_usec: 0), it_value: timeval(tv_sec: stopping ? 1 : 3, tv_usec: 500_000))
  _ = setitimer(ITIMER_REAL, &timer, nil)
}
private func remainingBudget() throws {
  try require(ProcessInfo.processInfo.systemUptime < commandDeadline, "DNS guard operation deadline exceeded")
}
private struct Reply: Encodable {
  var active: Bool
  var ownerUid: UInt32
  var corePid: Int32?
  var reason: String?
  private enum CodingKeys: String, CodingKey { case active, ownerUid, corePid, reason }
  func encode(to encoder: Encoder) throws {
    var values = encoder.container(keyedBy: CodingKeys.self)
    try values.encode(active, forKey: .active)
    try values.encode(ownerUid, forKey: .ownerUid)
    if let corePid { try values.encode(corePid, forKey: .corePid) }
    else { try values.encodeNil(forKey: .corePid) }
    try values.encodeIfPresent(reason, forKey: .reason)
  }
}
private struct State: Codable {
  var version = 1
  var ownerUid: UInt32
  var appPid: Int32
  var appStart: UInt64
  var corePid: Int32?
  var boot: String
  var desired = false
  var token: String?
  var pendingPid: Int32?
  var pendingSince: Double?
}
private func anchor(_ uid: UInt32) -> String { "com.apple/000.ClashPartyAutoDNS.\(uid)" }
private func isDigits(_ value: String) -> Bool {
  !value.isEmpty && value.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
}
private func parseUID(_ value: String) throws -> UInt32 {
  try require(isDigits(value), "Invalid UID")
  guard let uid = UInt32(value), uid > 0 else { throw GuardError("Invalid UID") }
  return uid
}
private func parsePID(_ value: String) throws -> Int32 {
  try require(isDigits(value), "Invalid core PID")
  guard let pid = Int32(value), pid > 1 else { throw GuardError("Invalid core PID") }
  return pid
}
private func bootIdentifier() throws -> String {
  var size = 0
  try require(sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0 && size > 1 && size < 128, "Cannot identify current boot")
  var bytes = [CChar](repeating: 0, count: size)
  try require(sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0, "Cannot read boot identity")
  return String(cString: bytes)
}
private func processInfo(_ pid: Int32) throws -> proc_bsdinfo {
  var info = proc_bsdinfo()
  try require(proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout.size(ofValue: info))) == MemoryLayout.size(ofValue: info), "Process is unavailable")
  return info
}
private func processPath(_ pid: Int32) throws -> String {
  var buffer = [CChar](repeating: 0, count: Int(4 * MAXPATHLEN))
  try require(proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0, "Cannot identify executable")
  return String(cString: buffer)
}
private func trustedOwnedMode(owner: UInt32, group: UInt32, mode: mode_t, applicationsParent: Bool) -> Bool {
  let systemAdminParent = applicationsParent && group == 80
  return owner == 0 && (mode & 0o002) == 0 && ((mode & 0o020) == 0 || systemAdminParent)
}
private func rejectMutableACLEntries(_ acl: acl_t) throws {
  var entry: acl_entry_t?
  var selector = ACL_FIRST_ENTRY
  let writeMask: UInt64 = [ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE, ACL_DELETE_CHILD, ACL_WRITE_ATTRIBUTES, ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER].reduce(0) { $0 | UInt64($1.rawValue) }
  while true {
    let result = acl_get_entry(acl, Int32(selector.rawValue), &entry)
    if result == -1 && errno == EINVAL { break } // Darwin reports end-of-ACL as EINVAL.
    try require(result == 0, "Cannot inspect installed path ACL entry")
    selector = ACL_NEXT_ENTRY
    guard let entry else { throw GuardError("Missing installed path ACL entry") }
    var tag = ACL_UNDEFINED_TAG
    var permissions: acl_permset_mask_t = 0
    try require(acl_get_tag_type(entry, &tag) == 0 && acl_get_permset_mask_np(entry, &permissions) == 0, "Cannot inspect installed path ACL permissions")
    try require(tag != ACL_EXTENDED_ALLOW || (permissions & writeMask) == 0, "Installed path grants mutable ACL access")
  }
}
private func rejectWritableACL(_ path: String) throws {
  guard let acl = acl_get_file(path, ACL_TYPE_EXTENDED) else { throw GuardError("Cannot inspect installed path ACL") }
  defer { acl_free(UnsafeMutableRawPointer(acl)) }
  try rejectMutableACLEntries(acl)
}
private func checkRootPath(_ path: String, file: Bool, permitApplicationsAdmin: Bool = false) throws {
  var root = stat()
  try require(lstat("/", &root) == 0 && trustedOwnedMode(owner: root.st_uid, group: root.st_gid, mode: root.st_mode, applicationsParent: false), "Filesystem root is not trusted")
  try rejectWritableACL("/")
  var current = ""
  for component in path.split(separator: "/") {
    current += "/" + component
    var info = stat()
    try require(lstat(current, &info) == 0, "Required installed path is missing")
    try require((info.st_mode & S_IFMT) != S_IFLNK && info.st_uid == 0, "Installed path is not root-owned or contains a symlink")
    try rejectWritableACL(current)
    try require(trustedOwnedMode(owner: info.st_uid, group: info.st_gid, mode: info.st_mode, applicationsParent: permitApplicationsAdmin && current == "/Applications"), "Installed path is writable by an untrusted principal")
    if current == path && file { try require((info.st_mode & S_IFMT) == S_IFREG && info.st_nlink == 1, "Installed executable is not a unique regular file") }
    else { try require((info.st_mode & S_IFMT) == S_IFDIR, "Installed parent is not a directory") }
  }
}
private func validateCode(pid: Int32, path: String) throws {
  var disk: SecStaticCode?
  try require(SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &disk) == errSecSuccess, "Cannot inspect installed code identity")
  var requirement: SecRequirement?
  guard let disk else { throw GuardError("Missing installed code identity") }
  try require(SecCodeCopyDesignatedRequirement(disk, [], &requirement) == errSecSuccess && requirement != nil, "Installed executable has no designated code requirement")
  var guest: SecCode?
  try require(SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &guest) == errSecSuccess, "Cannot authenticate running executable")
  guard let guest else { throw GuardError("Missing running code identity") }
  try require(SecCodeCheckValidity(guest, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess, "Running executable does not match installed code")
}
private func authenticateCaller() throws -> (UInt32, proc_bsdinfo) {
  let uid = getuid()
  try require(uid > 0 && geteuid() == 0 && issetugid() != 0, "Use the installed application or root-only recovery command")
  try require(try processPath(getpid()) == installedTool, "Tool is not running from its installed path")
  try checkRootPath(installedTool, file: true)
  try checkRootPath(appExecutable, file: true, permitApplicationsAdmin: true)
  let pid = getppid()
  let info = try processInfo(pid)
  try require(info.pbi_ruid == uid && (try processPath(pid)) == appExecutable, "Caller is not the installed application")
  try validateCode(pid: pid, path: appExecutable)
  return (uid, info)
}
private func checkCore(_ pid: Int32, caller: proc_bsdinfo) throws {
  let info = try processInfo(pid)
  try require(info.pbi_ppid == caller.pbi_pid && info.pbi_ruid == caller.pbi_ruid, "Core is not owned by this application")
  let path = try processPath(pid)
  let allowed = ["mihomo", "mihomo-alpha", "mihomo-smart"].map { appPath + "/Contents/Resources/sidecar/" + $0 }
  try require(allowed.contains(path), "Core executable is not a bundled core")
  try checkRootPath(path, file: true, permitApplicationsAdmin: true)
  try validateCode(pid: pid, path: path)
  let parent = try processInfo(Int32(caller.pbi_pid))
  try require(parent.pbi_start_tvsec == caller.pbi_start_tvsec && parent.pbi_start_tvusec == caller.pbi_start_tvusec && parent.pbi_ruid == caller.pbi_ruid && (try processPath(Int32(caller.pbi_pid))) == appExecutable, "Application owner changed during setup")
}

private struct CommandResult { let code: Int32; let output: String; let errors: String }
// A bounded argument-vector runner with drained, limited pipes and a fixed child environment.
private func run(_ executable: String, _ arguments: [String], input: String? = nil, durableOutput: Int32? = nil, beforeResume: ((Int32) throws -> Void)? = nil) throws -> CommandResult {
  try remainingBudget()
  try require([pfctl, "/usr/sbin/lsof"].contains(executable), "Internal executable is not allowed")
  var out = [Int32](repeating: 0, count: 2), err = out, stdinPipe = out
  try require(pipe(&out) == 0, "Cannot create output pipe")
  defer { for fd in out where fd >= 0 { close(fd) } }
  try require(pipe(&err) == 0, "Cannot create error pipe")
  defer { for fd in err where fd >= 0 { close(fd) } }
  try require(pipe(&stdinPipe) == 0, "Cannot create input pipe")
  defer { for fd in stdinPipe where fd >= 0 { close(fd) } }
  var actions: posix_spawn_file_actions_t?
  posix_spawn_file_actions_init(&actions)
  defer { posix_spawn_file_actions_destroy(&actions) }
  posix_spawn_file_actions_adddup2(&actions, stdinPipe[0], STDIN_FILENO)
  posix_spawn_file_actions_adddup2(&actions, durableOutput ?? out[1], STDOUT_FILENO)
  posix_spawn_file_actions_adddup2(&actions, durableOutput ?? err[1], STDERR_FILENO)
  for fd in out + err + stdinPipe { posix_spawn_file_actions_addclose(&actions, fd) }
  var argv = ([executable] + arguments).map { strdup($0) } + [nil]
  var environment: [UnsafeMutablePointer<CChar>?] = (["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"] as [String]).map { strdup($0) } + [nil]
  defer { for pointer in argv + environment { if let pointer { free(pointer) } } }
  var pid: pid_t = 0
  var attributes: posix_spawnattr_t?
  posix_spawnattr_init(&attributes)
  defer { posix_spawnattr_destroy(&attributes) }
  if beforeResume != nil { posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_START_SUSPENDED)) }
  let result = posix_spawn(&pid, executable, &actions, &attributes, &argv, &environment)
  try require(result == 0, "Cannot launch fixed system utility")
  runningChild = pid
  var reaped = false
  defer {
    if !reaped { kill(pid, SIGKILL); _ = waitpid(pid, nil, 0) }
    runningChild = 0
  }
  if let beforeResume { try beforeResume(pid); try require(kill(pid, SIGCONT) == 0, "Cannot resume recorded system utility") }
  close(stdinPipe[0]); stdinPipe[0] = -1
  if let input {
    let bytes = Array(input.utf8)
    let written = bytes.withUnsafeBytes { write(stdinPipe[1], $0.baseAddress, $0.count) }
    try require(written == bytes.count, "Cannot write fixed utility input")
  }
  close(stdinPipe[1]); stdinPipe[1] = -1
  close(out[1]); out[1] = -1; close(err[1]); err[1] = -1
  for fd in [out[0], err[0]] { _ = fcntl(fd, F_SETFL, O_NONBLOCK) }
  var data = [Data(), Data()], childStatus: Int32 = 0, exited = false, overflow = false
  while true {
    for (index, fd) in [out[0], err[0]].enumerated() {
      var bytes = [UInt8](repeating: 0, count: 8192)
      while true {
        let count = read(fd, &bytes, bytes.count)
        if count <= 0 { break }
        if data[index].count + count <= 1_048_576 { data[index].append(contentsOf: bytes.prefix(count)) }
        else { overflow = true }
      }
    }
    if waitpid(pid, &childStatus, WNOHANG) == pid { exited = true; reaped = true; runningChild = 0 }
    if exited { break }
    if ProcessInfo.processInfo.systemUptime >= commandDeadline {
      kill(pid, SIGKILL)
      _ = waitpid(pid, &childStatus, 0); reaped = true
      throw GuardError("Fixed system utility timed out; protection state requires verification")
    }
    usleep(5_000)
  }
  // Drain bytes already queued after waitpid observed termination.
  for (index, fd) in [out[0], err[0]].enumerated() {
    var bytes = [UInt8](repeating: 0, count: 8192)
    while true {
      let count = read(fd, &bytes, bytes.count)
      if count <= 0 { break }
      if data[index].count + count <= 1_048_576 { data[index].append(contentsOf: bytes.prefix(count)) }
      else { overflow = true }
    }
  }
  try require(!overflow, "System utility output exceeded the safety limit")
  let code = (childStatus >> 8) & 0xff
  return CommandResult(code: (childStatus & 0x7f) == 0 ? code : 128 + (childStatus & 0x7f), output: String(decoding: data[0], as: UTF8.self), errors: String(decoding: data[1], as: UTF8.self))
}
private func checked(_ arguments: [String], input: String? = nil) throws -> String {
  let result = try run(pfctl, arguments, input: input)
  try require(result.code == 0, "PF operation failed: " + result.errors.prefix(300))
  return result.output
}
private func canonicalRules(_ output: String) -> [String] {
  output.split(whereSeparator: \.isNewline).map { $0.split(whereSeparator: \.isWhitespace).joined(separator: " ") }.filter { !$0.isEmpty }
}
private func tokenFrom(_ output: String) -> String? {
  for line in output.split(whereSeparator: \.isNewline).reversed() {
    let parts = line.split(whereSeparator: \.isWhitespace)
    if parts.count == 3 && parts[0] == "Token" && parts[1] == ":" && isDigits(String(parts[2])) { return String(parts[2]) }
  }
  return nil
}
private func safeResolver(_ content: String) -> Bool {
  for line in content.split(whereSeparator: \.isNewline) {
    let words = line.split(whereSeparator: \.isWhitespace)
    if words.first != "nameserver" { continue }
    guard words.count > 1 else { return false }
    var address = String(words[1])
    if address.contains(":"), let dot = address.lastIndex(of: "."), isDigits(String(address[address.index(after: dot)...])) { address = String(address[..<dot]) }
    if !address.contains(":"), address.split(separator: ".").count == 5 { address = address.split(separator: ".").prefix(4).joined(separator: ".") }
    var v4 = in_addr(), v6 = in6_addr()
    if address.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
      if address.split(separator: ".").first == "127" { continue }
      return false
    }
    if address.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
      let bytes = withUnsafeBytes(of: &v6) { Array($0) }
      if bytes.dropLast().allSatisfy({ $0 == 0 }) && bytes.last == 1 { continue }
    }
    return false
  }
  return true
}
private func validateRootRules(_ text: String) throws {
  let lines = canonicalRules(text)
  guard let position = lines.firstIndex(where: { $0 == "anchor \"com.apple/*\" all" || $0 == "anchor \"com.apple/*\" quick all" }) else { throw GuardError("System com.apple/* PF filter anchor is unavailable") }
  try require(!lines.prefix(position).contains(where: { $0.hasPrefix("anchor ") || ($0.hasPrefix("pass ") && $0.split(separator: " ").contains("quick")) }), "An earlier PF anchor or quick-pass rule prevents verified DNS filtering")
}
private func validateSkippedInterfaces(_ text: String) throws {
  var current = ""
  for line in text.split(whereSeparator: \.isNewline) {
    if line.first?.isWhitespace == false { current = String(line.split(whereSeparator: \.isWhitespace).first ?? "") }
    if line.lowercased().contains("skip") && current != "lo0" { throw GuardError("A non-loopback PF interface is skipped; guard cannot claim protection") }
  }
}

private final class Store {
  let directory: Int32
  let lock: Int32
  let uid: UInt32
  init(uid: UInt32) throws {
    self.uid = uid
    try checkRootPath("/private/var/db", file: false)
    if mkdir(stateDirectory, 0o700) != 0 && errno != EEXIST { throw GuardError("Cannot create guard state directory") }
    try rejectWritableACL(stateDirectory)
    directory = open(stateDirectory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    try require(directory >= 0, "Cannot open trusted guard state directory")
    var info = stat()
    try require(fstat(directory, &info) == 0 && info.st_uid == 0 && (info.st_mode & 0o777) == 0o700, "Guard state directory has unsafe ownership or permissions")
    lock = openat(directory, "guard.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
    try require(lock >= 0, "Cannot open guard lock")
    try validateFile(lock)
    while flock(lock, LOCK_EX | LOCK_NB) != 0 {
      try require(errno == EWOULDBLOCK && ProcessInfo.processInfo.systemUptime < commandDeadline, "Guard state is busy")
      usleep(10_000)
    }
  }
  deinit { flock(lock, LOCK_UN); close(lock); close(directory) }
  private var pendingName: String { "uid-\(uid).enable" }
  private var name: String { "uid-\(uid).json" }
  private func validateFile(_ fd: Int32) throws {
    var info = stat()
    try require(fstat(fd, &info) == 0 && info.st_uid == 0 && (info.st_mode & S_IFMT) == S_IFREG && (info.st_mode & 0o777) == 0o600 && info.st_nlink == 1, "Guard state file is unsafe")
  }
  func load() throws -> State? {
    let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    if fd < 0 { if errno == ENOENT { return nil }; throw GuardError("Cannot read guard recovery state") }
    defer { close(fd) }
    try validateFile(fd)
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
    let data = try handle.read(upToCount: 32769) ?? Data()
    try require(data.count <= 32768, "Guard recovery state exceeds safety limit")
    let state = try JSONDecoder().decode(State.self, from: data)
    try require(state.version == 1 && state.ownerUid == uid && (state.token == nil || isDigits(state.token!)), "Guard recovery state is invalid")
    return state
  }
  func save(_ state: State) throws {
    let temporary = ".uid-\(uid)-\(UUID().uuidString)"
    let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    try require(fd >= 0, "Cannot create atomic recovery state")
    defer { close(fd); unlinkat(directory, temporary, 0) }
    let data = try JSONEncoder().encode(state)
    let written = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
    try require(written == data.count && fsync(fd) == 0 && renameat(directory, temporary, directory, name) == 0 && fsync(directory) == 0, "Cannot durably save guard recovery state")
  }
  func createPendingOutput() throws -> Int32 {
    let fd = openat(directory, pendingName, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
    try require(fd >= 0, "Cannot open PF enable journal")
    do {
      try validateFile(fd)
      try require(ftruncate(fd, 0) == 0 && fsync(fd) == 0 && fsync(directory) == 0, "Cannot durably prepare PF enable journal")
      return fd
    } catch { close(fd); throw error }
  }
  func clearPendingOutput() throws {
    if unlinkat(directory, pendingName, 0) != 0 && errno != ENOENT { throw GuardError("Cannot clear completed enable journal") }
    try require(fsync(directory) == 0, "Cannot persist completed enable journal")
  }

}

private func systemAnchorChildren() throws -> [String] {
  // The kernel rejects queries for absent anchors with EINVAL. Establish absence
  // from the existing parent tree, never by treating a failed query as empty.
  let roots = canonicalRules(try checked(["-s", "Anchors"]))
  guard roots.contains("com.apple") else { return [] }
  return canonicalRules(try checked(["-a", "com.apple", "-s", "Anchors"]))
}
private func hasOwnAnchor(_ uid: UInt32) throws -> Bool {
  let children = try systemAnchorChildren()
  return children.contains("000.ClashPartyAutoDNS.\(uid)") || children.contains(anchor(uid))
}
private func matchesRules(_ uid: UInt32) throws -> Bool {
  let info = try checked(["-s", "info"])
  guard info.contains("Status: Enabled") else { return false }
  try validateRootRules(try checked(["-sr"]))
  try validateSkippedInterfaces(try checked(["-s", "Interfaces", "-v"]))
  let expected = canonicalRules(try checked(["-nvf", "-"], input: fixedRules))
  try require(!expected.isEmpty, "PF rule parser returned no canonical rules")
  let children = try systemAnchorChildren()
  let ownName = "000.ClashPartyAutoDNS.\(uid)"
  guard children.contains(ownName) || children.contains(anchor(uid)) else { return false }
  try require(children.first == ownName || children.first == anchor(uid), "DNS guard is not the first system wildcard anchor")
  let actual = canonicalRules(try checked(["-a", anchor(uid), "-sr"]))
  guard actual == expected else { return false }
  return noExistingDNSStates(try checked(["-s", "states"]))
}
private func resolverPreflight() throws {
  var info = stat()
  if lstat("/etc/resolver", &info) != 0 { if errno == ENOENT { return }; throw GuardError("Cannot inspect scoped resolvers") }
  try require((info.st_mode & S_IFMT) == S_IFDIR && info.st_uid == 0 && (info.st_mode & 0o022) == 0, "Scoped resolver directory is not trusted")
  try checkRootPath("/private/etc/resolver", file: false)
  for name in try FileManager.default.contentsOfDirectory(atPath: "/etc/resolver") {
    let path = "/etc/resolver/" + name
    try require(lstat(path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFREG && info.st_uid == 0 && (info.st_mode & 0o022) == 0 && info.st_size <= 32768, "Scoped resolver entry is unreadable or unsafe")
    try rejectWritableACL(path)
    try require(safeResolver(try String(contentsOfFile: path, encoding: .utf8)), "A scoped resolver points outside loopback; review it before enabling DNS protection")
  }
}
private func loopbackListeners(_ output: String) -> Set<String> {
  var addresses = Set<String>()
  for line in output.split(whereSeparator: \.isNewline) {
    guard line.hasPrefix("n"), line.hasSuffix(":53") else { continue }
    var address = String(line.dropFirst().dropLast(3))
    if address.hasPrefix("["), address.hasSuffix("]") { address = String(address.dropFirst().dropLast()) }
    var v4 = in_addr(), v6 = in6_addr()
    if address.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
      if address.split(separator: ".").first == "127" { addresses.insert(address) }
    } else if address.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
      let bytes = withUnsafeBytes(of: &v6) { Array($0) }
      if bytes.dropLast().allSatisfy({ $0 == 0 }) && bytes.last == 1 { addresses.insert("::1") }
    }
  }
  return addresses
}
private func listenerPreflight(corePid: Int32) throws {
  let args = ["-nP", "-a", "-p", String(corePid), "-Fn"]
  let tcp = try run("/usr/sbin/lsof", args + ["-iTCP", "-sTCP:LISTEN"])
  let udp = try run("/usr/sbin/lsof", args + ["-iUDP"])
  let both = loopbackListeners(tcp.output).intersection(loopbackListeners(udp.output))
  try require(tcp.code == 0 && udp.code == 0 && !both.isEmpty, "Owned core TCP and UDP numeric loopback DNS listeners must both be ready")
}
private struct Reference { let pid: Int32; let token: String; let age: Double }
private func references(_ text: String) throws -> [Reference] {
  try require(text.contains("TOKEN") && text.contains("PID"), "Unknown PF reference readback format")
  var result = [Reference]()
  for line in text.split(whereSeparator: \.isNewline) {
    let words = line.split(whereSeparator: \.isWhitespace).map(String.init)
    guard let first = words.first, isDigits(first) else { continue }
    try require(words.count >= 2, "Unknown PF reference row")
    if words[1] != "pfctl" { continue } // Only our fixed pfctl child can own our references.
    try require(words.count >= 6, "Unknown PF reference row")
    guard let pid = Int32(first), isDigits(words[2]), let days = Double(words[3]), words[4] == "days" else { throw GuardError("Unknown PF reference identity format") }
    let time = words[5].split(separator: ":").compactMap { Double($0) }
    try require(time.count == 3 && time[0] >= 0 && time[1] >= 0 && time[1] < 60 && time[2] >= 0 && time[2] < 60, "Unknown PF reference timestamp format")
    result.append(Reference(pid: pid, token: words[2], age: days * 86400 + time[0] * 3600 + time[1] * 60 + time[2]))
  }
  return result
}
private func currentReferences() throws -> [Reference] {
  let result = try run(pfctl, ["-s", "References"])
  if result.code == 0, result.output.contains("TOKEN"), result.output.contains("PID") { return try references(result.output) }
  // A global PF disable invalidates all reference tokens; it is already released.
  let info = try checked(["-s", "info"])
  if info.contains("Status: Disabled") { return [] }
  throw GuardError("Cannot verify actual PF enable references")
}
private func recoverToken(_ state: State, from rows: [Reference]) throws -> String? {
  if let token = state.token { return rows.contains { $0.token == token } ? token : nil }
  guard let pid = state.pendingPid, let since = state.pendingSince else { return nil }
  let matches = rows.filter { $0.pid == pid && abs((Date().timeIntervalSince1970 - $0.age) - since) < 6 }
  try require(matches.count <= 1, "PF enable recovery identity is ambiguous")
  return matches.first?.token
}
private func noExistingDNSStates(_ text: String) -> Bool {
  // PF state lookup precedes filter rules. Never claim protection over an already
  // admitted external port-53 flow, and never flush states owned by other software.
  for line in text.split(whereSeparator: \.isNewline) where line.contains(" udp ") || line.contains(" tcp ") {
    for raw in line.split(whereSeparator: \.isWhitespace) {
      let address = raw.trimmingCharacters(in: CharacterSet(charactersIn: "()"))
      if address.hasSuffix(":53") || address.hasSuffix("[53]") {
        if !address.hasPrefix("127.") && !address.hasPrefix("[::1]:") && !address.hasPrefix("::1[") { return false }
      }
    }
  }
  return true
}
private func readStateReply(uid: UInt32, state: State?, boot: String) throws -> Reply {
  let active = try matchesRules(uid)
  let core = state?.boot == boot ? state?.corePid : nil
  return Reply(active: active, ownerUid: uid, corePid: core, reason: active ? nil : (state?.desired == true ? "Protection is desired but actual PF rules are inactive or incompatible" : "DNS guard is not active"))
}
private func operate(_ action: String, uid: UInt32, caller: proc_bsdinfo?, corePid: Int32?) throws -> Reply {
  let store = try Store(uid: uid)
  let boot = try bootIdentifier()
  var saved = try store.load()
  if action == "status" { return try readStateReply(uid: uid, state: saved, boot: boot) }
  if let existing = saved, existing.boot == boot, existing.appPid != Int32(caller?.pbi_pid ?? 0), let other = try? processInfo(existing.appPid), other.pbi_start_tvsec * 1_000_000 + other.pbi_start_tvusec == existing.appStart, caller != nil {
    throw GuardError("Another live application owns this DNS guard")
  }
  if action == "stop" {
    // Root recovery is possible without a running app. No global PF disable/flush.
    if saved == nil {
      if try hasOwnAnchor(uid) {
        try require(canonicalRules(try checked(["-a", anchor(uid), "-sr"])).isEmpty, "An unjournalled guard anchor exists; administrator review is required")
      }
      return Reply(active: false, ownerUid: uid, corePid: nil, reason: "No owned guard recovery state")
    }
    saved!.desired = false
    try store.save(saved!)
    let token = saved!.boot == boot ? try recoverToken(saved!, from: currentReferences()) : nil
    // Always verify the actual current anchor, including stale journal boots.
    // A token from a previous boot must never be released in the new boot.
    if try hasOwnAnchor(uid) { _ = try checked(["-a", anchor(uid), "-F", "rules"]) }
    if try hasOwnAnchor(uid) {
      try require(canonicalRules(try checked(["-a", anchor(uid), "-sr"])).isEmpty, "PF guard anchor did not clear")
    }
    if let token {
      let released = try run(pfctl, ["-X", token])
      let stillOwned = try currentReferences().contains { $0.token == token }
      try require(!stillOwned, "Owned PF reference did not release: " + released.errors.prefix(200))
    }
    saved!.token = nil; saved!.corePid = nil; saved!.pendingPid = nil; saved!.pendingSince = nil; saved!.boot = boot
    try store.save(saved!)
    try store.clearPendingOutput()
    return Reply(active: false, ownerUid: uid, corePid: nil, reason: "Only this guard's anchor and PF reference were released")
  }
  guard let caller, let corePid else { throw GuardError("Missing authenticated core owner") }
  try checkCore(corePid, caller: caller)
  try listenerPreflight(corePid: corePid)
  try resolverPreflight()
  try validateRootRules(try checked(["-sr"]))
  try validateSkippedInterfaces(try checked(["-s", "Interfaces", "-v"]))
  _ = try checked(["-nvf", "-"], input: fixedRules)
  let oldToken = saved?.boot == boot ? try saved.flatMap { try recoverToken($0, from: currentReferences()) } : nil
  var state = State(ownerUid: uid, appPid: Int32(caller.pbi_pid), appStart: caller.pbi_start_tvsec * 1_000_000 + caller.pbi_start_tvusec, corePid: corePid, boot: boot, desired: true, token: oldToken)
  try store.save(state) // Durable intent precedes PF mutation.
  if state.token == nil {
    let output = try store.createPendingOutput()
    defer { close(output) }
    let enabled = try run(pfctl, ["-E"], durableOutput: output, beforeResume: { pid in
      // START_SUSPENDED ensures the child cannot acquire a PF reference before
      // its identity/timestamp are durably recorded for recovery after SIGKILL.
      state.pendingPid = pid; state.pendingSince = Date().timeIntervalSince1970
      try store.save(state)
    })
    try require(fsync(output) == 0, "Cannot persist PF enable result")
    state.token = try recoverToken(state, from: currentReferences())
    try require(enabled.code == 0 && state.token != nil, "Cannot confirm this invocation's PF enable reference; recovery evidence retained")
    try store.save(state)
  }
  _ = try checked(["-a", anchor(uid), "-f", "-"], input: fixedRules)
  try require(try matchesRules(uid), "PF readback did not confirm DNS guard rules")
  try checkCore(corePid, caller: caller)
  return Reply(active: true, ownerUid: uid, corePid: corePid)
}

private func selfTest() throws {
  try require(safeResolver("nameserver 127.0.0.1\n"), "IPv4 fixture")
  try require(safeResolver("nameserver ::1\r\n"), "CRLF fixture")
  try require(safeResolver("nameserver 0:0:0:0:0:0:0:0001\n"), "IPv6 fixture")
  try require(safeResolver("nameserver 0::1.5353\n"), "IPv6 port fixture")
  try require(safeResolver("# nameserver 223.5.5.5\n nameserver 127.0.0.1.5353\n"), "Comments/port fixture")
  try require(!safeResolver("nameserver 127.0.0.1\nnameserver 192.0.2.53\n"), "Fallback fixture")
  try require(!safeResolver("nameserver 2001:db8::1\n"), "IPv6 external fixture")
  try require(!safeResolver("nameserver localhost\n"), "Named host fixture")
  try require(tokenFrom("Token : 12345\n") == "12345" && tokenFrom("Token : not-a-number\n") == nil, "Token fixture")
  try validateRootRules("anchor \"com.apple/*\" all\n")
  do { try validateRootRules("pass quick all\nanchor \"com.apple/*\" all\n"); throw GuardError("Quick-pass fixture accepted") } catch let error as GuardError { try require(error.description != "Quick-pass fixture accepted", "Root rule rejection") }
  try validateSkippedInterfaces("lo0 (skip)\nen0\n")
  do { try validateSkippedInterfaces("en0 (skip)\n"); throw GuardError("Skip fixture accepted") } catch let error as GuardError { try require(error.description != "Skip fixture accepted", "Interface skip rejection") }
  try require(anchor(501) == "com.apple/000.ClashPartyAutoDNS.501", "Anchor scope")
  try require(try parseUID("501") == 501 && (try parsePID("1234")) == 1234, "Numeric ownership fixture")
  for value in ["", "../1", "501;id", "-1", "99999999999999999999"] {
    do { _ = try parseUID(value); throw GuardError("UID fixture accepted") } catch let error as GuardError { try require(error.description != "UID fixture accepted", "UID rejection") }
  }
  var testACL = acl_init(1)
  guard testACL != nil else { throw GuardError("Cannot create in-memory ACL fixture") }
  defer { if let testACL { acl_free(UnsafeMutableRawPointer(testACL)) } }
  try rejectMutableACLEntries(testACL!)
  var testEntry: acl_entry_t?
  try require(acl_create_entry(&testACL, &testEntry) == 0, "Cannot create ACL entry fixture")
  guard let testEntry else { throw GuardError("Missing ACL entry fixture") }
  try require(acl_set_tag_type(testEntry, ACL_EXTENDED_ALLOW) == 0 && acl_set_permset_mask_np(testEntry, UInt64(ACL_WRITE_DATA.rawValue)) == 0, "Cannot set writable ACL fixture")
  do { try rejectMutableACLEntries(testACL!); throw GuardError("Writable ACL fixture accepted") } catch let error as GuardError { try require(error.description != "Writable ACL fixture accepted", "Writable ACL rejection") }
  try require(acl_set_tag_type(testEntry, ACL_EXTENDED_DENY) == 0, "Cannot set deny ACL fixture")
  try rejectMutableACLEntries(testACL!)
  try require(trustedOwnedMode(owner: 0, group: 0, mode: 0o755, applicationsParent: false), "Root-owned mode fixture")
  try require(!trustedOwnedMode(owner: 501, group: 0, mode: 0o755, applicationsParent: false), "User-owned rejection")
  try require(!trustedOwnedMode(owner: 0, group: 80, mode: 0o775, applicationsParent: false), "Writable bundle rejection")
  try require(trustedOwnedMode(owner: 0, group: 80, mode: 0o775, applicationsParent: true), "System Applications admin parent")
  try require(!trustedOwnedMode(owner: 0, group: 80, mode: 0o777, applicationsParent: true), "World-writable rejection")
  try require(loopbackListeners("p123\nn127.0.0.2:53\n") == Set(["127.0.0.2"]), "Custom 127/8 listener fixture")
  try require(loopbackListeners("n[0:0:0:0:0:0:0:0001]:53\n") == Set(["::1"]), "Canonical IPv6 listener fixture")
  try require(loopbackListeners("n*:53\nn[::]:53\nn192.0.2.1:53\nn[2001:db8::1]:53\nnlocalhost:53\nn127.0.0.1:5353\n").isEmpty, "Wildcard/public/named/wrong-port rejection")
  try require(loopbackListeners("n127.0.0.1:53\n").intersection(loopbackListeners("n127.0.0.2:53\n")).isEmpty, "TCP/UDP address mismatch")
  let schema = try JSONSerialization.jsonObject(with: JSONEncoder().encode(Reply(active: false, ownerUid: 501, corePid: nil))) as? [String: Any]
  try require(schema?["corePid"] is NSNull, "Fixed null PID schema")
  let rows = try references("TOKENS:\nPID Process Name TOKEN TIMESTAMP\n1234 pfctl 99999 0 days 00:00:01\n")
  try require(rows.count == 1 && rows[0].pid == 1234 && rows[0].token == "99999", "PF reference fixture")
  try require(noExistingDNSStates("all udp 127.0.0.1:53 <- 127.0.0.1:5000 MULTIPLE:SINGLE\n"), "Loopback state fixture")
  try require(!noExistingDNSStates("all udp 192.0.2.53:53 <- 192.0.2.1:5000 MULTIPLE:SINGLE\n"), "External state rejection")
  print("macos-dns-guard-pure-self-test-ok")
}

private func main() -> Int32 {
  let arguments = Array(CommandLine.arguments.dropFirst())
  if arguments == ["--self-test"] {
    do { try selfTest(); return 0 } catch { fputs("Self-test failed: \(error)\n", stderr); return 1 }
  }
  var uid = getuid()
  setDeadline(uid: uid, stopping: arguments.first == "stop")
  _ = umask(0o077)
  _ = signal(SIGPIPE, SIG_IGN)
  _ = chdir("/")
  do {
    try require(geteuid() == 0, "DNS guard is not installed with required privileges")
    var caller: proc_bsdinfo?, core: Int32?
    let action: String
    if arguments.count == 3 && arguments[0] == "stop" && arguments[1] == "--uid" {
      try require(getuid() == 0, "Only a root administrator may choose a recovery UID")
      uid = try parseUID(arguments[2]); action = "stop"
      setDeadline(uid: uid, stopping: true)
      try require(try processPath(getpid()) == installedTool, "Recovery tool must use its installed path")
      try checkRootPath(installedTool, file: true)
    } else {
      try require(arguments == ["status"] || arguments == ["stop"] || (arguments.count == 2 && arguments[0] == "start"), "Expected start <core-pid>, status, or stop")
      let authenticated = try authenticateCaller(); uid = authenticated.0; caller = authenticated.1
      action = arguments[0]
      if action == "start" { core = try parsePID(arguments[1]) }
    }
    let result = try operate(action, uid: uid, caller: caller, corePid: core)
    print(String(decoding: try JSONEncoder().encode(result), as: UTF8.self)); return 0
  } catch {
    let result = Reply(active: false, ownerUid: uid, corePid: nil, reason: String(describing: error))
    if let data = try? JSONEncoder().encode(result) { print(String(decoding: data, as: UTF8.self)) }
    return 1
  }
}
exit(main())
