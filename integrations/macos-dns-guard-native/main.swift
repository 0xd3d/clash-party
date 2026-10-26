// SPDX-License-Identifier: GPL-3.0-only
// Fixed-purpose, opt-in macOS PF DNS guard. Never executes caller commands or rules.
import Foundation
import Darwin
import Security
import OpenDirectory

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
private func setDeadline(uid: UInt32, stopping: Bool, traffic: Bool = false, installing: Bool = false) {
  let seconds = installing ? 29.4 : (traffic ? (stopping ? 5.4 : 7.9) : (stopping ? 1.4 : 3.4))
  commandDeadline = ProcessInfo.processInfo.systemUptime + seconds
  emergencyJSON = strdup("{\"active\":false,\"ownerUid\":\(uid),\"corePid\":null,\"reason\":\"Native DNS guard operation timed out; verify actual protection state\"}\n")
  _ = signal(SIGALRM, deadlineHandler)
  let hard = installing ? 30.0 : (traffic ? (stopping ? 5.5 : 8.0) : (stopping ? 1.5 : 3.5))
  var timer = itimerval(it_interval: timeval(tv_sec: 0, tv_usec: 0), it_value: timeval(tv_sec: Int(hard), tv_usec: Int32((hard - floor(hard)) * 1_000_000)))
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
  var protection: String? = nil
  var dnsLease: Bool? = nil
  var trafficLease: Bool? = nil
  var tunDevice: String? = nil
  private enum CodingKeys: String, CodingKey { case active, ownerUid, corePid, reason, protection, dnsLease, trafficLease, tunDevice }
  func encode(to encoder: Encoder) throws {
    var values = encoder.container(keyedBy: CodingKeys.self)
    try values.encode(active, forKey: .active)
    try values.encode(ownerUid, forKey: .ownerUid)
    if let corePid { try values.encode(corePid, forKey: .corePid) }
    else { try values.encodeNil(forKey: .corePid) }
    try values.encodeIfPresent(reason, forKey: .reason)
    try values.encodeIfPresent(protection, forKey: .protection)
    try values.encodeIfPresent(dnsLease, forKey: .dnsLease)
    try values.encodeIfPresent(trafficLease, forKey: .trafficLease)
    try values.encodeIfPresent(tunDevice, forKey: .tunDevice)
  }
}
private struct State: Codable {
  var version = 2
  var ownerUid: UInt32
  var appPid: Int32
  var appStart: UInt64
  var corePid: Int32?
  var boot: String
  var desired = false
  var token: String?
  var pendingPid: Int32?
  var pendingSince: Double?
  var dnsLease: Bool?
  var trafficLease: Bool?
  var tunDevice: String?
  var tunAllowed: Bool?
  var trafficGid: UInt32?
  var trafficRules: [String]?
  var trafficConfirmed: Bool?
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
private func absentExtendedACL(_ error: Int32, existingMode: mode_t?) -> Bool {
  guard error == ENOENT, let existingMode else { return false }
  let kind = existingMode & S_IFMT
  return kind == S_IFREG || kind == S_IFDIR
}
private func rejectWritableACL(_ path: String) throws {
  errno = 0
  guard let acl = acl_get_file(path, ACL_TYPE_EXTENDED) else {
    let failure = errno
    var info = stat()
    let mode: mode_t? = lstat(path, &info) == 0 ? info.st_mode : nil
    // Darwin also uses ENOENT for an absent extended ACL on an existing object.
    // Confirm the object still exists and is not a link; callers independently
    // enforce root ownership, POSIX modes, ancestry and code identity.
    if absentExtendedACL(failure, existingMode: mode) { return }
    throw GuardError("Cannot inspect installed path ACL: \(path) (errno \(failure))")
  }
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
    try require((state.version == 1 || state.version == 2) && state.ownerUid == uid && (state.token == nil || isDigits(state.token!)), "Guard recovery state is invalid")
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
  private func allowedRootFile(_ value: String) throws {
    try require(["identity.json", "install-intent.json"].contains(value), "Root metadata file is not an internal fixed name")
  }
  func readRootFile(_ value: String) throws -> Data? {
    try allowedRootFile(value)
    let fd = openat(directory, value, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    if fd < 0 { if errno == ENOENT { return nil }; throw GuardError("Cannot read root metadata") }
    defer { close(fd) }
    try validateFile(fd)
    let data = try FileHandle(fileDescriptor: fd, closeOnDealloc: false).read(upToCount: 32769) ?? Data()
    try require(data.count <= 32768, "Root metadata exceeds safety limit")
    return data
  }
  func writeRootFile(_ value: String, data: Data) throws {
    try allowedRootFile(value)
    let temporary = ".metadata-\(UUID().uuidString)"
    let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    try require(fd >= 0, "Cannot create root metadata")
    defer { close(fd); unlinkat(directory, temporary, 0) }
    try require(data.count <= 32768, "Root metadata exceeds safety limit")
    let written = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
    try require(written == data.count && fsync(fd) == 0 && renameat(directory, temporary, directory, value) == 0 && fsync(directory) == 0, "Cannot durably save root metadata")
  }
  func removeRootFile(_ value: String) throws {
    try allowedRootFile(value)
    if unlinkat(directory, value, 0) != 0 && errno != ENOENT { throw GuardError("Cannot remove completed root metadata") }
    try require(fsync(directory) == 0, "Cannot persist completed root metadata")
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
private func dnsLease(_ state: State?) -> Bool { state?.dnsLease ?? (state?.desired == true && state?.trafficLease != true) }
private func trafficLease(_ state: State?) -> Bool { state?.trafficLease == true }
private func confirmRuleReadback(uid: UInt32, expected: [String]) throws -> Bool {
  guard !expected.isEmpty, try checked(["-s", "info"]).contains("Status: Enabled") else { return false }
  try validateRootRules(checked(["-sr"]))
  try validateSkippedInterfaces(checked(["-s", "Interfaces", "-v"]))
  let children = try systemAnchorChildren(), ownName = "000.ClashPartyAutoDNS.\(uid)"
  guard children.contains(ownName) || children.contains(anchor(uid)) else { return false }
  try require(children.first == ownName || children.first == anchor(uid), "Protection is not the first system wildcard anchor")
  return canonicalRules(try checked(["-a", anchor(uid), "-sr"])) == expected
}
private func mayInheritTrafficProof(_ state: State, boot: String, gid: UInt32) -> Bool {
  state.trafficConfirmed == true && trafficLease(state) && state.boot == boot && state.trafficGid == gid && state.token != nil && state.trafficRules?.isEmpty == false
}
private func verifiedTrafficReadback(_ state: State, uid: UInt32, boot: String, identity: InstalledIdentity) throws -> Bool {
  guard state.boot == boot, trafficLease(state), state.trafficGid == identity.gid, let expected = state.trafficRules,
        expected.count <= 256, expected.allSatisfy({ $0.count <= 4096 }),
        expected.contains(where: { $0.contains("ClashPartyTrafficV1") && $0.hasPrefix("block drop quick") }) else { return false }
  guard try confirmRuleReadback(uid: uid, expected: expected), try recoverToken(state, from: currentReferences()) != nil else { return false }
  return true
}
private func stateReply(uid: UInt32, state: State?, boot: String, store: Store, caller: proc_bsdinfo?) throws -> Reply {
  let dns = dnsLease(state), traffic = trafficLease(state)
  var active = false
  if traffic, let state {
    let identity = try installedIdentity(store)
    if try verifiedTrafficReadback(state, uid: uid, boot: boot, identity: identity) {
      if state.trafficConfirmed != true { try auditTrafficStates(state, identity: identity, caller: caller) }
      active = true
    }
  } else if dns { active = try matchesRules(uid) }
  else if try hasOwnAnchor(uid) {
    try require(canonicalRules(checked(["-a", anchor(uid), "-sr"])).isEmpty, "An unowned protection anchor remains; administrator review is required")
  }
  return Reply(active: active, ownerUid: uid, corePid: state?.boot == boot ? state?.corePid : nil,
               reason: active ? nil : "Protection is inactive or unconfirmed; retained rules and leases were not silently released",
               protection: active ? (traffic ? "traffic" : "dns") : "none", dnsLease: dns, trafficLease: traffic,
               tunDevice: traffic ? state?.tunDevice : nil)
}
private func prepareReference(_ store: Store, state: inout State) throws {
  try store.save(state)
  if state.token != nil { return }
  let output = try store.createPendingOutput()
  defer { close(output) }
  var pendingState = state
  let enabled = try run(pfctl, ["-E"], durableOutput: output, beforeResume: { pid in
    pendingState.pendingPid = pid; pendingState.pendingSince = Date().timeIntervalSince1970
    try store.save(pendingState)
  })
  state = pendingState
  try require(fsync(output) == 0, "Cannot persist PF enable result")
  state.token = try recoverToken(state, from: currentReferences())
  try require(enabled.code == 0 && state.token != nil, "Cannot confirm this invocation's PF enable reference; recovery evidence retained")
  try store.save(state)
}
private func releaseReference(_ store: Store, state: inout State, boot: String, uid: UInt32) throws {
  state.desired = false; state.dnsLease = false; state.trafficLease = false; state.trafficConfirmed = false
  try store.save(state)
  let token = state.boot == boot ? try recoverToken(state, from: currentReferences()) : nil
  if try hasOwnAnchor(uid) { _ = try checked(["-a", anchor(uid), "-F", "rules"]) }
  if try hasOwnAnchor(uid) { try require(canonicalRules(checked(["-a", anchor(uid), "-sr"])).isEmpty, "Own protection anchor did not clear") }
  if let token {
    let released = try run(pfctl, ["-X", token])
    try require(!currentReferences().contains { $0.token == token }, "Owned PF reference did not release: " + released.errors.prefix(200))
  }
  state.token = nil; state.corePid = nil; state.pendingPid = nil; state.pendingSince = nil; state.boot = boot
  state.tunDevice = nil; state.tunAllowed = nil; state.trafficRules = nil; state.trafficGid = nil
  try store.save(state); try store.clearPendingOutput()
}
private func operate(_ action: String, uid: UInt32, caller: proc_bsdinfo?, corePid: Int32?, tunDevice: String? = nil, closeOldPublic: Bool = false) throws -> Reply {
  let store = try Store(uid: uid), boot = try bootIdentifier()
  let saved = try store.load()
  if action == "status" || action == "traffic-status" { return try stateReply(uid: uid, state: saved, boot: boot, store: store, caller: caller) }
  if let existing = saved, existing.boot == boot, existing.appPid != Int32(caller?.pbi_pid ?? 0), let other = try? processInfo(existing.appPid), other.pbi_start_tvsec * 1_000_000 + other.pbi_start_tvusec == existing.appStart, caller != nil {
    throw GuardError("Another live application owns this protection lease")
  }
  if action == "install-identity" {
    try installIdentity(store)
    return Reply(active: false, ownerUid: uid, corePid: nil, reason: "Private core identity installed; no PF or network state changed")
  }
  if action == "repair-core" {
    _ = try repairCoreMetadata(installedIdentity(store))
    return Reply(active: false, ownerUid: uid, corePid: nil, reason: "Trusted core permissions repaired; restart the core to inherit its effective group")
  }
  if action == "stop" || action == "traffic-stop" || action == "recover" {
    guard var state = saved else {
      if try hasOwnAnchor(uid) { try require(canonicalRules(checked(["-a", anchor(uid), "-sr"])).isEmpty, "An unjournalled protection anchor exists; administrator review is required") }
      return Reply(active: false, ownerUid: uid, corePid: nil, protection: "none", dnsLease: false, trafficLease: false)
    }
    state.version = 2; state.dnsLease = dnsLease(state); state.trafficLease = trafficLease(state)
    if action == "stop" || action == "recover" { state.dnsLease = false }
    if action == "traffic-stop" || action == "recover" { state.trafficLease = false; state.trafficConfirmed = false }
    if trafficLease(state) {
      // A DNS-only monitor cannot overwrite or release the stronger traffic lease.
      try store.save(state)
      return try stateReply(uid: uid, state: state, boot: boot, store: store, caller: caller)
    }
    if dnsLease(state) {
      state.desired = true; state.tunAllowed = nil; state.trafficRules = nil; state.trafficGid = nil
      let expected = canonicalRules(try checked(["-nvf", "-"], input: fixedRules))
      try prepareReference(store, state: &state)
      _ = try checked(["-a", anchor(uid), "-f", "-"], input: fixedRules)
      try require(try confirmRuleReadback(uid: uid, expected: expected), "DNS-only protection readback did not match after traffic release")
      return try stateReply(uid: uid, state: state, boot: boot, store: store, caller: caller)
    }
    try releaseReference(store, state: &state, boot: boot, uid: uid)
    return Reply(active: false, ownerUid: uid, corePid: nil, protection: "none", dnsLease: false, trafficLease: false)
  }
  guard let caller else { throw GuardError("Missing authenticated application owner") }
  if action == "start", trafficLease(saved) {
    guard var state = saved, let corePid else { throw GuardError("Traffic lease must be rearmed before DNS-only startup") }
    try checkCore(corePid, caller: caller); try listenerPreflight(corePid: corePid); try resolverPreflight()
    state.dnsLease = true; state.desired = true
    try store.save(state)
    let reply = try stateReply(uid: uid, state: state, boot: boot, store: store, caller: caller)
    try require(reply.active && state.corePid == corePid, "Reacquire the traffic lease for this core before declaring DNS protection ready")
    return reply
  }
  if action == "start" {
    guard let corePid else { throw GuardError("Missing authenticated core owner") }
    try checkCore(corePid, caller: caller); try listenerPreflight(corePid: corePid); try resolverPreflight()
    try validateRootRules(checked(["-sr"])); try validateSkippedInterfaces(checked(["-s", "Interfaces", "-v"]))
    var state = State(ownerUid: uid, appPid: Int32(caller.pbi_pid), appStart: caller.pbi_start_tvsec * 1_000_000 + caller.pbi_start_tvusec, corePid: corePid, boot: boot, desired: true,
                      token: saved?.boot == boot ? try saved.flatMap { try recoverToken($0, from: currentReferences()) } : nil)
    state.dnsLease = true; state.trafficLease = false
    try prepareReference(store, state: &state)
    _ = try checked(["-a", anchor(uid), "-f", "-"], input: fixedRules)
    try require(try matchesRules(uid), "PF readback did not confirm DNS protection; existing external DNS states may need to expire")
    try checkCore(corePid, caller: caller)
    return try stateReply(uid: uid, state: state, boot: boot, store: store, caller: caller)
  }
  try require(["traffic-arm", "traffic-start"].contains(action), "Unknown fixed protection action")
  guard let tunDevice, validTunName(tunDevice) else { throw GuardError("Traffic protection requires a numeric utun device name") }
  let identity = try installedIdentity(store)
  try validateInstalledCores(identity)
  if action == "traffic-start" {
    guard let corePid else { throw GuardError("Missing traffic core PID") }
    try validateTrafficCore(corePid, caller: caller, identity: identity)
    _ = try processSockets(corePid, gid: identity.gid, tun: tunDevice)
    try require(if_nametoindex(tunDevice) > 0, "The authenticated TUN interface is not available")
  }
  try validateRootRules(checked(["-sr"])); try validateSkippedInterfaces(checked(["-s", "Interfaces", "-v"]))
  var continuous = false
  if let old = saved, mayInheritTrafficProof(old, boot: boot, gid: identity.gid) { continuous = try verifiedTrafficReadback(old, uid: uid, boot: boot, identity: identity) }
  let source = try trafficRuleSource(gid: identity.gid, device: action == "traffic-start" ? tunDevice : nil)
  let expected = canonicalRules(try checked(["-nvf", "-"], input: source))
  var state = State(ownerUid: uid, appPid: Int32(caller.pbi_pid), appStart: caller.pbi_start_tvsec * 1_000_000 + caller.pbi_start_tvusec, corePid: action == "traffic-start" ? corePid : nil,
                    boot: boot, desired: true, token: saved?.boot == boot ? try saved.flatMap { try recoverToken($0, from: currentReferences()) } : nil)
  state.dnsLease = dnsLease(saved); state.trafficLease = true; state.tunDevice = tunDevice; state.tunAllowed = action == "traffic-start"
  state.trafficGid = identity.gid; state.trafficRules = expected; state.trafficConfirmed = false
  try prepareReference(store, state: &state)
  _ = try checked(["-a", anchor(uid), "-f", "-"], input: source)
  try require(try verifiedTrafficReadback(state, uid: uid, boot: boot, identity: identity), "Traffic PF readback did not confirm the fixed protected rules")
  if !continuous {
    var audit = state
    if audit.corePid == nil, let previous = saved?.corePid, saved?.boot == boot { audit.corePid = previous }
    try auditTrafficStates(audit, identity: identity, caller: caller, closeOldPublic: action == "traffic-arm" && closeOldPublic)
  }
  if let corePid, action == "traffic-start" { try validateTrafficCore(corePid, caller: caller, identity: identity) }
  state.trafficConfirmed = true
  try store.save(state)
  return try stateReply(uid: uid, state: state, boot: boot, store: store, caller: caller)
}

private let privateNetworks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10", "224.0.0.0/24", "ff02::/16"]
private func validTunName(_ name: String) -> Bool {
  name.hasPrefix("utun") && isDigits(String(name.dropFirst(4))) && name.count <= 14
}
private func trafficRuleSource(gid: UInt32, device: String?) throws -> String {
  try require(gid > 100_000 && gid < 2_000_000_000, "Invalid traffic group")
  if let device { try require(validTunName(device), "Traffic protection accepts only a numeric utun device") }
  var rules = fixedRules
  rules += "pass quick on lo0 all no state\n"
  if let device { rules += "pass quick on \(device) all no state\n" }
  rules += "pass out quick from any to { \(privateNetworks.joined(separator: ", ")) } no state\n"
  rules += "pass in quick from { \(privateNetworks.joined(separator: ", ")) } to any no state\n"
  // Include the matching inbound DHCP replies, without opening generic broadcast traffic.
  rules += "pass out quick inet proto udp from any port 68 to any port 67 no state\n"
  rules += "pass in quick inet proto udp from any port 67 to any port 68 no state\n"
  rules += "pass out quick inet6 proto udp from any port 546 to any port 547 no state\n"
  rules += "pass in quick inet6 proto udp from any port 547 to any port 546 no state\n"
  rules += "pass quick inet6 proto ipv6-icmp from any to { fe80::/10, ff02::/16 } no state\n"
  // Return path/MTU diagnostics are required by the protected core's TCP transports.
  rules += "pass in quick inet proto icmp icmp-type unreach no state\n"
  rules += "pass in quick inet6 proto ipv6-icmp icmp6-type { toobig, unreach, paramprob } no state\n"
  rules += "pass quick proto { tcp udp } from any to any group \(gid) no state\n"
  rules += "block drop quick all label \"ClashPartyTrafficV1\"\n"
  return rules
}
private struct Endpoint: Hashable {
  var host: String
  var port: UInt16
  var family: Int32
}
private func normalizedIP(_ address: String, family: Int32? = nil) -> (String, Int32)? {
  let raw = address.split(separator: "%", maxSplits: 1).first.map(String.init) ?? address
  var v4 = in_addr(), v6 = in6_addr()
  var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
  if (family == nil || family == AF_INET), raw.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
    guard inet_ntop(AF_INET, &v4, &output, socklen_t(output.count)) != nil else { return nil }
    return (String(cString: output), AF_INET)
  }
  if (family == nil || family == AF_INET6), raw.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
    guard inet_ntop(AF_INET6, &v6, &output, socklen_t(output.count)) != nil else { return nil }
    return (String(cString: output), AF_INET6)
  }
  return nil
}
private func parseEndpoint(_ text: String, family: Int32? = nil, wildcard: Bool = false) -> Endpoint? {
  var host: String, rawPort: String
  if text.hasPrefix("["), let close = text.lastIndex(of: "]"), text.index(after: close) < text.endIndex, text[text.index(after: close)] == ":" {
    host = String(text[text.index(after: text.startIndex)..<close])
    rawPort = String(text[text.index(close, offsetBy: 2)...])
  } else if let delimiter = text.lastIndex(of: ":") {
    host = String(text[..<delimiter]); rawPort = String(text[text.index(after: delimiter)...])
  } else { return nil }
  guard isDigits(rawPort), let port = UInt16(rawPort), port > 0 else { return nil }
  if wildcard && host == "*", let family { return Endpoint(host: family == AF_INET ? "0.0.0.0" : "::", port: port, family: family) }
  guard let (numeric, version) = normalizedIP(host, family: family) else { return nil }
  return Endpoint(host: numeric, port: port, family: version)
}
private func loopbackIP(_ host: String) -> Bool { host.hasPrefix("127.") || host == "::1" }
private func localPolicyIP(_ host: String) -> Bool {
  if loopbackIP(host) { return true }
  if let (_, family) = normalizedIP(host), family == AF_INET {
    let bytes = host.split(separator: ".").compactMap { UInt8($0) }
    guard bytes.count == 4 else { return false }
    return bytes[0] == 10 || bytes[0] == 192 && bytes[1] == 168 || bytes[0] == 172 && (16...31).contains(bytes[1]) || bytes[0] == 169 && bytes[1] == 254 || bytes[0] == 224 && bytes[1] == 0 && bytes[2] == 0
  }
  var ipv6 = in6_addr()
  guard host.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 else { return false }
  let bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
  return bytes[0] & 0xfe == 0xfc || bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80 || bytes[0] == 0xff && bytes[1] == 2
}
private struct SocketRecord {
  var pid: Int32
  var fd: Int32
  var proto: String
  var local: Endpoint
  var remote: Endpoint?
}
private func lsofSockets(_ text: String) throws -> [SocketRecord] {
  var result = [SocketRecord](), pid: Int32?, fd: Int32?, proto: String?, family: Int32?, name: String?
  func finish() throws {
    guard let name else { return }
    guard let pid, let fd, let proto, ["TCP", "UDP"].contains(proto), let family else { throw GuardError("Incomplete socket ownership evidence") }
    let endpoints = name.components(separatedBy: "->")
    guard endpoints.count <= 2, let local = parseEndpoint(endpoints[0], family: family, wildcard: true) else { throw GuardError("Unknown numeric socket endpoint format") }
    var remote: Endpoint?
    if endpoints.count == 2 {
      guard let parsed = parseEndpoint(endpoints[1], family: family) else { throw GuardError("Unknown numeric peer endpoint format") }
      remote = parsed
    }
    result.append(SocketRecord(pid: pid, fd: fd, proto: proto.lowercased(), local: local, remote: remote))
  }
  for line in text.split(whereSeparator: \.isNewline) {
    guard let key = line.first else { continue }
    let value = String(line.dropFirst())
    switch key {
    case "p": try finish(); pid = Int32(value); fd = nil; proto = nil; family = nil; name = nil
    case "f": try finish(); fd = Int32(value); proto = nil; family = nil; name = nil
    case "P": proto = value
    case "t": family = value == "IPv4" ? AF_INET : (value == "IPv6" ? AF_INET6 : nil)
    case "n": name = value
    default: break
    }
  }
  try finish()
  return result
}
private struct TrafficState {
  var device: String
  var proto: String
  var first: Endpoint
  var second: Endpoint
}
private func trafficStates(_ text: String) throws -> [TrafficState] {
  var result = [TrafficState]()
  for line in text.split(whereSeparator: \.isNewline) {
    let words = line.split(whereSeparator: \.isWhitespace).map(String.init)
    guard !words.isEmpty else { continue }
    if ["age", "id:", "creatorid:", "expires"].contains(words[0]) { continue }
    try require(words.contains("->") || words.contains("<-"), "Unknown PF state readback; protection cannot be confirmed")
    try require(words.count == 6 && ["tcp", "udp"].contains(words[1]) && ["->", "<-"].contains(words[3]), "An existing PF state has an unsupported protocol, NAT mapping or readback format")
    guard let first = parseEndpoint(words[2]), let second = parseEndpoint(words[4]), first.family == second.family else { throw GuardError("An existing PF state has unrecognized numeric endpoints") }
    result.append(TrafficState(device: words[0], proto: words[1], first: first, second: second))
  }
  return result
}
private func processSockets(_ pid: Int32, gid: UInt32, tun: String? = nil) throws -> Set<Int32> {
  let entrySize = MemoryLayout<proc_fdinfo>.size
  let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
  try require(bytes >= 0 && bytes <= entrySize * 8192, "Core descriptor inventory is unavailable or too large")
  var descriptors = [proc_fdinfo](repeating: proc_fdinfo(), count: max(64, Int(bytes) / entrySize + 64))
  let count = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &descriptors, Int32(descriptors.count * entrySize))
  try require(count >= 0 && Int(count) < descriptors.count * entrySize && Int(count) % entrySize == 0, "Core descriptor inventory changed beyond its safety limit")
  var owned = Set<Int32>(), foundTun = tun == nil
  for descriptor in descriptors.prefix(Int(count) / entrySize) where descriptor.proc_fdtype == PROX_FDTYPE_SOCKET {
    var socket = socket_fdinfo()
    guard proc_pidfdinfo(pid, descriptor.proc_fd, PROC_PIDFDSOCKETINFO, &socket, Int32(MemoryLayout.size(ofValue: socket))) == MemoryLayout.size(ofValue: socket) else { continue }
    // fstat-equivalent socket credentials are taken at socket creation, matching PF's credential lookup.
    if socket.psi.soi_stat.vst_gid == gid && [SOCKINFO_TCP, SOCKINFO_IN].contains(Int(socket.psi.soi_kind)) { owned.insert(descriptor.proc_fd) }
    if socket.psi.soi_kind == SOCKINFO_KERN_CTL {
      var controller = socket.psi.soi_proto.pri_kern_ctl
      let name = withUnsafeBytes(of: &controller.kcsi_name) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
      if name == "com.apple.net.utun_control", controller.kcsi_unit > 0, tun == "utun\(controller.kcsi_unit - 1)" { foundTun = true }
    }
  }
  try require(foundTun, "The requested utun is not owned by the authenticated core")
  return owned
}
private func localAddresses() throws -> Set<String> {
  var first: UnsafeMutablePointer<ifaddrs>?
  try require(getifaddrs(&first) == 0, "Cannot inventory local interface addresses")
  defer { freeifaddrs(first) }
  var addresses = Set<String>(), cursor = first
  while let item = cursor {
    defer { cursor = item.pointee.ifa_next }
    guard let pointer = item.pointee.ifa_addr else { continue }
    let family = Int32(pointer.pointee.sa_family)
    var output = [CChar](repeating: 0, count: Int(NI_MAXHOST))
    if [AF_INET, AF_INET6].contains(family), getnameinfo(pointer, socklen_t(pointer.pointee.sa_len), &output, socklen_t(output.count), nil, 0, NI_NUMERICHOST) == 0,
       let (host, _) = normalizedIP(String(cString: output), family: family) { addresses.insert(host) }
  }
  return addresses
}
private func boundSocket(_ socket: SocketRecord, covers endpoint: Endpoint, local: Set<String>) -> Bool {
  guard socket.local.port == endpoint.port && socket.local.family == endpoint.family else { return false }
  if socket.local.host == endpoint.host { return true }
  return ["0.0.0.0", "::"].contains(socket.local.host) && local.contains(endpoint.host)
}
private func permittedExistingState(_ state: TrafficState, device: String?, core: Int32?, sockets: [SocketRecord], protectedFDs: Set<Int32>, udpInventory: [SocketRecord], local: Set<String>) -> Bool {
  if loopbackIP(state.first.host) && loopbackIP(state.second.host) { return true }
  // LAN DNS remains prohibited even though the destination is otherwise local.
  if state.first.port == 53 || state.second.port == 53 { return false }
  if state.proto == "udp" {
    let ports = Set([state.first.port, state.second.port])
    if state.first.family == AF_INET && ports == Set([UInt16(67), UInt16(68)]) { return true }
    if state.first.family == AF_INET6 && ports == Set([UInt16(546), UInt16(547)]) { return true }
  }
  if state.device == device { return true }
  if localPolicyIP(state.first.host) && localPolicyIP(state.second.host) { return true }
  guard let core else { return false }
  for socket in sockets where socket.pid == core && protectedFDs.contains(socket.fd) && socket.proto == state.proto {
    if let remote = socket.remote, Set([socket.local, remote]) == Set([state.first, state.second]) { return true }
    if state.proto == "udp", socket.remote == nil {
      for candidate in [state.first, state.second] where boundSocket(socket, covers: candidate, local: local) {
        let owners = udpInventory.filter { $0.proto == "udp" && boundSocket($0, covers: candidate, local: local) }
        if !owners.isEmpty && owners.allSatisfy({ $0.pid == core && protectedFDs.contains($0.fd) }) { return true }
      }
    }
  }
  return false
}
private struct OldStatePair: Hashable {
  var local: String
  var remote: String
}
private func oldStatePairs(_ blocked: [TrafficState], snapshot: [TrafficState], local: Set<String>) throws -> Set<OldStatePair> {
  var pairs = Set<OldStatePair>()
  for state in blocked {
    let endpoints = [state.first, state.second]
    let mine = endpoints.filter { local.contains($0.host) }
    try require(mine.count == 1, "Old state endpoint ownership is ambiguous; no automatic broad cleanup is permitted")
    let source = mine[0], destination = state.first == source ? state.second : state.first
    try require(!loopbackIP(destination.host) && !local.contains(destination.host), "Old state is not a verified local-to-peer connection")
    if localPolicyIP(destination.host) {
      // A router/resolver pair is eligible only when every complete snapshot
      // entry for that host pair is plaintext DNS. Preserve mixed SSH/UI pairs.
      let related = snapshot.filter { Set([$0.first.host, $0.second.host]) == Set([source.host, destination.host]) }
      try require(!related.isEmpty && related.allSatisfy({ $0.first.port == 53 || $0.second.port == 53 }), "A LAN DNS peer also has non-DNS state; automatic cleanup would be too broad")
    }
    pairs.insert(OldStatePair(local: source.host, remote: destination.host))
  }
  try require(pairs.count <= 24, "Too many old host pairs for bounded safe cleanup; close pre-existing applications first")
  return pairs
}
private func auditTrafficStates(_ state: State, identity: InstalledIdentity, caller: proc_bsdinfo?, closeOldPublic: Bool = false) throws {
  let states = try trafficStates(checked(["-s", "states"]))
  if states.isEmpty { return }
  var core: Int32?, sockets = [SocketRecord](), owned = Set<Int32>()
  if let pid = state.corePid, let caller, (try? validateTrafficCore(pid, caller: caller, identity: identity)) != nil {
    owned = try processSockets(pid, gid: identity.gid)
    let evidence = try run("/usr/sbin/lsof", ["-nP", "-a", "-p", String(pid), "-iTCP", "-iUDP", "-FpPftn"])
    try require(evidence.code == 0 || evidence.code == 1 && evidence.output.isEmpty, "Cannot read owned core socket endpoints")
    sockets = try lsofSockets(evidence.output); core = pid
  }
  var inventory = [SocketRecord]()
  if states.contains(where: { $0.proto == "udp" }) {
    let evidence = try run("/usr/sbin/lsof", ["-nP", "-iUDP", "-FpPftn"])
    try require(evidence.code == 0 || evidence.code == 1 && evidence.output.isEmpty, "Cannot prove UDP socket ownership")
    // Incomplete global visibility cannot prove a unique UDP binding. Treat it
    // as unknown evidence, never as proof that another owner is absent.
    if evidence.errors.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { inventory = try lsofSockets(evidence.output) }
  }
  let addresses = try localAddresses()
  let blocked = states.filter { !permittedExistingState($0, device: state.tunAllowed == true ? state.tunDevice : nil, core: core, sockets: sockets, protectedFDs: owned, udpInventory: inventory, local: addresses) }
  if blocked.isEmpty { return }
  if closeOldPublic {
    let pairs = try oldStatePairs(blocked, snapshot: states, local: addresses)
    for pair in pairs {
      // Only normalized numeric endpoints derived from the complete trusted
      // snapshot may reach -k. The caller cannot supply an address or CIDR.
      _ = try checked(["-k", pair.local, "-k", pair.remote])
      _ = try checked(["-k", pair.remote, "-k", pair.local])
    }
    try auditTrafficStates(state, identity: identity, caller: caller, closeOldPublic: false)
    return
  }
  throw GuardError("Traffic protection is unconfirmed: pre-existing PF states lack protected-core evidence; close prior public/plaintext-DNS connections and retry. No global states were flushed")
}

private let coreGroupName = "_clashpartycore"
private let coreNames = ["mihomo", "mihomo-alpha", "mihomo-smart"]
private let corePaths = coreNames.map { appPath + "/Contents/Resources/sidecar/" + $0 }
private struct InstalledIdentity: Codable, Equatable {
  var version = 1
  var groupName: String
  var gid: UInt32
  var generatedUID: String
}
private struct CoreMetadata: Codable {
  var path: String
  var device: Int32
  var inode: UInt64
  var uid: UInt32
  var gid: UInt32
  var mode: UInt16
}
private struct IdentityInstallIntent: Codable {
  var identity: InstalledIdentity
  var original: [CoreMetadata]
}
private func localNode() throws -> ODNode {
  try remainingBudget()
  return try ODNode(session: ODSession.default(), type: UInt32(kODNodeTypeLocalNodes))
}
private func localRecords(_ node: ODNode, type: String, name: String? = nil) throws -> [ODRecord] {
  let query = try ODQuery(node: node, forRecordTypes: type, attribute: kODAttributeTypeRecordName,
                          matchType: UInt32(name == nil ? kODMatchAny : kODMatchEqualTo), queryValues: name,
                          returnAttributes: type == kODRecordTypeUsers ? [kODAttributeTypeRecordName, kODAttributeTypePrimaryGroupID] : [kODAttributeTypeRecordName, kODAttributeTypePrimaryGroupID, kODAttributeTypeGUID, kODAttributeTypeGroupMembership, kODAttributeTypeGroupMembers, kODAttributeTypeNestedGroups], maximumResults: name == nil ? 0 : 2)
  let rows = try query.resultsAllowingPartial(false) as? [ODRecord] ?? []
  try require(rows.count <= 4096, "Local directory inventory exceeds safety limit")
  return rows
}
private func recordValues(_ details: [AnyHashable: Any], _ key: String) -> [String] {
  guard let raw = details[key] else { return [] }
  guard let strings = raw as? [String] else { return ["<invalid-directory-value>"] }
  return strings.filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
}
// OpenDirectory uses signed decimal strings for system IDs such as nobody (-2),
// while gid_t is UInt32. Compare normalized numeric IDs, never raw spellings.
private func directoryGID(_ value: String) -> UInt32? {
  if let unsigned = UInt32(value) { return unsigned }
  if let signed = Int32(value), signed < 0 { return UInt32(bitPattern: signed) }
  return nil
}
private func isolatedPrimaryGroup(_ values: [String], privateGID: UInt32) -> Bool {
  guard values.count == 1, let gid = directoryGID(values[0]) else { return false }
  return gid != privateGID
}
private func validateGroupDetails(_ details: [AnyHashable: Any], identity: InstalledIdentity) throws {
  try require(identity.version == 1 && identity.groupName == coreGroupName && identity.gid > 100_000 && identity.gid < 2_000_000_000 && UUID(uuidString: identity.generatedUID) != nil, "Invalid installed core group identity")
  try require(recordValues(details, kODAttributeTypeRecordName) == [coreGroupName] && recordValues(details, kODAttributeTypePrimaryGroupID) == [String(identity.gid)], "Installed core group identity does not match the local directory")
  try require(recordValues(details, kODAttributeTypeGUID).map { $0.uppercased() } == [identity.generatedUID.uppercased()], "Installed core group UUID does not match")
  for key in [kODAttributeTypeGroupMembership, kODAttributeTypeGroupMembers, kODAttributeTypeNestedGroups] {
    try require(recordValues(details, key).isEmpty, "The private core group must not have users or nested groups")
  }
}
private func directoryGroup(_ node: ODNode, identity: InstalledIdentity) throws -> ODRecord {
  let records = try localRecords(node, type: kODRecordTypeGroups, name: coreGroupName)
  try require(records.count == 1, "The private core group is missing or ambiguous; reinstall the PKG")
  let record = records[0]
  try validateGroupDetails(try record.recordDetails(forAttributes: nil), identity: identity)
  for user in try localRecords(node, type: kODRecordTypeUsers) {
    let details = try user.recordDetails(forAttributes: [kODAttributeTypePrimaryGroupID])
    let groups = recordValues(details, kODAttributeTypePrimaryGroupID)
    try require(isolatedPrimaryGroup(groups, privateGID: identity.gid), "A user has the private core group, or primary-group evidence is incomplete")
  }
  return record
}
private func installedIdentity(_ store: Store) throws -> InstalledIdentity {
  guard let data = try store.readRootFile("identity.json") else { throw GuardError("Private core group is not installed; install the updated PKG before enabling traffic protection") }
  let identity = try JSONDecoder().decode(InstalledIdentity.self, from: data)
  _ = try directoryGroup(localNode(), identity: identity)
  return identity
}
private func validateStaticCode(_ path: String) throws {
  var code: SecStaticCode?
  try require(SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, "Cannot inspect trusted installed core code")
  guard let code else { throw GuardError("Missing trusted installed core code") }
  try require(SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess, "An installed core signature is invalid")
}
private func coreMetadata(_ path: String, identity: InstalledIdentity? = nil) throws -> CoreMetadata {
  try require(corePaths.contains(path), "Core path is not a fixed bundled executable")
  try checkRootPath(path, file: true, permitApplicationsAdmin: true)
  try validateStaticCode(path)
  var value = stat()
  try require(lstat(path, &value) == 0, "Cannot inspect installed core metadata")
  if let identity {
    try require(value.st_gid == identity.gid && value.st_mode & 0o7777 == 0o6755, "Trusted cores require the installed private group and mode 6755; repair permissions and restart the core")
  }
  return CoreMetadata(path: path, device: value.st_dev, inode: value.st_ino, uid: value.st_uid, gid: value.st_gid, mode: value.st_mode & 0o7777)
}
private func validateInstalledCores(_ identity: InstalledIdentity) throws {
  for path in corePaths { _ = try coreMetadata(path, identity: identity) }
}
private func restoreCoreMetadata(_ originals: [CoreMetadata]) throws {
  for original in originals {
    try require(corePaths.contains(original.path) && original.uid == 0 && original.mode & 0o022 == 0, "Unsafe core rollback metadata")
    let fd = open(original.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    if fd < 0 && errno == ENOENT { continue }
    try require(fd >= 0, "Cannot open core during permission rollback")
    defer { close(fd) }
    var actual = stat()
    try require(fstat(fd, &actual) == 0 && actual.st_uid == 0 && actual.st_nlink == 1, "Unsafe core permission rollback target")
    // A later PKG may have replaced the old inode. Never apply stale metadata to it.
    if actual.st_dev != original.device || actual.st_ino != original.inode { continue }
    try require(fchown(fd, original.uid, original.gid) == 0 && fchmod(fd, original.mode) == 0 && fsync(fd) == 0, "Core permission rollback could not complete")
  }
}
private func repairCoreMetadata(_ identity: InstalledIdentity) throws -> [CoreMetadata] {
  let originals = try corePaths.map { try coreMetadata($0) }
  do {
    for original in originals {
      let fd = open(original.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
      try require(fd >= 0, "Cannot open trusted core for permission repair")
      defer { close(fd) }
      var actual = stat()
      try require(fstat(fd, &actual) == 0 && actual.st_dev == original.device && actual.st_ino == original.inode && actual.st_uid == 0 && actual.st_nlink == 1, "Core changed during permission repair")
      try require(fchown(fd, 0, identity.gid) == 0 && fchmod(fd, 0o6755) == 0 && fsync(fd) == 0, "Cannot set private core permissions")
    }
    try validateInstalledCores(identity)
    return originals
  } catch {
    do { try restoreCoreMetadata(originals) }
    catch { throw GuardError("Permission repair failed and rollback is incomplete; administrator review required") }
    throw error
  }
}
private func rollbackIdentityInstall(_ intent: IdentityInstallIntent, store: Store, node: ODNode) throws {
  try restoreCoreMetadata(intent.original)
  let rows = try localRecords(node, type: kODRecordTypeGroups, name: coreGroupName)
  if !rows.isEmpty {
    try require(rows.count == 1, "Private group rollback is ambiguous")
    try validateGroupDetails(try rows[0].recordDetails(forAttributes: nil), identity: intent.identity)
    try rows[0].delete()
  }
  try store.removeRootFile("install-intent.json")
}
private func installIdentity(_ store: Store) throws {
  let node = try localNode()
  if let pending = try store.readRootFile("install-intent.json") {
    let intent = try JSONDecoder().decode(IdentityInstallIntent.self, from: pending)
    if let committed = try store.readRootFile("identity.json"), try JSONDecoder().decode(InstalledIdentity.self, from: committed) == intent.identity {
      _ = try directoryGroup(node, identity: intent.identity)
      try store.removeRootFile("install-intent.json")
    } else { try rollbackIdentityInstall(intent, store: store, node: node) }
  }
  if try store.readRootFile("identity.json") != nil {
    _ = try repairCoreMetadata(installedIdentity(store))
    return
  }
  try require(try localRecords(node, type: kODRecordTypeGroups, name: coreGroupName).isEmpty && getgrnam(coreGroupName) == nil, "A pre-existing private group cannot be adopted without ownership evidence")
  var occupied = Set<UInt32>()
  for type in [kODRecordTypeGroups, kODRecordTypeUsers] {
    for record in try localRecords(node, type: type) {
      for value in recordValues(try record.recordDetails(forAttributes: [kODAttributeTypePrimaryGroupID]), kODAttributeTypePrimaryGroupID) {
        if let gid = directoryGID(value) { occupied.insert(gid) }
      }
    }
  }
  var selected: UInt32?
  for _ in 0..<64 {
    let gid = 100_001 + arc4random_uniform(1_000_000_000)
    if !occupied.contains(gid) && getgrgid(gid) == nil { selected = gid; break }
  }
  guard let gid = selected else { throw GuardError("Cannot allocate an unused private core group") }
  let identity = InstalledIdentity(groupName: coreGroupName, gid: gid, generatedUID: UUID().uuidString)
  let original = try corePaths.map { try coreMetadata($0) }
  let intent = IdentityInstallIntent(identity: identity, original: original)
  try store.writeRootFile("install-intent.json", data: JSONEncoder().encode(intent))
  var committed = false
  do {
    _ = try node.createRecord(withRecordType: kODRecordTypeGroups, name: coreGroupName,
        attributes: [kODAttributeTypePrimaryGroupID: [String(gid)], kODAttributeTypeGUID: [identity.generatedUID], kODAttributeTypePassword: ["*"], kODAttributeTypeFullName: ["Clash Party isolated network core"]])
    _ = try directoryGroup(node, identity: identity)
    _ = try repairCoreMetadata(identity)
    try store.writeRootFile("identity.json", data: JSONEncoder().encode(identity))
    committed = true
    try store.removeRootFile("install-intent.json")
  } catch {
    var committedOnDisk = committed
    do {
      if let data = try store.readRootFile("identity.json") {
        let actual = try JSONDecoder().decode(InstalledIdentity.self, from: data)
        try require(actual == identity, "Installed identity changed during its transaction")
        committedOnDisk = true
      }
    } catch { throw GuardError("Cannot prove identity commit state; installer intent is retained for administrator review") }
    if committedOnDisk { throw GuardError("Private identity committed but installer journal cleanup is pending; retry installation without deleting the group") }
    do { try rollbackIdentityInstall(intent, store: store, node: node) }
    catch { throw GuardError("Private group installation failed and rollback needs administrator review; recovery intent retained") }
    throw error
  }
}
private func validateTrafficCore(_ pid: Int32, caller: proc_bsdinfo, identity: InstalledIdentity) throws {
  try checkCore(pid, caller: caller)
  let process = try processInfo(pid)
  try require(process.pbi_uid == 0 && process.pbi_gid == identity.gid && process.pbi_svgid == identity.gid && process.pbi_rgid == caller.pbi_rgid, "Core did not inherit the private effective/saved group; repair permissions and restart it")
  _ = try coreMetadata(processPath(pid), identity: identity)
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
  try require(absentExtendedACL(ENOENT, existingMode: S_IFREG | 0o644), "Existing file without an extended ACL")
  try require(absentExtendedACL(ENOENT, existingMode: S_IFDIR | 0o755), "Existing directory without an extended ACL")
  try require(!absentExtendedACL(ENOENT, existingMode: nil), "Missing path cannot prove absent ACL")
  try require(!absentExtendedACL(ENOENT, existingMode: S_IFLNK | 0o777), "Symlink cannot prove absent ACL")
  for error in [EACCES, EPERM, EINVAL, EOPNOTSUPP, Int32(0)] {
    try require(!absentExtendedACL(error, existingMode: S_IFREG | 0o644), "ACL errors must fail closed")
  }
  try require(directoryGID("-2") == UInt32(bitPattern: -2) && directoryGID("4294967294") == UInt32(bitPattern: -2), "Signed directory group ID normalization")
  try require(isolatedPrimaryGroup(["-2"], privateGID: 100001), "System nobody group remains distinct from the private group")
  for values in [[String](), ["-2", "20"], ["invalid"], ["4294967296"], ["-2147483649"], ["100001"], ["0100001"]] {
    try require(!isolatedPrimaryGroup(values, privateGID: 100001), "Missing, malformed or numerically matching primary groups must be rejected")
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
  let generated = try trafficRuleSource(gid: 123456, device: "utun4")
  try require(generated.hasPrefix(fixedRules) && generated.contains("group 123456 no state") && generated.contains("pass quick on utun4 all no state") && generated.contains("block drop quick all"), "Traffic allowlist precedes fixed deny")
  try require(!generated.contains("user 0") && !generated.contains("en0") && !generated.contains("en10"), "No root-wide or physical-interface bypass")
  try require(try !trafficRuleSource(gid: 123456, device: nil).contains("on utun"), "Pre-spawn arm does not open an unauthenticated TUN")
  for name in ["en0", "utun", "utun1\npass all", "utun-1", "utun0;id"] {
    do { _ = try trafficRuleSource(gid: 123456, device: name); throw GuardError("Unsafe TUN accepted") } catch let error as GuardError { try require(error.description != "Unsafe TUN accepted", "Unsafe TUN rejection") }
  }
  var legacy = State(ownerUid: 501, appPid: 100, appStart: 1, corePid: 101, boot: "fixture", desired: true)
  try require(dnsLease(legacy) && !trafficLease(legacy), "Legacy DNS lease migration")
  legacy.dnsLease = true; legacy.trafficLease = true
  try require(dnsLease(legacy) && trafficLease(legacy), "Independent DNS and traffic leases")
  legacy.dnsLease = false
  try require(!dnsLease(legacy) && trafficLease(legacy), "DNS release cannot revoke traffic")
  let reply = Reply(active: true, ownerUid: 501, corePid: nil, protection: "traffic", dnsLease: false, trafficLease: true, tunDevice: "utun4")
  let trafficSchema = try JSONSerialization.jsonObject(with: JSONEncoder().encode(reply)) as? [String: Any]
  try require(trafficSchema?["corePid"] is NSNull && trafficSchema?["trafficLease"] as? Bool == true && trafficSchema?["dnsLease"] as? Bool == false, "Armed traffic fixed JSON schema")
  legacy.trafficConfirmed = true; legacy.trafficGid = 123456; legacy.token = "42"; legacy.trafficRules = ["fixed-traffic-fixture"]; legacy.corePid = nil
  try require(mayInheritTrafficProof(legacy, boot: "fixture", gid: 123456), "A crashed core does not erase continuous protected-state provenance")
  try require(!mayInheritTrafficProof(legacy, boot: "new-boot", gid: 123456) && !mayInheritTrafficProof(legacy, boot: "fixture", gid: 123457), "Boot/group changes require a fresh old-state audit")
  legacy.trafficLease = false
  try require(!mayInheritTrafficProof(legacy, boot: "fixture", gid: 123456), "An explicitly released traffic lease cannot inherit proof")
  let stateRows = try trafficStates("all tcp 192.0.2.2:5000 -> 203.0.113.7:443 ESTABLISHED:ESTABLISHED\n")
  try require(stateRows.count == 1, "Numeric PF state fixture")
  let socket = SocketRecord(pid: 101, fd: 7, proto: "tcp", local: stateRows[0].first, remote: stateRows[0].second)
  try require(permittedExistingState(stateRows[0], device: nil, core: 101, sockets: [socket], protectedFDs: [7], udpInventory: [], local: []), "Private-group core TCP state evidence")
  try require(!permittedExistingState(stateRows[0], device: nil, core: 101, sockets: [socket], protectedFDs: [], udpInventory: [], local: []), "A process PID alone is insufficient socket group evidence")
  let udpState = TrafficState(device: "all", proto: "udp", first: Endpoint(host: "192.0.2.2", port: 5000, family: AF_INET), second: Endpoint(host: "203.0.113.7", port: 443, family: AF_INET))
  let udp = SocketRecord(pid: 101, fd: 8, proto: "udp", local: Endpoint(host: "0.0.0.0", port: 5000, family: AF_INET), remote: nil)
  try require(permittedExistingState(udpState, device: nil, core: 101, sockets: [udp], protectedFDs: [8], udpInventory: [udp], local: ["192.0.2.2"]), "Uniquely owned private-group unconnected UDP evidence")
  var shared = udp; shared.pid = 102
  try require(!permittedExistingState(udpState, device: nil, core: 101, sockets: [udp], protectedFDs: [8], udpInventory: [udp, shared], local: ["192.0.2.2"]), "Shared UDP binding is not a proven private core flow")
  let dhcp = TrafficState(device: "all", proto: "udp", first: Endpoint(host: "0.0.0.0", port: 68, family: AF_INET), second: Endpoint(host: "255.255.255.255", port: 67, family: AF_INET))
  try require(permittedExistingState(dhcp, device: nil, core: nil, sockets: [], protectedFDs: [], udpInventory: [], local: []), "Necessary DHCP state is not mistaken for a public application")
  let lanDNS = TrafficState(device: "all", proto: "udp", first: Endpoint(host: "192.168.1.2", port: 5000, family: AF_INET), second: Endpoint(host: "192.168.1.1", port: 53, family: AF_INET))
  try require(!permittedExistingState(lanDNS, device: nil, core: nil, sockets: [], protectedFDs: [], udpInventory: [], local: []), "LAN DNS does not inherit LAN transport permission")
  for malformed in ["unknown state format\n", "all tcp 192.0.2.2:5000 (198.51.100.2:5000) -> 203.0.113.7:443 ESTABLISHED:ESTABLISHED\n"] {
    do { _ = try trafficStates(malformed); throw GuardError("Unknown state accepted") } catch let error as GuardError { try require(error.description != "Unknown state accepted", "Unsupported PF state rejection") }
  }
  try require(try oldStatePairs([stateRows[0]], snapshot: stateRows, local: ["192.0.2.2"]) == Set([OldStatePair(local: "192.0.2.2", remote: "203.0.113.7")]), "Public cleanup derives an exact local numeric host pair")
  try require(try oldStatePairs([lanDNS], snapshot: [lanDNS], local: ["192.168.1.2"]).count == 1, "DNS-only LAN pair cleanup")
  var lanSSH = lanDNS; lanSSH.second.port = 22
  do { _ = try oldStatePairs([lanDNS], snapshot: [lanDNS, lanSSH], local: ["192.168.1.2"]); throw GuardError("Mixed LAN peer accepted") } catch let error as GuardError { try require(error.description != "Mixed LAN peer accepted", "Mixed LAN DNS/SSH is preserved") }
  do { _ = try oldStatePairs(stateRows, snapshot: stateRows, local: []); throw GuardError("Unknown local endpoint accepted") } catch let error as GuardError { try require(error.description != "Unknown local endpoint accepted", "Ambiguous host-pair cleanup is refused") }
  let machine = try lsofSockets("p101\nf7\ntIPv4\nPTCP\nn192.0.2.2:5000->203.0.113.7:443\np102\nf9\ntIPv6\nPUDP\nn*:5353\n")
  try require(machine.count == 2 && machine[0].pid == 101 && machine[0].fd == 7 && machine[1].local.host == "::", "Bounded numeric lsof record fixture")
  let identity = InstalledIdentity(groupName: coreGroupName, gid: 123456, generatedUID: "12345678-1234-1234-1234-123456789ABC")
  var details: [AnyHashable: Any] = [kODAttributeTypeRecordName: [coreGroupName], kODAttributeTypePrimaryGroupID: ["123456"], kODAttributeTypeGUID: [identity.generatedUID]]
  try validateGroupDetails(details, identity: identity)
  details[kODAttributeTypeNestedGroups] = ["untrusted-nested-members"]
  do { try validateGroupDetails(details, identity: identity); throw GuardError("Nested group accepted") } catch let error as GuardError { try require(error.description != "Nested group accepted", "No nested private-group members") }

  print("macos-dns-guard-pure-self-test-ok")
}

private func main() -> Int32 {
  let arguments = Array(CommandLine.arguments.dropFirst())
  if arguments == ["--self-test"] {
    do { try selfTest(); return 0 } catch { fputs("Self-test failed: \(error)\n", stderr); return 1 }
  }
  var uid = getuid()
  let traffic = arguments.first?.hasPrefix("traffic-") == true || arguments.first == "repair-core"
  let stopping = ["stop", "traffic-stop", "traffic-status"].contains(arguments.first ?? "")
  setDeadline(uid: uid, stopping: stopping, traffic: traffic, installing: arguments.first == "install-identity")
  _ = umask(0o077); _ = signal(SIGPIPE, SIG_IGN); _ = chdir("/")
  do {
    try require(geteuid() == 0, "Protection helper is not installed with required privileges")
    var caller: proc_bsdinfo?, core: Int32?, device: String?
    var closeOldPublic = false
    let action: String
    if arguments == ["install-identity"] || (arguments.count == 3 && ["stop", "traffic-stop"].contains(arguments[0]) && arguments[1] == "--uid") {
      try require(getuid() == 0, "Only a real root administrator may install identity or choose a recovery UID")
      try require(try processPath(getpid()) == installedTool, "Administrative helper must use its installed path")
      try checkRootPath(installedTool, file: true)
      if arguments[0] == "install-identity" { action = "install-identity" }
      else { uid = try parseUID(arguments[2]); action = "recover"; setDeadline(uid: uid, stopping: true, traffic: true) }
    } else {
      let plain = [["status"], ["stop"], ["traffic-status"], ["traffic-stop"], ["repair-core"]].contains(arguments)
      let dns = arguments.count == 2 && arguments[0] == "start"
      let arm = arguments.first == "traffic-arm" && (arguments.count == 2 || arguments.count == 3 && arguments[2] == "--close-old-public")
      let start = arguments.count == 3 && arguments[0] == "traffic-start"
      try require(plain || dns || arm || start, "Expected a fixed DNS, traffic protection, or core repair operation")
      let authenticated = try authenticateCaller(); uid = authenticated.0; caller = authenticated.1
      action = arguments[0]
      if dns || start { core = try parsePID(arguments[1]) }
      if arm { device = arguments[1]; closeOldPublic = arguments.count == 3 }
      if start { device = arguments[2] }
    }
    let result = try operate(action, uid: uid, caller: caller, corePid: core, tunDevice: device, closeOldPublic: closeOldPublic)
    print(String(decoding: try JSONEncoder().encode(result), as: UTF8.self)); return 0
  } catch {
    let result = Reply(active: false, ownerUid: uid, corePid: nil, reason: String(describing: error))
    if let data = try? JSONEncoder().encode(result) { print(String(decoding: data, as: UTF8.self)) }
    return 1
  }
}
exit(main())
