// Windows-only launcher. No WFP, network settings, shell, service or persistent state.
#pragma once
#include <windows.h>
#include <array>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace network_guard::launch {
class Handle {
 public:
  HANDLE value = nullptr;
  Handle() = default;
  explicit Handle(HANDLE handle) : value(handle) {}
  ~Handle() { reset(); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) { reset(); value = std::exchange(other.value, nullptr); }
    return *this;
  }
  void reset() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); value = nullptr; }
  bool valid() const { return value && value != INVALID_HANDLE_VALUE; }
};
inline void check(BOOL ok, const char* operation) {
  if (!ok) {
    const auto error = GetLastError();
    throw std::runtime_error(std::string(operation) + " failed (" + std::to_string(error) + ")");
  }
}
class Attributes {
 public:
  LPPROC_THREAD_ATTRIBUTE_LIST value = nullptr;
  std::vector<unsigned char> storage;
  Attributes() {
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    if (!size) throw std::runtime_error("Cannot size startup handle allowlist");
    storage.resize(size);
    value = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    check(InitializeProcThreadAttributeList(value, 1, 0, &size), "Initialize startup handle allowlist");
  }
  ~Attributes() { DeleteProcThreadAttributeList(value); }
  Attributes(const Attributes&) = delete;
  Attributes& operator=(const Attributes&) = delete;
};
struct Process { Handle process; Handle thread; Handle output; DWORD pid; };

// Only callers' fixed internal commands are passed here, never profile text or IPC arguments.
inline Process suspended(const std::wstring& executable, const wchar_t* command) {
  if (executable.empty() || executable.find(L'"') != std::wstring::npos)
    throw std::runtime_error("Invalid independent helper executable");
  SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
  Handle read, write;
  check(CreatePipe(&read.value, &write.value, &security, 0), "Create startup diagnostic pipe");
  check(SetHandleInformation(read.value, HANDLE_FLAG_INHERIT, 0), "Protect startup read handle");
  Handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            &security, OPEN_EXISTING, 0, nullptr));
  check(input.valid(), "Open helper null input");
  Attributes attributes;
  std::array<HANDLE, 2> inherited{write.value, input.value};
  check(UpdateProcThreadAttribute(attributes.value, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   inherited.data(), sizeof(inherited), nullptr, nullptr),
        "Allow only startup standard handles");
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = input.value;
  startup.StartupInfo.hStdOutput = write.value;
  startup.StartupInfo.hStdError = write.value;
  startup.lpAttributeList = attributes.value;
  PROCESS_INFORMATION info{};
  std::wstring arguments = L"\"" + executable + L"\" " + command;
  // detached:true in Node separates the console, but does not request Windows job breakaway.
  // Start suspended so no listener/policy exists before we verify complete job independence.
  const DWORD flags = CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED | CREATE_NO_WINDOW |
                      CREATE_NEW_PROCESS_GROUP | EXTENDED_STARTUPINFO_PRESENT;
  BOOL created = CreateProcessW(executable.c_str(), arguments.data(), nullptr, nullptr, TRUE, flags,
                                nullptr, nullptr, &startup.StartupInfo, &info);
  if (!created && GetLastError() == ERROR_ACCESS_DENIED) {
    // Some jobs permit silent breakaway only. A suspended fallback is safe: verify that the
    // child actually escaped every job before executing even its first instruction.
    arguments = L"\"" + executable + L"\" " + command;
    created = CreateProcessW(executable.c_str(), arguments.data(), nullptr, nullptr, TRUE,
                             flags & ~CREATE_BREAKAWAY_FROM_JOB, nullptr, nullptr,
                             &startup.StartupInfo, &info);
  }
  check(created, "Start independent guard; parent Windows job must permit breakaway");
  write.reset();
  return {Handle(info.hProcess), Handle(info.hThread), std::move(read), info.dwProcessId};
}

// Runtime uses nullptr to inspect membership in ANY job. The fixture also verifies escape
// from a known synthetic job while a hosted CI runner may retain its own restrictive ancestor.
inline void resumeOutsideJob(Process& child, HANDLE forbiddenJob = nullptr) {
  try {
    BOOL inJob = TRUE;
    check(IsProcessInJob(child.process.value, forbiddenJob, &inJob), "Verify independent guard job");
    if (inJob) throw std::runtime_error("Windows retained the guard in a parent job; protection was not started");
    check(ResumeThread(child.thread.value) != static_cast<DWORD>(-1), "Resume independent guard");
  } catch (...) {
    // Only this newly created, still-suspended process can be terminated here. It has no rules.
    TerminateProcess(child.process.value, 1);
    WaitForSingleObject(child.process.value, 3000);
    throw;
  }
  child.thread.reset();
}
inline Process independent(const std::wstring& executable, const wchar_t* command) {
  auto child = suspended(executable, command);
  resumeOutsideJob(child); // Never permit a production guard to inherit ANY ancestor job.
  return child;
}

inline std::string startupLine(Process& child) {
  std::string output;
  const auto deadline = GetTickCount64() + 6000;
  for (;;) {
    DWORD available = 0;
    if (!PeekNamedPipe(child.output.value, nullptr, 0, nullptr, &available, nullptr)) {
      const auto error = GetLastError();
      if (error != ERROR_BROKEN_PIPE) check(FALSE, "Read guard startup diagnostics");
      throw std::runtime_error("Guard exited before confirming startup: " + output.substr(0, 256));
    }
    if (available) {
      if (output.size() + available > 4096) throw std::runtime_error("Guard startup response exceeds limit");
      std::vector<char> bytes(available);
      DWORD read = 0;
      check(ReadFile(child.output.value, bytes.data(), available, &read, nullptr), "Read guard startup output");
      output.append(bytes.data(), read);
      const auto end = output.find('\n');
      if (end != std::string::npos) {
        output.resize(end);
        if (!output.empty() && output.back() == '\r') output.pop_back();
        return output;
      }
    }
    if (GetTickCount64() >= deadline)
      // Never terminate a running guard on timeout: another client may already have armed it.
      throw std::runtime_error("Independent guard did not confirm startup within 6 seconds; retry status");
    Sleep(20);
  }
}
}  // namespace network_guard::launch
