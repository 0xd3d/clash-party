// Process/job regression tests only: never elevated, never starts the guard or opens WFP.
#include "process-launch.h"
#include <iostream>
#include <limits>

namespace launch = network_guard::launch;
void require(bool ok, const char* text) { if (!ok) throw std::runtime_error(text); }
std::wstring executable() {
  std::wstring path(32768, L'\0');
  const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  require(size > 0 && size < path.size(), "Resolve fixture path");
  path.resize(size);
  return path;
}
void waitExit(const launch::Process& child) {
  require(WaitForSingleObject(child.process.value, 4000) == WAIT_OBJECT_0, "Fixture host did not exit");
}
void host(DWORD breakaway) {
  launch::Handle job(CreateJobObjectW(nullptr, nullptr));
  require(job.valid(), "Create fixture job");
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                          breakaway;
  launch::check(SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
                "Set fixture job policy");
  launch::check(AssignProcessToJobObject(job.value, GetCurrentProcess()), "Assign fixture host job");
  if (breakaway) {
    auto child = launch::independent(executable(), L"--child");
    require(launch::startupLine(child) == "READY", "Independent fixture did not start");
    std::cout << child.pid << '\n' << std::flush;
  } else {
    bool denied = false;
    try {
      auto child = launch::independent(executable(), L"--child");
      // Test-only child: no WFP/listener/policy. A denial must not be reported as success.
      TerminateProcess(child.process.value, 1);
    } catch (const std::exception& error) {
      const std::string reason = error.what();
      denied = reason.find("parent Windows job must permit breakaway") != std::string::npos ||
               reason.find("retained the guard in a parent job") != std::string::npos;
    }
    require(denied, "Restrictive job was not rejected");
    std::cout << "DENIED\n" << std::flush;
  }
  // Closing this kill-on-close job terminates its host, but must not terminate its escaped child.
  Sleep(200);
}
int wmain(int argc, wchar_t** argv) {
  try {
    if (argc == 2) {
      const std::wstring mode(argv[1]);
      if (mode == L"--child") {
        BOOL inJob = TRUE;
        launch::check(IsProcessInJob(GetCurrentProcess(), nullptr, &inJob), "Inspect fixture job");
        require(!inJob, "Child retained a job");
        std::cout << "READY\n" << std::flush;
        Sleep(15000);
        return 0;
      }
      if (mode == L"--allowed-host") { host(JOB_OBJECT_LIMIT_BREAKAWAY_OK); return 0; }
      if (mode == L"--silent-host") { host(JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK); return 0; }
      if (mode == L"--denied-host") { host(0); return 0; }
      if (mode == L"--startup-error") {
        std::cout << "{\"protocolVersion\":1,\"error\":\"fixture startup rejected\"}\n" << std::flush;
        return 1;
      }
      throw std::runtime_error("Unknown fixture mode");
    }
    require(argc == 1, "Invalid fixture arguments");
    for (const auto* mode : {L"--allowed-host", L"--silent-host"}) {
      auto allowed = launch::independent(executable(), mode);
      const auto pidText = launch::startupLine(allowed);
      require(!pidText.empty() && pidText.find_first_not_of("0123456789") == std::string::npos,
              "Allowed host did not report its independent child");
      const auto pid = std::stoull(pidText);
      require(pid > 0 && pid <= std::numeric_limits<DWORD>::max(), "Invalid fixture PID");
      launch::Handle child(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE,
                                       FALSE, static_cast<DWORD>(pid)));
      require(child.valid(), "Open independent fixture child");
      waitExit(allowed);
      require(WaitForSingleObject(child.value, 0) == WAIT_TIMEOUT, "Child died with parent job");
      BOOL inJob = TRUE;
      launch::check(IsProcessInJob(child.value, nullptr, &inJob), "Check survivor job");
      require(!inJob, "Survivor is still in a job");
      TerminateProcess(child.value, 0); // Only the purpose-built, unprivileged fixture is stopped.
      require(WaitForSingleObject(child.value, 3000) == WAIT_OBJECT_0, "Fixture cleanup failed");
    }
    auto denied = launch::independent(executable(), L"--denied-host");
    require(launch::startupLine(denied) == "DENIED", "Restrictive parent job not explained");
    waitExit(denied);
    auto error = launch::independent(executable(), L"--startup-error");
    require(launch::startupLine(error) == "{\"protocolVersion\":1,\"error\":\"fixture startup rejected\"}",
            "Startup error was lost");
    waitExit(error);
    std::cout << "{\"launchSelfTest\":\"passed\",\"cases\":4}\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
