// Windows CI fixture only. No WFP, core, DNS or permanent OS changes.
#include "process-launch.h"
#include <iostream>
#include <tlhelp32.h>
#include <limits>
namespace launch = network_guard::launch;
void require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
launch::Handle restrictiveJob() {
  launch::Handle job(CreateJobObjectW(nullptr, nullptr));
  require(job.valid(), "Create private fixture job");
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  launch::check(SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
                "Set no-breakaway, kill-on-close fixture job");
  return job;
}
void resume(launch::Process& child, HANDLE job) {
  try {
    launch::check(AssignProcessToJobObject(job, child.process.value), "Put suspended launcher in fixture job");
    launch::check(ResumeThread(child.thread.value) != static_cast<DWORD>(-1), "Resume fixture launcher");
    child.thread.reset();
  } catch (...) {
    TerminateProcess(child.process.value, 1); // Only our new, suspended fixture process.
    throw;
  }
}
void addAmbientJob(const std::wstring& pidText) {
  require(!pidText.empty() && pidText.find_first_not_of(L"0123456789") == std::wstring::npos,
          "Invalid fixture guard PID");
  const auto value = std::stoull(pidText);
  require(value > 0 && value <= std::numeric_limits<DWORD>::max(), "Invalid fixture guard PID range");
  const auto pid = static_cast<DWORD>(value);
  launch::Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE | SYNCHRONIZE,
                                    FALSE, pid));
  require(process.valid() && WaitForSingleObject(process.value, 0) == WAIT_TIMEOUT, "Missing suspended fixture guard");
  std::wstring actual(32768, L'\0'), own(32768, L'\0');
  DWORD actualSize = static_cast<DWORD>(actual.size());
  launch::check(QueryFullProcessImageNameW(process.value, 0, actual.data(), &actualSize), "Read fixture guard path");
  actual.resize(actualSize);
  const auto ownSize = GetModuleFileNameW(nullptr, own.data(), static_cast<DWORD>(own.size()));
  require(ownSize > 0 && ownSize < own.size(), "Read fixture path");
  own.resize(ownSize);
  const auto expected = own.substr(0, own.find_last_of(L"\\") + 1) + L"party.mihomo.network-guard.exe";
  require(CompareStringOrdinal(actual.c_str(), -1, expected.c_str(), -1, TRUE) == CSTR_EQUAL,
          "Refusing to assign an unrelated process to the fixture Job");
  launch::Handle job(CreateJobObjectW(nullptr, nullptr));
  require(job.valid(), "Create ambient fixture Job");
  launch::check(AssignProcessToJobObject(job.value, process.value), "Assign non-app fixture Job");
  launch::Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
  require(snapshot.valid(), "Snapshot suspended fixture thread");
  THREADENTRY32 entry{}; entry.dwSize = sizeof(entry);
  launch::check(Thread32First(snapshot.value, &entry), "Read suspended fixture thread");
  DWORD threadId = 0;
  do {
    if (entry.th32OwnerProcessID == pid) {
      require(threadId == 0, "Fixture guard already has more than its suspended startup thread");
      threadId = entry.th32ThreadID;
    }
  } while (Thread32Next(snapshot.value, &entry));
  require(threadId != 0, "Missing suspended fixture thread");
  launch::Handle thread(OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId));
  require(thread.valid(), "Open suspended fixture thread");
  require(ResumeThread(thread.value) == 1, "Fixture guard was not suspended exactly once");
  // No KILL_ON_JOB_CLOSE: associated processes retain this Job after the fixture exits.
  // It represents a non-app lifetime and is never installed on a user application.
  std::cout << "{\"ambientJobAssigned\":true}\n";
}
int wmain(int argc, wchar_t** argv) {
  try {
    if (argc == 3 && std::wstring(argv[1]) == L"--add-ambient-job") { addAmbientJob(argv[2]); return 0; }
    if (argc == 3 && std::wstring(argv[1]) == L"--reject-origin") {
      for (const auto* command : {L"serve", L"serve-wmi"}) {
        auto job = restrictiveJob();
        auto child = launch::suspended(argv[2], command);
        resume(child, job.value);
        const auto output = launch::startupLine(child, 15000);
        require(WaitForSingleObject(child.process.value, 3000) == WAIT_OBJECT_0,
                "Untrusted helper was not rejected before serving");
        DWORD code = 0;
        launch::check(GetExitCodeProcess(child.process.value, &code), "Read rejection status");
        require(code != 0 && output.find("\"error\":") != std::string::npos,
                "Untrusted launcher unexpectedly succeeded");
        const bool ordinary = std::wstring(command) == L"serve";
        require(output.find(ordinary ? "inherited Windows job" : "not the Windows system WMI provider") != std::string::npos,
                "Wrong startup rejection reason");
      }
      std::cout << "{\"untrustedOriginRejected\":true,\"cases\":2}\n";
      return 0;
    }
    require(argc == 4 && std::wstring(argv[1]) == L"--run-launcher", "Invalid broker fixture arguments");
    const std::wstring encoded(argv[3]);
    require(!encoded.empty() && encoded.find_first_not_of(L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::wstring::npos,
            "Expected an encoded fixture script");
    const auto command = L"-NoLogo -NoProfile -NonInteractive -EncodedCommand " + encoded;
    auto job = restrictiveJob();
    auto child = launch::suspended(argv[2], command.c_str());
    resume(child, job.value);
    const auto result = launch::startupLine(child, 30000);
    require(!result.empty() && result.front() == '{', "Broker did not return JSON");
    if (result.find("\"error\":") != std::string::npos)
      throw std::runtime_error("Broker fixture response: " + result);
    require(WaitForSingleObject(child.process.value, 0) == WAIT_TIMEOUT,
            "Launcher exited before the crash-survival experiment");
    // The PS launcher intentionally remains alive. Closing the only handle forcibly kills
    // its whole no-breakaway job; the authenticated WMI guard must survive independently.
    job.reset();
    require(WaitForSingleObject(child.process.value, 5000) == WAIT_OBJECT_0,
            "Closing the app job did not terminate the fixture launcher");
    std::cout << "{\"launcherJobTerminated\":true,\"broker\":" << result << "}\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
