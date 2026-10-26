// Fixed local protocol and dynamic WFP ownership; no service installation or persistent filters.
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <tlhelp32.h>
#include <initguid.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <sddl.h>
#include <rpc.h>
#include <objbase.h>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <utility>
#include "policy.h"
#include "process-launch.h"

namespace fs = std::filesystem;
namespace ng = network_guard;
namespace {
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
  void reset() {
    if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
    value = nullptr;
  }
  bool valid() const { return value && value != INVALID_HANDLE_VALUE; }
};

void winCheck(DWORD code, const char* operation) {
  if (code != ERROR_SUCCESS) throw std::runtime_error(std::string(operation) + " failed (" + std::to_string(code) + ")");
}
void handleCheck(const Handle& handle, const char* operation) {
  if (!handle.valid()) {
    const DWORD error = GetLastError();
    winCheck(error == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : error, operation);
  }
}
std::string utf8(const std::wstring& value) {
  if (value.empty()) return {};
  const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  ng::require(size > 0, "Invalid UTF-16 text");
  std::string result(static_cast<std::size_t>(size), '\0');
  ng::require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr) == size,
              "UTF-8 conversion failed");
  return result;
}
std::string json(const std::string& text) {
  std::ostringstream result;
  result << '"';
  constexpr char hex[] = "0123456789abcdef";
  for (const unsigned char character : text) {
    if (character == '"' || character == '\\') result << '\\' << character;
    else if (character < 32) result << "\\u00" << hex[character >> 4] << hex[character & 15];
    else result << character;
  }
  result << '"';
  return result.str();
}
std::wstring widen(const std::u16string& value) { return std::wstring(value.begin(), value.end()); }
std::u16string narrow16(const std::wstring& value) { return std::u16string(value.begin(), value.end()); }
bool equalPath(const std::wstring& left, const std::wstring& right) {
  return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_EQUAL;
}

std::wstring canonicalHandlePath(HANDLE file) {
  std::wstring result(32768, L'\0');
  const auto size = GetFinalPathNameByHandleW(file, result.data(), static_cast<DWORD>(result.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  ng::require(size > 0 && size < result.size(), "Cannot resolve local file identity");
  result.resize(size);
  ng::require(result.rfind(L"\\\\?\\UNC\\", 0) != 0, "Network executable paths are not allowed");
  if (result.rfind(L"\\\\?\\", 0) == 0) result.erase(0, 4);
  ng::require(result.size() > 3 && result[1] == L':', "Executable must be on a local drive");
  return result;
}
std::wstring canonicalPath(const std::wstring& value) {
  Handle file(CreateFileW(value.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  handleCheck(file, "Open file identity");
  return canonicalHandlePath(file.value);
}
std::wstring selfPath() {
  std::wstring result(32768, L'\0');
  const auto size = GetModuleFileNameW(nullptr, result.data(), static_cast<DWORD>(result.size()));
  ng::require(size > 0 && size < result.size(), "Cannot resolve helper executable");
  result.resize(size);
  return canonicalPath(result);
}
std::wstring processPath(HANDLE process) {
  std::wstring result(32768, L'\0');
  DWORD size = static_cast<DWORD>(result.size());
  if (!QueryFullProcessImageNameW(process, 0, result.data(), &size)) winCheck(GetLastError(), "Query process image");
  result.resize(size);
  return canonicalPath(result);
}
std::wstring elevatedUser(HANDLE process) {
  Handle token;
  if (!OpenProcessToken(process, TOKEN_QUERY, &token.value)) winCheck(GetLastError(), "Open process token");
  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  if (!GetTokenInformation(token.value, TokenElevation, &elevation, sizeof(elevation), &size))
    winCheck(GetLastError(), "Read token elevation");
  ng::require(elevation.TokenIsElevated != 0, "An elevated same-user process is required");
  GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
  ng::require(size > 0 && size <= 65536, "Invalid token identity size");
  std::vector<std::uint8_t> storage(size);
  if (!GetTokenInformation(token.value, TokenUser, storage.data(), size, &size)) winCheck(GetLastError(), "Read token identity");
  LPWSTR text = nullptr;
  if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid, &text))
    winCheck(GetLastError(), "Convert token identity");
  const std::wstring result(text);
  LocalFree(text);
  return result;
}
// The WMI provider can retain an OS-owned quota Job even when breakaway was requested.
// A Job-free direct launch and a verified service-origin launch are different lifetimes.
// Never trust a command flag, process basename or caller-supplied PID as provenance.
DWORD verifyLocalWmiCreator() {
  Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
  handleCheck(snapshot, "Snapshot guard creator");
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  DWORD parentPid = 0;
  if (!Process32FirstW(snapshot.value, &entry)) winCheck(GetLastError(), "Read guard creator");
  do {
    if (entry.th32ProcessID == GetCurrentProcessId()) {
      parentPid = entry.th32ParentProcessID;
      break;
    }
  } while (Process32NextW(snapshot.value, &entry));
  ng::require(parentPid != 0, "Local WMI creator is unconfirmed");
  Handle parent(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, parentPid));
  handleCheck(parent, "Open local WMI creator");
  ng::require(WaitForSingleObject(parent.value, 0) == WAIT_TIMEOUT, "Local WMI creator has exited");
  FILETIME parentCreated{}, childCreated{}, exited{}, kernel{}, user{};
  if (!GetProcessTimes(parent.value, &parentCreated, &exited, &kernel, &user) ||
      !GetProcessTimes(GetCurrentProcess(), &childCreated, &exited, &kernel, &user))
    winCheck(GetLastError(), "Read creator lifetime");
  ng::require(CompareFileTime(&parentCreated, &childCreated) < 0, "Local WMI creator PID was reused");
  std::wstring system(32768, L'\0');
  const auto length = GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size()));
  ng::require(length > 0 && length < system.size(), "Cannot resolve Windows system directory");
  system.resize(length);
  ng::require(equalPath(processPath(parent.value), canonicalPath(system + L"\\wbem\\WmiPrvSE.exe")),
              "Guard broker creator is not the Windows system WMI provider");
  DWORD session = 0;
  if (!ProcessIdToSessionId(parentPid, &session)) winCheck(GetLastError(), "Read WMI creator session");
  ng::require(session == 0, "WMI creator is not in the Windows service session");
  Handle token;
  if (!OpenProcessToken(parent.value, TOKEN_QUERY, &token.value)) winCheck(GetLastError(), "Read WMI creator token");
  DWORD size = 0;
  GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
  ng::require(size > 0 && size <= 65536, "Invalid WMI creator identity size");
  std::vector<std::uint8_t> storage(size);
  if (!GetTokenInformation(token.value, TokenUser, storage.data(), size, &size))
    winCheck(GetLastError(), "Read WMI creator identity");
  const auto sid = reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid;
  ng::require(IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinLocalServiceSid) ||
                  IsWellKnownSid(sid, WinNetworkServiceSid),
              "WMI creator does not have a built-in service identity");
  return parentPid;
}
struct LaunchOrigin { bool broker = false; bool inJob = false; DWORD creator = 0; };
LaunchOrigin verifyLaunchOrigin(bool broker) {
  BOOL inJob = FALSE;
  if (!IsProcessInJob(GetCurrentProcess(), nullptr, &inJob)) winCheck(GetLastError(), "Inspect process job");
  if (broker) return {true, inJob != FALSE, verifyLocalWmiCreator()};
  ng::require(!inJob, "Guard must be launched as an independent process outside an inherited Windows job");
  return {};
}
DWORD currentSession() {
  DWORD session = 0;
  if (!ProcessIdToSessionId(GetCurrentProcessId(), &session)) winCheck(GetLastError(), "Read logon session");
  return session;
}
std::wstring pipeName(const std::wstring& sid) {
  return L"\\\\.\\pipe\\ClashParty.NetworkGuard.v1." + sid + L"." + std::to_wstring(currentSession());
}
Handle verifyPeer(DWORD pid, const std::wstring& sid) {
  Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
  handleCheck(process, "Open IPC peer");
  DWORD session = std::numeric_limits<DWORD>::max();
  if (!ProcessIdToSessionId(pid, &session)) winCheck(GetLastError(), "Read IPC peer session");
  ng::require(session == currentSession() && elevatedUser(process.value) == sid &&
                  equalPath(processPath(process.value), selfPath()),
              "IPC peer identity does not match this elevated helper");
  return process;
}

DWORD io(HANDLE pipe, bool write, std::vector<std::uint8_t>& bytes) {
  Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  handleCheck(event, "Create I/O event");
  OVERLAPPED overlapped{};
  overlapped.hEvent = event.value;
  DWORD transferred = 0;
  const auto size = static_cast<DWORD>(bytes.size());
  const BOOL done = write ? WriteFile(pipe, bytes.data(), size, &transferred, &overlapped)
                          : ReadFile(pipe, bytes.data(), size, &transferred, &overlapped);
  if (!done) {
    const DWORD error = GetLastError();
    if (error != ERROR_IO_PENDING) winCheck(error, "Named pipe I/O");
    const DWORD wait = WaitForSingleObject(event.value, ng::IoTimeoutMs);
    if (wait != WAIT_OBJECT_0) {
      CancelIoEx(pipe, &overlapped);
      GetOverlappedResult(pipe, &overlapped, &transferred, TRUE);
      throw std::runtime_error("Named pipe I/O timed out");
    }
    if (!GetOverlappedResult(pipe, &overlapped, &transferred, FALSE)) winCheck(GetLastError(), "Complete named pipe I/O");
  }
  if (write) ng::require(transferred == size, "Incomplete named pipe write");
  return transferred;
}
std::vector<std::uint8_t> readMessage(HANDLE pipe) {
  std::vector<std::uint8_t> bytes(ng::MaxMessage);
  const auto size = io(pipe, false, bytes);
  ng::require(size > 0, "Empty named pipe message");
  bytes.resize(size);
  return bytes;
}
void writeMessage(HANDLE pipe, const std::string& message) {
  ng::require(!message.empty() && message.size() <= ng::MaxMessage, "Invalid response size");
  std::vector<std::uint8_t> bytes(message.begin(), message.end());
  io(pipe, true, bytes);
}

// IF_TYPE_PROP_VIRTUAL alone is insufficient: match the adapter's actual driver service as well.
bool wintunService(const GUID& interfaceGuid) {
  wchar_t guidText[40]{};
  ng::require(StringFromGUID2(interfaceGuid, guidText, 40) > 0, "Cannot format interface GUID");
  HDEVINFO devices = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT);
  if (devices == INVALID_HANDLE_VALUE) winCheck(GetLastError(), "Enumerate network devices");
  bool matches = false;
  try {
    SP_DEVINFO_DATA device{};
    device.cbSize = sizeof(device);
    for (DWORD index = 0; SetupDiEnumDeviceInfo(devices, index, &device); index++) {
      wchar_t service[256]{};
      DWORD type = 0;
      DWORD serviceLength = 0;
      if (!SetupDiGetDeviceRegistryPropertyW(devices, &device, SPDRP_SERVICE, &type,
                                              reinterpret_cast<PBYTE>(service), sizeof(service), &serviceLength) ||
          type != REG_SZ || serviceLength < sizeof(wchar_t) || serviceLength > sizeof(service) ||
          serviceLength % sizeof(wchar_t) != 0 || service[serviceLength / sizeof(wchar_t) - 1] != L'\0' ||
          _wcsicmp(service, L"Wintun") != 0) continue;
      HKEY key = SetupDiOpenDevRegKey(devices, &device, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);
      if (key == INVALID_HANDLE_VALUE) continue;
      wchar_t instance[256]{};
      DWORD length = sizeof(instance);
      const auto result = RegQueryValueExW(key, L"NetCfgInstanceId", nullptr, &type,
                                         reinterpret_cast<LPBYTE>(instance), &length);
      RegCloseKey(key);
      if (result == ERROR_SUCCESS && type == REG_SZ && length >= sizeof(wchar_t) &&
          length <= sizeof(instance) && length % sizeof(wchar_t) == 0 && instance[(length / sizeof(wchar_t)) - 1] == L'\0' &&
          _wcsicmp(instance, guidText) == 0) { matches = true; break; }
    }
  } catch (...) { SetupDiDestroyDeviceInfoList(devices); throw; }
  SetupDiDestroyDeviceInfoList(devices);
  return matches;
}
struct TunIdentity { NET_LUID luid{}; NET_IFINDEX index = 0; };
std::optional<TunIdentity> resolveTun(const std::wstring& name) {
  PMIB_IF_TABLE2 raw = nullptr;
  winCheck(GetIfTable2(&raw), "Enumerate interface aliases");
  std::unique_ptr<MIB_IF_TABLE2, decltype(&FreeMibTable)> table(raw, &FreeMibTable);
  std::optional<NET_LUID> luid;
  for (ULONG index = 0; index < table->NumEntries; index++) {
    if (_wcsicmp(table->Table[index].Alias, name.c_str()) != 0) continue;
    ng::require(!luid.has_value(), "Ambiguous TUN alias");
    luid = table->Table[index].InterfaceLuid;
  }
  if (!luid) return std::nullopt;
  MIB_IF_ROW2 row{};
  row.InterfaceLuid = *luid;
  winCheck(GetIfEntry2(&row), "Inspect TUN interface");
  ng::require(row.Type == IF_TYPE_PROP_VIRTUAL && !row.InterfaceAndOperStatusFlags.HardwareInterface &&
                  !row.InterfaceAndOperStatusFlags.ConnectorPresent && wintunService(row.InterfaceGuid),
              "The configured TUN alias is not a Wintun virtual interface");
  return TunIdentity{row.InterfaceLuid, row.InterfaceIndex};
}

struct Candidate {
  std::wstring corePath;
  std::wstring tunName;
  Handle file;
  Handle process;
  DWORD corePid = 0;
  std::optional<TunIdentity> tun;
};
Candidate prepare(const ng::Request& request, const std::wstring& sid) {
  Candidate candidate;
  candidate.tunName = widen(request.tunName);
  const auto supplied = widen(request.corePath);
  ng::require(fs::path(supplied).is_absolute(), "Core path must be absolute");
  candidate.file = Handle(CreateFileW(supplied.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                     nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  handleCheck(candidate.file, "Lock core executable identity");
  candidate.corePath = canonicalHandlePath(candidate.file.value);
  const auto core = fs::path(candidate.corePath);
  const auto directory = fs::path(selfPath()).parent_path().parent_path() / L"sidecar";
  const auto filename = core.filename().wstring();
  ng::require(equalPath(core.parent_path().wstring(), directory.wstring()) &&
                  (equalPath(filename, L"mihomo.exe") || equalPath(filename, L"mihomo-alpha.exe") ||
                   equalPath(filename, L"mihomo-smart.exe")),
              "Only bundled sibling sidecar executables may receive a core exception");
  BY_HANDLE_FILE_INFORMATION identity{};
  if (!GetFileInformationByHandle(candidate.file.value, &identity)) winCheck(GetLastError(), "Read core identity");
  ng::require((identity.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0,
              "Invalid core executable identity");
  candidate.tun = resolveTun(candidate.tunName);
  if (request.operation == ng::Operation::Acquire) {
    ng::require(candidate.tun.has_value(), "The actual Wintun interface is not ready");
    candidate.corePid = request.corePid;
    candidate.process = Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, request.corePid));
    handleCheck(candidate.process, "Open core process");
    ng::require(WaitForSingleObject(candidate.process.value, 0) == WAIT_TIMEOUT &&
                    equalPath(processPath(candidate.process.value), candidate.corePath) &&
                    elevatedUser(candidate.process.value) == sid,
                "Core PID does not match the elevated bundled executable");
  } else {
    // An existing interface with the requested alias may belong to an unrelated process.
    // Arm is deliberately a closed startup barrier; only verified acquisition opens TUN egress.
    candidate.tun.reset();
  }
  return candidate;
}

FWPM_FILTER_CONDITION0 condition(const GUID& key, FWP_DATA_TYPE type) {
  FWPM_FILTER_CONDITION0 value{};
  value.fieldKey = key;
  value.matchType = FWP_MATCH_EQUAL;
  value.conditionValue.type = type;
  return value;
}
class AppID {
 public:
  FWP_BYTE_BLOB* value = nullptr;
  explicit AppID(const std::wstring& executable) {
    winCheck(FwpmGetAppIdFromFileName0(executable.c_str(), &value), "Resolve executable AppID");
  }
  ~AppID() { if (value) FwpmFreeMemory0(reinterpret_cast<void**>(&value)); }
  AppID(const AppID&) = delete;
  AppID& operator=(const AppID&) = delete;
};
std::wstring dhcpServicePath() {
  std::wstring directory(32768, L'\0');
  const auto size = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
  ng::require(size > 0 && size < directory.size(), "Cannot locate the Windows DHCP service host");
  directory.resize(size);
  return canonicalPath((fs::path(directory) / L"svchost.exe").wstring());
}
class Guard {
  HANDLE engine_ = nullptr;
  GUID provider_{};
  GUID sublayer_{};
  std::vector<UINT64> filters_;
  std::optional<Candidate> active_;

  void verifyFilter(UINT64 id) const {
    FWPM_FILTER0* filter = nullptr;
    winCheck(FwpmFilterGetById0(engine_, id, &filter), "Verify owned WFP filter");
    const bool valid = filter && filter->providerKey && IsEqualGUID(*filter->providerKey, provider_) &&
                       IsEqualGUID(filter->subLayerKey, sublayer_) &&
                       (filter->flags & FWPM_FILTER_FLAG_DISABLED) == 0;
    FwpmFreeMemory0(reinterpret_cast<void**>(&filter));
    ng::require(valid, "An owned WFP filter is no longer active");
  }

  void initialize() {
    if (engine_) return;
    FWPM_SESSION0 session{};
    session.displayData.name = const_cast<wchar_t*>(L"Clash Party network guard session");
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.txnWaitTimeoutInMSec = ng::IoTimeoutMs;
    winCheck(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine_), "Open dynamic WFP session");
    try {
      for (auto* key : {&provider_, &sublayer_}) {
        const auto result = UuidCreate(key);
        if (result != RPC_S_UUID_LOCAL_ONLY) winCheck(result, "Create owned WFP GUID");
      }
      FWPM_PROVIDER0 provider{};
      provider.providerKey = provider_;
      provider.displayData.name = const_cast<wchar_t*>(L"Clash Party session network guard");
      winCheck(FwpmProviderAdd0(engine_, &provider, nullptr), "Add owned WFP provider");
      FWPM_SUBLAYER0 sublayer{};
      sublayer.subLayerKey = sublayer_;
      sublayer.providerKey = &provider_;
      sublayer.displayData.name = const_cast<wchar_t*>(L"Clash Party session guard rules");
      sublayer.weight = 0xFFFE;
      winCheck(FwpmSubLayerAdd0(engine_, &sublayer, nullptr), "Add owned WFP sublayer");
    } catch (...) { FwpmEngineClose0(engine_); engine_ = nullptr; throw; }
  }
  void add(const GUID& layer, FWP_ACTION_TYPE action, UINT8 weight,
           std::vector<FWPM_FILTER_CONDITION0> conditions, std::vector<UINT64>& ids) {
    FWPM_FILTER0 filter{};
    filter.displayData.name = const_cast<wchar_t*>(action == FWP_ACTION_PERMIT ? L"Clash Party scoped exception" : L"Clash Party direct egress block");
    filter.providerKey = &provider_;
    filter.layerKey = layer;
    filter.subLayerKey = sublayer_;
    // Default filter permit is soft; default filter block is hard. Never clear action rights
    // on an exception: another provider's firewall denial must remain able to block it.
    filter.flags = 0;
    filter.action.type = action;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    filter.numFilterConditions = static_cast<UINT32>(conditions.size());
    filter.filterCondition = conditions.empty() ? nullptr : conditions.data();
    UINT64 id = 0;
    winCheck(FwpmFilterAdd0(engine_, &filter, nullptr, &id), "Add owned WFP filter");
    ids.push_back(id);
  }
  void layerRules(const GUID& layer, bool ipv6, Candidate& candidate, FWP_BYTE_BLOB* app, FWP_BYTE_BLOB* dhcpApp,
                  std::vector<UINT64>& ids) {
    auto application = condition(FWPM_CONDITION_ALE_APP_ID, FWP_BYTE_BLOB_TYPE);
    application.conditionValue.byteBlob = app;
    add(layer, FWP_ACTION_PERMIT, 15, {application}, ids);
    auto loopback = condition(FWPM_CONDITION_FLAGS, FWP_UINT32);
    loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
    loopback.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
    add(layer, FWP_ACTION_PERMIT, 15, {loopback}, ids);
    if (ng::allowTun(candidate.corePid, candidate.process.valid(), candidate.tun.has_value())) {
      auto tun = condition(FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_UINT64);
      tun.conditionValue.uint64 = &candidate.tun->luid.Value;
      add(layer, FWP_ACTION_PERMIT, 14, {tun}, ids);
    }
    // LAN services are preserved, but a physical LAN resolver is not an exception to port 53.
    auto dns = condition(FWPM_CONDITION_IP_REMOTE_PORT, FWP_UINT16);
    dns.conditionValue.uint16 = 53;
    add(layer, FWP_ACTION_BLOCK, 13, {dns}, ids);
    if (!ipv6) {
      for (const auto& prefix : ng::LocalV4) {
        FWP_V4_ADDR_AND_MASK range{prefix.address, prefix.mask};
        auto local = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_V4_ADDR_MASK);
        local.conditionValue.v4AddrMask = &range;
        add(layer, FWP_ACTION_PERMIT, 12, {local}, ids);
      }
    } else {
      for (const auto& prefix : ng::LocalV6) {
        FWP_V6_ADDR_AND_MASK range{};
        std::copy(prefix.address.begin(), prefix.address.end(), range.addr);
        range.prefixLength = prefix.length;
        auto local = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_V6_ADDR_MASK);
        local.conditionValue.v6AddrMask = &range;
        add(layer, FWP_ACTION_PERMIT, 12, {local}, ids);
      }
      for (UINT16 type : {UINT16(133), UINT16(135), UINT16(136)}) {
        auto protocol = condition(FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8);
        protocol.conditionValue.uint8 = IPPROTO_ICMPV6;
        auto icmp = condition(FWPM_CONDITION_ICMP_TYPE, FWP_UINT16);
        icmp.conditionValue.uint16 = type;
        auto code = condition(FWPM_CONDITION_ICMP_CODE, FWP_UINT16);
        code.conditionValue.uint16 = 0;
        add(layer, FWP_ACTION_PERMIT, 12, {protocol, icmp, code}, ids);
      }
    }
    // DHCP renewal can use a public server address. Scope this exception to the actual
    // Windows service-host AppID and client/server ports, never all applications on those ports.
    auto service = condition(FWPM_CONDITION_ALE_APP_ID, FWP_BYTE_BLOB_TYPE);
    service.conditionValue.byteBlob = dhcpApp;
    auto protocol = condition(FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8);
    protocol.conditionValue.uint8 = IPPROTO_UDP;
    auto localPort = condition(FWPM_CONDITION_IP_LOCAL_PORT, FWP_UINT16);
    localPort.conditionValue.uint16 = ipv6 ? 546 : 68;
    auto remotePort = condition(FWPM_CONDITION_IP_REMOTE_PORT, FWP_UINT16);
    remotePort.conditionValue.uint16 = ipv6 ? 547 : 67;
    add(layer, FWP_ACTION_PERMIT, 12, {service, protocol, localPort, remotePort}, ids);
    add(layer, FWP_ACTION_BLOCK, 0, {}, ids);
  }

 public:
  ~Guard() { if (engine_) FwpmEngineClose0(engine_); }
  void replace(Candidate candidate) {
    AppID app(candidate.corePath);
    AppID dhcp(dhcpServicePath());
    initialize();
    winCheck(FwpmTransactionBegin0(engine_, 0), "Begin WFP replacement");
    try {
      // WFP commits the delete/add set atomically. Any validation/add/commit failure leaves
      // the previous rules and file/process identity alive, including during automatic restart.
      for (const auto id : filters_) {
        verifyFilter(id);
        winCheck(FwpmFilterDeleteById0(engine_, id), "Delete owned filter in transaction");
      }
      std::vector<UINT64> replacement;
      layerRules(FWPM_LAYER_ALE_AUTH_CONNECT_V4, false, candidate, app.value, dhcp.value, replacement);
      layerRules(FWPM_LAYER_ALE_AUTH_CONNECT_V6, true, candidate, app.value, dhcp.value, replacement);
      layerRules(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false, candidate, app.value, dhcp.value, replacement);
      layerRules(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, true, candidate, app.value, dhcp.value, replacement);
      winCheck(FwpmTransactionCommit0(engine_), "Commit WFP replacement");
      filters_ = std::move(replacement);
      active_ = std::move(candidate);
    } catch (...) { FwpmTransactionAbort0(engine_); throw; }
  }
  void release() {
    if (engine_) {
      winCheck(FwpmEngineClose0(engine_), "Release owned dynamic WFP session");
      engine_ = nullptr;
    }
    filters_.clear();
    active_.reset();
  }
  std::string status(const LaunchOrigin& origin) const {
    // A BFE restart or an administrator removing our rules must not leave a stale active report.
    for (const auto id : filters_) verifyFilter(id);
    std::ostringstream out;
    out << "{\"protocolVersion\":1,\"active\":" << (active_ ? "true" : "false")
        << ",\"guardPid\":" << GetCurrentProcessId() << ",\"corePid\":";
    if (active_ && active_->corePid) out << active_->corePid; else out << "null";
    out << ",\"coreAlive\":" << ((active_ && active_->process.valid() && WaitForSingleObject(active_->process.value, 0) == WAIT_TIMEOUT) ? "true" : "false");
    out << ",\"corePath\":" << (active_ ? json(utf8(active_->corePath)) : "null")
        << ",\"tunName\":" << (active_ ? json(utf8(active_->tunName)) : "null") << ",\"tunLuid\":";
    if (active_ && active_->tun) out << json(std::to_string(active_->tun->luid.Value)); else out << "null";
    out << ",\"tunIndex\":";
    if (active_ && active_->tun) out << active_->tun->index; else out << "null";
    out << ",\"filterCount\":" << filters_.size()
        << ",\"launchOrigin\":" << json(origin.broker ? "local-wmi" : "job-free")
        << ",\"jobMember\":" << (origin.inJob ? "true" : "false")
        << ",\"creatorPid\":" << origin.creator << '}';
    return out.str();
  }
};

std::string absentStatus() {
  return "{\"protocolVersion\":1,\"active\":false,\"guardPid\":null,\"corePid\":null,\"coreAlive\":false,\"corePath\":null,\"tunName\":null,\"tunLuid\":null,\"tunIndex\":null,\"filterCount\":0}";
}
std::string errorJson(const std::exception& error) {
  return "{\"protocolVersion\":1,\"error\":" + json(error.what()) + '}';
}
void connect(HANDLE pipe) {
  Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  handleCheck(event, "Create connection event");
  OVERLAPPED overlapped{};
  overlapped.hEvent = event.value;
  if (!ConnectNamedPipe(pipe, &overlapped)) {
    const DWORD error = GetLastError();
    if (error == ERROR_PIPE_CONNECTED) return;
    if (error != ERROR_IO_PENDING) winCheck(error, "Accept local client");
    winCheck(WaitForSingleObject(event.value, INFINITE) == WAIT_OBJECT_0 ? ERROR_SUCCESS : GetLastError(), "Wait for local client");
    DWORD transferred = 0;
    if (!GetOverlappedResult(pipe, &overlapped, &transferred, FALSE)) winCheck(GetLastError(), "Complete local connection");
  }
}
void serve(const std::wstring& sid, bool broker = false) {
  const auto origin = verifyLaunchOrigin(broker);
  // Filtering is machine-wide. Refuse a second session/user owner rather than install two
  // incompatible global policies whose respective core exceptions would block each other.
  PSECURITY_DESCRIPTOR ownerSecurity = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1,
                                                            &ownerSecurity, nullptr))
    winCheck(GetLastError(), "Create owner mutex ACL");
  SECURITY_ATTRIBUTES ownerAttributes{sizeof(SECURITY_ATTRIBUTES), ownerSecurity, FALSE};
  SetLastError(ERROR_SUCCESS);
  Handle owner(CreateMutexW(&ownerAttributes, FALSE, L"Global\\ClashParty.NetworkGuard.v1.Owner"));
  const DWORD ownerError = GetLastError();
  LocalFree(ownerSecurity);
  if (!owner.valid()) winCheck(ownerError == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : ownerError,
                              "Reserve machine-wide guard ownership");
  ng::require(ownerError != ERROR_ALREADY_EXISTS, "Another network guard already owns this machine session");
  const std::wstring descriptor = L"D:P(A;;GA;;;SY)(A;;GA;;;" + sid + L")";
  PSECURITY_DESCRIPTOR security = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor.c_str(), SDDL_REVISION_1, &security, nullptr))
    winCheck(GetLastError(), "Create pipe ACL");
  SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), security, FALSE};
  Handle pipe(CreateNamedPipeW(pipeName(sid).c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                               PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                               1, static_cast<DWORD>(ng::MaxMessage), static_cast<DWORD>(ng::MaxMessage), ng::IoTimeoutMs, &attributes));
  LocalFree(security);
  handleCheck(pipe, "Create private local command pipe");
  Guard guard;
  std::cout << "READY\n" << std::flush;
  for (;;) {
    try {
      connect(pipe.value);
    } catch (...) {
      // A client connecting and disappearing before authentication must not terminate the
      // rule owner. Keep the existing guard and recover the listener independently.
      DisconnectNamedPipe(pipe.value);
      Sleep(50);
      continue;
    }
    bool shouldExit = false;
    std::string response;
    try {
      const auto bytes = readMessage(pipe.value);
      ULONG client = 0;
      if (!GetNamedPipeClientProcessId(pipe.value, &client)) winCheck(GetLastError(), "Identify local client");
      verifyPeer(client, sid);
      const auto request = ng::decode(bytes);
      if (request.operation == ng::Operation::Arm || request.operation == ng::Operation::Acquire)
        guard.replace(prepare(request, sid));
      if (request.operation == ng::Operation::Release) { guard.release(); shouldExit = true; }
      response = "0" + guard.status(origin);
    } catch (const std::exception& error) {
      response = "1" + errorJson(error);
    }
    try {
      writeMessage(pipe.value, response);
      // A bounded acknowledgement avoids DisconnectNamedPipe discarding a reply before its
      // client has consumed it. FlushFileBuffers could wait forever on an unresponsive peer.
      const auto ack = readMessage(pipe.value);
      ng::require(ack.size() == 1 && ack[0] == 6, "Invalid response acknowledgement");
    } catch (...) {}
    DisconnectNamedPipe(pipe.value);
    if (shouldExit) return;
  }
}
int client(const ng::Request& request, const std::wstring& sid) {
  const auto name = pipeName(sid);
  Handle pipe(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr));
  if (!pipe.valid()) {
    const auto error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND && (request.operation == ng::Operation::Status || request.operation == ng::Operation::Release)) {
      std::cout << absentStatus() << '\n'; return 0;
    }
    if (error == ERROR_PIPE_BUSY && WaitNamedPipeW(name.c_str(), ng::IoTimeoutMs))
      pipe = Handle(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr));
    handleCheck(pipe, "Connect to existing guard");
  }
  ULONG server = 0;
  if (!GetNamedPipeServerProcessId(pipe.value, &server)) winCheck(GetLastError(), "Identify guard server");
  const auto serverProcess = verifyPeer(server, sid);
  DWORD mode = PIPE_READMODE_MESSAGE;
  if (!SetNamedPipeHandleState(pipe.value, &mode, nullptr, nullptr)) winCheck(GetLastError(), "Set pipe message mode");
  auto bytes = ng::encode(request);
  io(pipe.value, true, bytes);
  const auto response = readMessage(pipe.value);
  ng::require(response.size() > 1 && (response[0] == '0' || response[0] == '1'), "Invalid helper response");
  std::vector<std::uint8_t> ack{6};
  io(pipe.value, true, ack);
  if (response[0] == '0' && request.operation == ng::Operation::Release)
    ng::require(WaitForSingleObject(serverProcess.value, ng::IoTimeoutMs) == WAIT_OBJECT_0,
                "Guard released its rules but did not finish exiting");
  std::cout << std::string(response.begin() + 1, response.end()) << '\n';
  return response[0] == '0' ? 0 : 1;
}

int start(const std::wstring& sid) {
  auto child = ng::launch::independent(selfPath(), L"serve");
  const auto line = ng::launch::startupLine(child);
  if (line != "READY") {
    // This bounded startup message comes only from our canonical executable. Preserve the
    // native error JSON instead of hiding it behind an eventual pipe-not-found error.
    if (line.rfind("{\"protocolVersion\":1,\"error\":", 0) != 0)
      throw std::runtime_error("Invalid independent guard startup response");
    std::cout << line << '\n';
    return 1;
  }
  ng::Request status;
  status.operation = ng::Operation::Status;
  // Reuse authenticated IPC: READY alone is not proof of a working command pipe.
  return client(status, sid);
}

ng::Request arguments(int argc, wchar_t** argv) {
  ng::require(argc >= 2, "Expected a fixed command: start, serve, status, arm, acquire, release or recover");
  const std::wstring command(argv[1]);
  ng::Request request;
  if (command == L"status") request.operation = ng::Operation::Status;
  else if (command == L"release" || command == L"recover") request.operation = ng::Operation::Release;
  else if (command == L"arm") request.operation = ng::Operation::Arm;
  else if (command == L"acquire") request.operation = ng::Operation::Acquire;
  else throw std::runtime_error("Unknown command");
  bool pathSeen = false, tunSeen = false, pidSeen = false;
  for (int index = 2; index < argc; index += 2) {
    ng::require(index + 1 < argc, "Missing command value");
    const std::wstring flag(argv[index]), value(argv[index + 1]);
    if (flag == L"--core-path" && !pathSeen) { request.corePath = narrow16(value); pathSeen = true; }
    else if (flag == L"--tun-name" && !tunSeen) { request.tunName = narrow16(value); tunSeen = true; }
    else if (flag == L"--core-pid" && !pidSeen) {
      ng::require(!value.empty() && value.size() <= 10 && value.find_first_not_of(L"0123456789") == std::wstring::npos, "Invalid core PID");
      const auto pid = std::stoull(value);
      ng::require(pid > 0 && pid <= std::numeric_limits<DWORD>::max(), "Invalid core PID");
      request.corePid = static_cast<DWORD>(pid); pidSeen = true;
    } else throw std::runtime_error("Unknown or repeated command argument");
  }
  ng::validate(request);
  return request;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  try {
    // This path does not open BFE, inspect interfaces, start IPC or request elevation.
    if (argc == 2 && std::wstring(argv[1]) == L"--self-test") {
      std::cout << "{\"protocolVersion\":1,\"selfTest\":\"passed\",\"cases\":" << ng::selfTest() << "}\n";
      return 0;
    }
    const auto sid = elevatedUser(GetCurrentProcess());
    if (argc == 2 && std::wstring(argv[1]) == L"start") return start(sid);
    if (argc == 2 && std::wstring(argv[1]) == L"serve") { serve(sid); return 0; }
    if (argc == 2 && std::wstring(argv[1]) == L"serve-wmi") { serve(sid, true); return 0; }
    return client(arguments(argc, argv), sid);
  } catch (const std::exception& error) {
    std::cout << errorJson(error) << '\n';
    return 1;
  }
}
