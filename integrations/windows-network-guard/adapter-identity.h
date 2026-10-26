#pragma once

#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <objbase.h>
#include <memory>
#include <optional>
#include <sstream>
#include "policy.h"

namespace network_guard {
inline void adapterCheck(DWORD code, const char* operation) {
  if (code != ERROR_SUCCESS)
    throw std::runtime_error(std::string(operation) + " failed (" + std::to_string(code) + ")");
}
struct DeviceInfoList {
  HDEVINFO value;
  ~DeviceInfoList() { if (value != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(value); }
};
struct DriverIdentity {
  std::wstring service;
  bool matchedDevice = false;
  DWORD error = ERROR_NOT_FOUND;
};

// Compare the OS interface GUID with the network device's driver registry identity.
// An alias, description or virtual flag alone must never authorize an interface.
inline DriverIdentity adapterDriver(const GUID& interfaceGuid) {
  wchar_t guidText[40]{};
  require(StringFromGUID2(interfaceGuid, guidText, 40) > 0, "Cannot format interface GUID");
  const DeviceInfoList devices{SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT)};
  if (devices.value == INVALID_HANDLE_VALUE) adapterCheck(GetLastError(), "Enumerate network devices");
  DriverIdentity identity;
  SP_DEVINFO_DATA device{};
  device.cbSize = sizeof(device);
  for (DWORD index = 0; SetupDiEnumDeviceInfo(devices.value, index, &device); index++) {
    const HKEY key = SetupDiOpenDevRegKey(devices.value, &device, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);
    if (key == INVALID_HANDLE_VALUE) continue;
    wchar_t instance[256]{};
    DWORD type = 0, length = sizeof(instance);
    const auto result = RegQueryValueExW(key, L"NetCfgInstanceId", nullptr, &type,
                                        reinterpret_cast<LPBYTE>(instance), &length);
    RegCloseKey(key);
    if (result != ERROR_SUCCESS || type != REG_SZ || length < sizeof(wchar_t) ||
        length > sizeof(instance) || length % sizeof(wchar_t) != 0 ||
        instance[length / sizeof(wchar_t) - 1] != L'\0' || _wcsicmp(instance, guidText) != 0) continue;
    identity.matchedDevice = true;
    wchar_t service[256]{};
    DWORD required = 0;
    if (!SetupDiGetDeviceRegistryPropertyW(devices.value, &device, SPDRP_SERVICE, &type,
                                          reinterpret_cast<PBYTE>(service), sizeof(service), &required)) {
      identity.error = GetLastError();
    } else if (type != REG_SZ || required < sizeof(wchar_t) || required > sizeof(service) ||
               required % sizeof(wchar_t) != 0 || service[required / sizeof(wchar_t) - 1] != L'\0') {
      identity.error = ERROR_INVALID_DATA;
    } else {
      identity.service = service;
      identity.error = ERROR_SUCCESS;
    }
    break;
  }
  return identity;
}
struct TunIdentity { NET_LUID luid{}; NET_IFINDEX index = 0; };
struct AdapterSnapshot {
  TunIdentity identity;
  ULONG type = 0;
  bool hardware = false;
  bool connector = false;
  DriverIdentity driver;
};
inline bool verifiedWintun(const AdapterSnapshot& snapshot) {
  static_assert(IF_TYPE_PROP_VIRTUAL == 53);
  return verifiedTunAdapter(snapshot.type, snapshot.hardware, snapshot.connector,
      snapshot.driver.matchedDevice && snapshot.driver.error == ERROR_SUCCESS &&
      _wcsicmp(snapshot.driver.service.c_str(), L"Wintun") == 0);
}
inline std::string adapterDiagnostic(const AdapterSnapshot& snapshot) {
  std::string service;
  for (const auto character : snapshot.driver.service.substr(0, 40)) {
    service += character >= 32 && character < 127 ? static_cast<char>(character) : '?';
  }
  std::ostringstream out;
  out << "index=" << snapshot.identity.index << ",type=" << snapshot.type
      << ",hardware=" << snapshot.hardware << ",connector=" << snapshot.connector
      << ",service=" << (service.empty() ? "unknown" : service)
      << ",mapped=" << snapshot.driver.matchedDevice << ",lookup=" << snapshot.driver.error;
  return out.str();
}
inline std::optional<AdapterSnapshot> inspectTun(const std::wstring& name) {
  PMIB_IF_TABLE2 raw = nullptr;
  adapterCheck(GetIfTable2(&raw), "Enumerate interface aliases");
  const std::unique_ptr<MIB_IF_TABLE2, decltype(&FreeMibTable)> table(raw, &FreeMibTable);
  std::optional<NET_LUID> luid;
  for (ULONG index = 0; index < table->NumEntries; index++) {
    if (_wcsicmp(table->Table[index].Alias, name.c_str()) != 0) continue;
    require(!luid.has_value(), "Ambiguous TUN alias");
    luid = table->Table[index].InterfaceLuid;
  }
  if (!luid) return std::nullopt;
  MIB_IF_ROW2 row{};
  row.InterfaceLuid = *luid;
  adapterCheck(GetIfEntry2(&row), "Inspect TUN interface");
  return AdapterSnapshot{{row.InterfaceLuid, row.InterfaceIndex}, row.Type,
      row.InterfaceAndOperStatusFlags.HardwareInterface != 0,
      row.InterfaceAndOperStatusFlags.ConnectorPresent != 0, adapterDriver(row.InterfaceGuid)};
}
inline std::optional<TunIdentity> resolveTun(const std::wstring& name) {
  const auto snapshot = inspectTun(name);
  if (!snapshot) return std::nullopt;
  if (!verifiedWintun(*snapshot))
    throw std::runtime_error("TUN identity rejected: " + adapterDiagnostic(*snapshot));
  return snapshot->identity;
}
}  // namespace network_guard
