// Privileged CI-only fixture. Creates one owned Wintun adapter without routes, DNS or WFP.
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <initguid.h>
#include <iostream>
#include "adapter-identity.h"

namespace ng = network_guard;
using CreateAdapter = HANDLE(WINAPI*)(LPCWSTR, LPCWSTR, const GUID*);
using CloseAdapter = VOID(WINAPI*)(HANDLE);
using GetAdapterLuid = VOID(WINAPI*)(HANDLE, NET_LUID*);
class Fixture {
 public:
  HMODULE library = nullptr;
  HANDLE adapter = nullptr;
  CloseAdapter close = nullptr;
  ~Fixture() { reset(); if (library) FreeLibrary(library); }
  void reset() { if (adapter && close) close(adapter); adapter = nullptr; }
};
template <typename T> T procedure(HMODULE library, const char* name) {
  const auto address = GetProcAddress(library, name);
  ng::require(address != nullptr, "Wintun API export missing");
  // GetProcAddress returns a function pointer of unspecified signature.
  static_assert(sizeof(T) == sizeof(address));
  T result;
  memcpy(&result, &address, sizeof(result));
  return result;
}
int wmain(int argc, wchar_t** argv) {
  try {
    ng::require(argc == 2, "Expected absolute CI Wintun DLL path");
    Fixture fixture;
    fixture.library = LoadLibraryExW(argv[1], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!fixture.library) ng::adapterCheck(GetLastError(), "Load pinned CI Wintun");
    const auto create = procedure<CreateAdapter>(fixture.library, "WintunCreateAdapter");
    fixture.close = procedure<CloseAdapter>(fixture.library, "WintunCloseAdapter");
    const auto getLuid = procedure<GetAdapterLuid>(fixture.library, "WintunGetAdapterLUID");
    const auto name = L"CP Guard CI " + std::to_wstring(GetCurrentProcessId());
    ng::require(!ng::inspectTun(name), "CI alias unexpectedly exists");
    fixture.adapter = create(name.c_str(), L"ClashPartyIdentityTest", nullptr);
    if (!fixture.adapter) ng::adapterCheck(GetLastError(), "Create isolated CI Wintun");
    NET_LUID expected{};
    getLuid(fixture.adapter, &expected);
    const auto snapshot = ng::inspectTun(name);
    ng::require(snapshot.has_value(), "Created CI Wintun not visible");
    std::cout << "Observed CI Wintun: " << ng::adapterDiagnostic(*snapshot) << std::endl;
    const auto actual = ng::resolveTun(name);
    ng::require(actual && actual->luid.Value == expected.Value && actual->index != 0,
                "Wintun alias did not resolve to the created adapter");
    unsigned rejectedPhysical = 0;
    PMIB_IF_TABLE2 raw = nullptr;
    ng::adapterCheck(GetIfTable2(&raw), "Enumerate physical rejection fixtures");
    const std::unique_ptr<MIB_IF_TABLE2, decltype(&FreeMibTable)> table(raw, &FreeMibTable);
    for (ULONG index = 0; index < table->NumEntries; index++) {
      const auto& row = table->Table[index];
      if (!row.InterfaceAndOperStatusFlags.HardwareInterface) continue;
      bool rejected = false;
      try { (void)ng::resolveTun(row.Alias); } catch (const std::runtime_error&) { rejected = true; }
      ng::require(rejected, "Physical adapter was accepted as Wintun");
      rejectedPhysical++;
    }
    fixture.reset();
    const auto deadline = GetTickCount64() + 10000;
    while (ng::inspectTun(name) && GetTickCount64() < deadline) Sleep(100);
    ng::require(!ng::inspectTun(name), "Owned CI Wintun was not removed");
    std::cout << "{\"adapterSelfTest\":\"passed\",\"wintunCreatedAndRemoved\":true,\"physicalAdaptersRejected\":"
              << rejectedPhysical << "}\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
