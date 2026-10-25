#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace network_guard {
constexpr std::uint32_t Magic = 0x474E5043;
constexpr std::uint32_t Version = 1;
constexpr std::size_t MaxMessage = 65536;
constexpr std::size_t MaxPathCharacters = 8192;
constexpr std::size_t MaxTunCharacters = 256;
constexpr std::uint32_t IoTimeoutMs = 3000;

enum class Operation : std::uint32_t { Status = 1, Arm = 2, Acquire = 3, Release = 4 };
struct Request {
  Operation operation = Operation::Status;
  std::uint32_t corePid = 0;
  std::u16string corePath;
  std::u16string tunName;
};

inline bool allowTun(std::uint32_t corePid, bool verifiedProcess, bool verifiedTun) {
  return corePid != 0 && verifiedProcess && verifiedTun;
}

inline void require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}

inline void validate(const Request& request) {
  require(request.corePath.size() <= MaxPathCharacters && request.tunName.size() <= MaxTunCharacters,
          "Request fields exceed the protocol limit");
  require(request.corePath.find(u'\0') == std::u16string::npos &&
              request.tunName.find(u'\0') == std::u16string::npos,
          "Request fields contain a null character");
  switch (request.operation) {
    case Operation::Arm:
    case Operation::Acquire:
      require(!request.corePath.empty() && !request.tunName.empty(), "Core path and TUN name are required");
      require((request.operation == Operation::Arm) == (request.corePid == 0), "Invalid core PID");
      break;
    case Operation::Status:
    case Operation::Release:
      require(request.corePid == 0 && request.corePath.empty() && request.tunName.empty(),
              "Unexpected command fields");
      break;
    default:
      throw std::runtime_error("Unknown command");
  }
}

inline void append32(std::vector<std::uint8_t>& data, std::uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8) data.push_back(static_cast<std::uint8_t>(value >> shift));
}

inline std::uint32_t read32(const std::vector<std::uint8_t>& data, std::size_t offset) {
  require(offset + 4 <= data.size(), "Truncated request");
  std::uint32_t value = 0;
  for (unsigned index = 0; index < 4; index++) value |= std::uint32_t(data[offset + index]) << (index * 8);
  return value;
}

inline std::vector<std::uint8_t> encode(const Request& request) {
  validate(request);
  std::vector<std::uint8_t> data;
  for (auto value : {Magic, Version, static_cast<std::uint32_t>(request.operation), request.corePid,
                     static_cast<std::uint32_t>(request.corePath.size()),
                     static_cast<std::uint32_t>(request.tunName.size())}) append32(data, value);
  for (const auto* text : {&request.corePath, &request.tunName}) {
    for (char16_t character : *text) {
      data.push_back(static_cast<std::uint8_t>(character));
      data.push_back(static_cast<std::uint8_t>(character >> 8));
    }
  }
  return data;
}

inline Request decode(const std::vector<std::uint8_t>& data) {
  require(data.size() >= 24 && data.size() <= MaxMessage, "Invalid request size");
  require(read32(data, 0) == Magic && read32(data, 4) == Version, "Invalid protocol identity");
  const auto pathLength = read32(data, 16);
  const auto tunLength = read32(data, 20);
  require(pathLength <= MaxPathCharacters && tunLength <= MaxTunCharacters, "Invalid field length");
  require(24ULL + (std::uint64_t(pathLength) + tunLength) * 2 == data.size(), "Invalid payload length");
  Request request;
  request.operation = static_cast<Operation>(read32(data, 8));
  request.corePid = read32(data, 12);
  std::size_t offset = 24;
  for (auto entry : {std::make_pair(&request.corePath, pathLength), std::make_pair(&request.tunName, tunLength)}) {
    for (std::uint32_t index = 0; index < entry.second; index++, offset += 2) {
      entry.first->push_back(static_cast<char16_t>(data[offset] | (std::uint16_t(data[offset + 1]) << 8)));
    }
  }
  validate(request);
  return request;
}

struct LocalV4Prefix { std::uint32_t address; std::uint32_t mask; };
inline constexpr std::array<LocalV4Prefix, 6> LocalV4 = {{
    {0x0A000000, 0xFF000000}, {0xAC100000, 0xFFF00000}, {0xC0A80000, 0xFFFF0000},
    {0xA9FE0000, 0xFFFF0000}, {0xE0000000, 0xFFFFFF00}, {0xEFFFFFFA, 0xFFFFFFFF}}};
struct LocalV6Prefix { std::array<std::uint8_t, 16> address; std::uint8_t length; };
inline constexpr std::array<LocalV6Prefix, 3> LocalV6 = {{
    {{{0xFC}}, 7}, {{{0xFE, 0x80}}, 10}, {{{0xFF, 0x02}}, 16}}};

inline bool localV4(std::uint32_t address) {
  for (const auto& prefix : LocalV4) if ((address & prefix.mask) == prefix.address) return true;
  return false;
}

inline unsigned selfTest() {
  unsigned cases = 0;
  auto check = [&](bool value, const char* message) { require(value, message); cases++; };
  for (const auto& request : std::array<Request, 4>{{
           {Operation::Status, 0, {}, {}}, {Operation::Release, 0, {}, {}},
           {Operation::Arm, 0, u"C:\\app\\resources\\sidecar\\mihomo.exe", u"virtual α"},
           {Operation::Acquire, 123, u"C:\\app\\resources\\sidecar\\mihomo.exe", u"virtual α"}}}) {
    const auto actual = decode(encode(request));
    check(actual.operation == request.operation && actual.corePid == request.corePid &&
              actual.corePath == request.corePath && actual.tunName == request.tunName,
          "Protocol round-trip failed");
  }
  auto rejects = [&](std::vector<std::uint8_t> data) {
    bool failed = false;
    try { (void)decode(data); } catch (const std::runtime_error&) { failed = true; }
    check(failed, "Malformed request accepted");
  };
  rejects({});
  auto invalid = encode(Request{}); invalid[4] = 2; rejects(invalid);
  invalid = encode(Request{}); invalid[8] = 99; rejects(invalid);
  invalid = encode(Request{}); invalid[16] = 255; rejects(invalid);
  invalid = encode(Request{}); invalid.push_back(0); rejects(invalid);
  invalid = encode(Request{}); invalid[12] = 1; rejects(invalid);
  check(localV4(0x0A010203) && localV4(0xAC1FFFFF) && localV4(0xC0A80101), "Private LAN range missing");
  check(!localV4(0xAC200001) && !localV4(0x08080808), "Public IPv4 allowed as LAN");
  check(LocalV6[0].length == 7 && LocalV6[1].length == 10 && LocalV6[2].length == 16,
        "IPv6 local scope changed");
  check(!allowTun(0, false, true), "Arm allowed an existing unowned TUN");
  check(!allowTun(123, false, true), "Unverified process opened TUN egress");
  check(!allowTun(123, true, false), "Unverified adapter opened TUN egress");
  check(allowTun(123, true, true), "Verified acquisition cannot use its TUN");
  return cases;
}
}  // namespace network_guard
