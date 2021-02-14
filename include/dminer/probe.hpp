#pragma once

#include <arpa/inet.h>
#include <spdlog/fmt/fmt.h>

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

#include "checked.hpp"
#include "constants.hpp"
#include "utilities.hpp"

namespace dminer {

/// A traceroute probe specification.
struct Probe {
  in6_addr dst_addr;  ///< IPv6 or IPv4-mapped IPv6 address (network order)
  uint16_t src_port;  ///< Source port (host order)
  uint16_t dst_port;  ///< Destination port (host order)
  uint8_t ttl;        ///< Time-to-live

  [[nodiscard]] static Probe from_csv(const std::string &line) {
    Probe probe{};
    std::istringstream iss{line};
    std::string token;
    int index = 0;
    while (std::getline(iss, token, ',')) {
      switch (index) {
        case 0:
          Utilities::parse_addr(token, probe.dst_addr);
          break;
        case 1:
          probe.src_port = Checked::stou16(token);
          break;
        case 2:
          probe.dst_port = Checked::stou16(token);
          break;
        case 3:
          probe.ttl = Checked::stou8(token);
          break;
        default:
          break;
      }
      index++;
    }
    if (index != 4) {
      throw std::runtime_error("Invalid CSV line: " + line);
    }
    return probe;
  }

  [[nodiscard]] std::string to_csv() const noexcept {
    auto addr = Utilities::format_addr(dst_addr);
    return fmt::format("{},{},{},{}", addr, src_port, dst_port, ttl);
  }

  [[nodiscard]] bool operator==(const Probe &other) const noexcept {
    return IN6_ARE_ADDR_EQUAL(&dst_addr, &other.dst_addr) &&
           (src_port == other.src_port) && (dst_port == other.dst_port) &&
           (ttl == other.ttl);
  }

  [[nodiscard]] bool v4() const noexcept {
    return IN6_IS_ADDR_V4MAPPED(&dst_addr);
  }

  [[nodiscard]] sockaddr_in sockaddr4() const noexcept {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = dst_addr.s6_addr32[3];
    addr.sin_port = htons(dst_port);
    return addr;
  }

  [[nodiscard]] sockaddr_in6 sockaddr6() const noexcept {
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = dst_addr;
    addr.sin6_port = htons(dst_port);
    addr.sin6_flowinfo = 0;
    addr.sin6_scope_id = 0;
    return addr;
  }
};

inline std::ostream &operator<<(std::ostream &os, Probe const &v) {
  auto addr = Utilities::format_addr(v.dst_addr);
  if (v.v4()) {
    os << fmt::format("{}:{}:{}@{}", v.src_port, addr, v.dst_port, v.ttl);
  } else {
    os << fmt::format("{}:[{}]:{}@{}", v.src_port, addr, v.dst_port, v.ttl);
  }
  return os;
}

}  // namespace dminer
