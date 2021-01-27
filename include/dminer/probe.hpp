#pragma once

#include <arpa/inet.h>
#include <fmt/format.h>

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>

#include "utilities.hpp"

namespace dminer {

// Quick hack from https://stackoverflow.com/a/966497,
// to make tests pass, since inet_pton returns an error
// on Linux when the address contains leading zeros.
// e.g. 008.008.008.008 => 8.8.8.8.
[[nodiscard]] inline std::string remove_leading_zeros(std::string s) {
  std::replace(s.begin(), s.end(), '.', ' ');
  std::istringstream iss(s);
  int a, b, c, d;
  iss >> a >> b >> c >> d;
  std::ostringstream oss;
  oss << a << '.' << b << '.' << c << '.' << d;
  return oss.str();
}

/// A traceroute probe specification.
struct Probe {
  in6_addr dst_addr;  ///< IPv6 or IPv4-mapped IPv6 address (network order)
  uint16_t src_port;  ///< Source port (host order)
  uint16_t dst_port;  ///< Destination port (host order)
  uint8_t ttl;        ///< Time-to-live

  [[nodiscard]] bool operator==(const Probe &other) const {
    return IN6_ARE_ADDR_EQUAL(&dst_addr, &other.dst_addr) &&
           (src_port == other.src_port) && (dst_port == other.dst_port) &&
           (ttl == other.ttl);
  }

  [[nodiscard]] static Probe from_csv(const std::string &line) {
    Probe probe{};
    int index = 0;
    std::istringstream lstream{line};
    std::string token;
    while (std::getline(lstream, token, ',')) {
      switch (index) {
        case 0:
          // IPv6 (x:x:x:x:x:x:x:x) or IPv4-mapped IPv6 (::ffff:d.d.d.d)
          if (std::find(token.begin(), token.end(), ':') != token.end()) {
            if (inet_pton(AF_INET6, token.c_str(), &probe.dst_addr) != 1) {
              throw std::runtime_error("Invalid IPv6 or IPv4-mapped address: " +
                                       token);
            }
            // IPv4 dotted (d.d.d.d)
          } else if (std::find(token.begin(), token.end(), '.') !=
                     token.end()) {
            token = remove_leading_zeros(token);
            if (inet_pton(AF_INET6, ("::ffff:" + token).c_str(),
                          &probe.dst_addr) != 1) {
              throw std::runtime_error("Invalid IPv4 addresss: " + token);
            }
          } else {
            // IPv4 uint32
            probe.dst_addr.s6_addr32[0] = 0;
            probe.dst_addr.s6_addr32[1] = 0;
            probe.dst_addr.s6_addr32[2] = 0xFFFF0000U;
            probe.dst_addr.s6_addr32[3] = Utilities::htonl(std::stoul(token));
          }
          break;
        case 1:
          probe.src_port = Utilities::stou16(token);
          break;
        case 2:
          probe.dst_port = Utilities::stou16(token);
          break;
        case 3:
          probe.ttl = Utilities::stou8(token);
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

  [[nodiscard]] bool v4() const { return IN6_IS_ADDR_V4MAPPED(&dst_addr); }

  [[nodiscard]] sockaddr_in sockaddr4() const {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = dst_addr.s6_addr32[3];
    addr.sin_port = Utilities::htons(dst_port);
    return addr;
  }

  [[nodiscard]] sockaddr_in6 sockaddr6() const {
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = dst_addr;
    addr.sin6_port = Utilities::htons(dst_port);
    addr.sin6_flowinfo = 0;
    addr.sin6_scope_id = 0;
    return addr;
  }

  [[nodiscard]] std::string to_csv() const {
    return fmt::format("{},{},{},{}", human_dst_addr(), src_port, dst_port,
                       ttl);
  }

  [[nodiscard]] std::string human_dst_addr() const {
    char buf[INET6_ADDRSTRLEN] = {};
    if (v4()) {
      inet_ntop(AF_INET, &dst_addr.s6_addr32[3], buf, INET_ADDRSTRLEN);
    } else {
      inet_ntop(AF_INET6, &dst_addr, buf, INET6_ADDRSTRLEN);
    }
    return std::string{buf};
  }
};

inline std::ostream &operator<<(std::ostream &os, Probe const &v) {
  os << v.src_port << ":";
  if (v.v4()) {
    os << v.human_dst_addr();
  } else {
    os << "[" << v.human_dst_addr() << "]";
  }
  os << ":" << v.dst_port << "@" << +v.ttl;
  return os;
}

}  // namespace dminer
