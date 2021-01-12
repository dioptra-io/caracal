#pragma once

#include <arpa/inet.h>

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>

namespace dminer {

// Quick hack from https://stackoverflow.com/a/966497,
// to make tests pass, since inet_pton returns an error
// on Linux when the address contains leading zeros.
// e.g. 008.008.008.008 => 8.8.8.8.
inline std::string remove_leading_zeros(std::string s) {
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
  // TODO: Use IPv6 address here (even for IPv4).
  in_addr dst_addr;   ///< IPv6 or IPv4-mapped IPv6 address (network order)
  uint16_t src_port;  ///< @brief Source port (network order)
  uint16_t dst_port;  ///< @brief Destination port (network order)
  uint8_t ttl;        ///< @brief Time-to-live

  bool operator==(const Probe &other) const {
    return (dst_addr.s_addr == other.dst_addr.s_addr) &&
           (src_port == other.src_port) && (dst_port == other.dst_port) &&
           (ttl == other.ttl);
  }

  static Probe from_csv(const std::string &line) {
    Probe probe;
    int index = 0;
    std::istringstream lstream{line};
    std::string token;
    while (std::getline(lstream, token, ',')) {
      switch (index) {
        case 0:
          if (std::find(token.begin(), token.end(), '.') == token.end()) {
            // uint32
            probe.dst_addr.s_addr = htonl(std::stoul(token));
          } else {
            // Dotted notation
            token = remove_leading_zeros(token);
            if (!inet_pton(AF_INET, token.c_str(), &probe.dst_addr)) {
              throw std::runtime_error("Invalid token: " + token);
            }
          }
          break;
        case 1:
          probe.src_port = htons(std::stoul(token));
          break;
        case 2:
          probe.dst_port = htons(std::stoul(token));
          break;
        case 3:
          probe.ttl = std::stoul(token);
          break;
      }
      index++;
    }
    if (index != 4) {
      throw std::runtime_error("Invalid CSV line: " + line);
    }
    return probe;
  }

  std::string to_csv() const {
    std::ostringstream oss;
    oss << human_dst_addr() << "," << ntohs(src_port) << "," << ntohs(dst_port)
        << "," << uint(ttl);
    return oss.str();
  }

  std::string human_dst_addr() const {
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &dst_addr, buf, INET_ADDRSTRLEN);
    return std::string{buf};
  }
};

inline std::ostream &operator<<(std::ostream &os, Probe const &v) {
  os << ntohs(v.src_port) << ":" << v.human_dst_addr() << ":"
     << ntohs(v.dst_port) << "@" << uint(v.ttl);
  return os;
}

}  // namespace dminer
