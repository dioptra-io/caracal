#include <arpa/inet.h>
#include <spdlog/fmt/fmt.h>

#include <algorithm>
#include <caracal/checked.hpp>
#include <caracal/checksum.hpp>
#include <caracal/constants.hpp>
#include <caracal/probe.hpp>
#include <caracal/utilities.hpp>
#include <iostream>
#include <sstream>
#include <string>

namespace caracal {

Probe Probe::from_csv(const std::string &line) {
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
      case 4:
        probe.protocol = Protocols::l4_from_string(token);
      default:
        break;
    }
    index++;
  }
  if (index != 5) {
    throw std::runtime_error("Invalid CSV line: " + line);
  }
  return probe;
}

std::string Probe::to_csv() const noexcept {
  auto addr = Utilities::format_addr(dst_addr);
  return fmt::format("{},{},{},{},{}", addr, src_port, dst_port, ttl,
                     Protocols::to_string(protocol));
}

bool Probe::operator==(const Probe &other) const noexcept {
  return IN6_ARE_ADDR_EQUAL(&dst_addr, &other.dst_addr) &&
         (src_port == other.src_port) && (dst_port == other.dst_port) &&
         (ttl == other.ttl);
}

Protocols::L3 Probe::l3_protocol() const noexcept {
  if (IN6_IS_ADDR_V4MAPPED(&dst_addr)) {
    return Protocols::L3::IPv4;
  } else {
    return Protocols::L3::IPv6;
  }
}

Protocols::L4 Probe::l4_protocol() const noexcept { return protocol; }

sockaddr_in Probe::sockaddr4() const noexcept {
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = dst_addr.s6_addr32[3];
  addr.sin_port = htons(dst_port);
  return addr;
}

sockaddr_in6 Probe::sockaddr6() const noexcept {
  sockaddr_in6 addr{};
  addr.sin6_family = AF_INET6;
  addr.sin6_addr = dst_addr;
  addr.sin6_port = htons(dst_port);
  addr.sin6_flowinfo = 0;
  addr.sin6_scope_id = 0;
  return addr;
}

uint16_t Probe::checksum(uint32_t caracal_id) const noexcept {
  // TODO: IPv6 support? Or just encode the last 32 bits for IPv6?
  return Checksum::caracal_checksum(caracal_id, dst_addr.s6_addr32[3], src_port,
                                    ttl);
}

std::ostream &operator<<(std::ostream &os, Probe const &v) {
  auto addr = Utilities::format_addr(v.dst_addr);
  if (v.l3_protocol() == Protocols::L3::IPv4) {
    os << fmt::format("{}:{}:{}:{}@{}", Protocols::to_string(v.protocol),
                      v.src_port, addr, v.dst_port, v.ttl);
  } else {
    os << fmt::format("{}:{}:[{}]:{}@{}", Protocols::to_string(v.protocol),
                      v.src_port, addr, v.dst_port, v.ttl);
  }
  return os;
}

}  // namespace caracal
