#pragma once

#include <arpa/inet.h>

#include <string>

#include "./protocols.hpp"

namespace caracal {

/// A traceroute probe specification.
struct Probe {
  in6_addr dst_addr;       ///< IPv6 or IPv4-mapped IPv6 address (network order)
  uint16_t src_port;       ///< Source port (host order)
  uint16_t dst_port;       ///< Destination port (host order)
  uint8_t ttl;             ///< Time-to-live
  Protocols::L4 protocol;  ///< Protocol
  uint32_t wait_us;  ///< Microseconds to wait before the next probe (optional)

  [[nodiscard]] static Probe from_csv(const std::string &line);

  [[nodiscard]] std::string to_csv() const noexcept;

  [[nodiscard]] bool operator==(const Probe &other) const noexcept;

  [[nodiscard]] Protocols::L3 l3_protocol() const noexcept;

  [[nodiscard]] Protocols::L4 l4_protocol() const noexcept;

  [[nodiscard]] sockaddr_in sockaddr4() const noexcept;

  [[nodiscard]] sockaddr_in6 sockaddr6() const noexcept;

  /// Compute the caracal checksum used to verify the (eventual) reply
  /// integrity.
  [[nodiscard]] uint16_t checksum(uint32_t caracal_id) const noexcept;
};

std::ostream &operator<<(std::ostream &os, Probe const &v);

}  // namespace caracal
