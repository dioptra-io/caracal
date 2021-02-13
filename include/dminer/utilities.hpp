#pragma once

#include <arpa/inet.h>
#include <tins/tins.h>

#include <limits>
#include <string>

namespace dminer::Utilities {

template <typename Type, typename Value>
[[nodiscard]] inline constexpr Type cast(const Value value) {
  // Compile-time fast-path if Value is included into Type.
  if ((std::numeric_limits<Value>::min() >= std::numeric_limits<Type>::min()) &&
      (std::numeric_limits<Value>::max() <= std::numeric_limits<Type>::max())) {
    return static_cast<Type>(value);
  }
  // Runtime check otherwise.
  if ((value >= std::numeric_limits<Type>::min()) &&
      (value <= std::numeric_limits<Type>::max())) {
    return static_cast<Type>(value);
  }
  throw std::invalid_argument{
      "Value (" + std::to_string(value) + ") must be between " +
      std::to_string(std::numeric_limits<Type>::min()) + " and " +
      std::to_string(std::numeric_limits<Type>::max())};
}

// We can't name those functions htons or htonl since these are macros on macOS.
template <typename To, typename From>
[[nodiscard]] inline constexpr To hton(const From value) {
  if constexpr (std::is_same<To, uint16_t>::value) {
    return htons(cast<uint16_t>(value));
  } else if constexpr (std::is_same<To, uint32_t>::value) {
    return htonl(cast<uint32_t>(value));
  }
}

[[nodiscard]] inline uint16_t stou16(const std::string& str) {
  return cast<uint16_t>(std::stoul(str));
}

[[nodiscard]] inline uint8_t stou8(const std::string& str) {
  return cast<uint8_t>(std::stoul(str));
}

[[nodiscard]] inline Tins::IPv4Address source_ipv4_for(
    const Tins::NetworkInterface& interface) {
  return interface.ipv4_address();
}

[[nodiscard]] inline Tins::IPv6Address source_ipv6_for(
    const Tins::NetworkInterface& interface) {
  for (const auto& addr : interface.ipv6_addresses()) {
    if (addr.address.is_local_unicast() || addr.address.is_loopback() ||
        addr.address.is_multicast()) {
      continue;
    }
    return addr.address;
  }
  return Tins::IPv6Address{};
}

[[nodiscard]] inline Tins::IPv4Address gateway_ip_for(
    const Tins::IPv4Address& destination) {
  Tins::IPv4Address gateway_ip{};
  Tins::Utils::gateway_from_ip(destination, gateway_ip);
  return gateway_ip;
}

[[nodiscard]] inline Tins::HWAddress<6> gateway_mac_for(
    const Tins::NetworkInterface& interface,
    const Tins::IPv4Address& destination) {
  Tins::PacketSender sender{interface};
  const auto gateway_ip = gateway_ip_for(destination);
  return Tins::Utils::resolve_hwaddr(gateway_ip, sender);
}

}  // namespace dminer::Utilities
