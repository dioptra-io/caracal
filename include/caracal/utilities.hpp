#pragma once

#include <arpa/inet.h>
#include <tins/tins.h>

#include <set>
#include <string>

namespace caracal::Utilities {

[[nodiscard]] std::set<Tins::IPv4Address> all_ipv4_for(
    const Tins::NetworkInterface& interface);

[[nodiscard]] std::set<Tins::IPv6Address> all_ipv6_for(
    const Tins::NetworkInterface& interface);

[[nodiscard]] Tins::IPv4Address source_ipv4_for(
    const Tins::NetworkInterface& interface);

[[nodiscard]] Tins::IPv6Address source_ipv6_for(
    const Tins::NetworkInterface& interface);

[[nodiscard]] Tins::IPv4Address gateway_ip_for(
    const Tins::IPv4Address& destination);

[[nodiscard]] Tins::HWAddress<6> gateway_mac_for(
    const Tins::NetworkInterface& interface,
    const Tins::IPv4Address& destination);

[[nodiscard]] std::string format_addr(const in6_addr& addr) noexcept;

void parse_addr(const std::string& src, in6_addr& dst);

/// Demangle C++ identifiers.
std::string demangle(const std::string& mangled_name);

}  // namespace caracal::Utilities
