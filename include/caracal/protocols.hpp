#pragma once

#include <ostream>
#include <string>

/// Protocols constants.
namespace caracal::Protocols {

enum class L2 { None, BSDLoopback, Ethernet };
enum class L3 { IPv4, IPv6 };
enum class L4 { ICMP, ICMPv6, UDP };

/// Layer 3 protocol constant (e.g. IPPROTO_IP).
uint8_t posix_value(L3 const &v);

/// Layer 4 protocol constant (e.g. IPPROTO_ICMP).
uint8_t posix_value(L4 const &v);

L4 l4_from_string(std::string const &s);
std::string to_string(L4 const &v);

}  // namespace caracal::Protocols
