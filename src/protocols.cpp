#include <netinet/in.h>

#include <caracal/protocols.hpp>

namespace caracal::Protocols {

uint8_t posix_value(L3 const &v) {
  switch (v) {
    case L3::IPv4:
      return IPPROTO_IP;
    case L3::IPv6:
      return IPPROTO_IPV6;
  }
}

uint8_t posix_value(L4 const &v) {
  switch (v) {
    case L4::ICMP:
      return IPPROTO_ICMP;
    case L4::ICMPv6:
      return IPPROTO_ICMPV6;
    case L4::UDP:
      return IPPROTO_UDP;
  }
}

L4 l4_from_string(std::string const &s) {
  if (s == "icmp") {
    return L4::ICMP;
  } else if (s == "icmp6") {
    return L4::ICMPv6;
  } else if (s == "udp") {
    return L4::UDP;
  } else {
    throw std::runtime_error("Invalid protocol: " + s);
  }
}

std::string to_string(L4 const &v) {
  switch (v) {
    case L4::ICMP:
      return "icmp";
    case L4::ICMPv6:
      return "icmp6";
    case L4::UDP:
      return "udp";
  }
}

}  // namespace caracal::Protocols
