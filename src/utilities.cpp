#include <arpa/inet.h>
#include <cxxabi.h>
#include <ifaddrs.h>
#include <tins/tins.h>

#include <caracal/constants.hpp>
#include <caracal/utilities.hpp>
#include <string>

namespace caracal::Utilities {

std::set<Tins::IPv4Address> all_ipv4_for(
    const Tins::NetworkInterface& interface) {
  std::set<Tins::IPv4Address> addresses;
  addresses.emplace(interface.ipv4_address());
#ifdef __linux__
  ifaddrs* ifaddr;
  if (getifaddrs(&ifaddr) == -1) {
    throw std::system_error(errno, std::generic_category());
  }
  for (auto ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET &&
        ifa->ifa_name == interface.name()) {
      auto sa = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
      addresses.emplace(sa->sin_addr.s_addr);
    }
  }
  freeifaddrs(ifaddr);
#endif
  return addresses;
}

std::set<Tins::IPv6Address> all_ipv6_for(
    const Tins::NetworkInterface& interface) {
  std::set<Tins::IPv6Address> addresses;
  for (const auto& addr : interface.ipv6_addresses()) {
    if (addr.address.is_local_unicast() || addr.address.is_loopback() ||
        addr.address.is_multicast()) {
      continue;
    }
    addresses.emplace(addr.address);
  }
  return addresses;
}

Tins::IPv4Address source_ipv4_for(const Tins::NetworkInterface& interface) {
  return interface.ipv4_address();
}

Tins::IPv6Address source_ipv6_for(const Tins::NetworkInterface& interface) {
  for (const auto& addr : interface.ipv6_addresses()) {
    if (addr.address.is_local_unicast() || addr.address.is_loopback() ||
        addr.address.is_multicast()) {
      continue;
    }
    return addr.address;
  }
  return Tins::IPv6Address{};
}

Tins::IPv4Address gateway_ip_for(const Tins::IPv4Address& destination) {
  Tins::IPv4Address gateway_ip{};
  Tins::Utils::gateway_from_ip(destination, gateway_ip);
  return gateway_ip;
}

Tins::HWAddress<6> gateway_mac_for(const Tins::NetworkInterface& interface,
                                   const Tins::IPv4Address& destination) {
  Tins::PacketSender sender{interface};
  const auto gateway_ip = gateway_ip_for(destination);
  return Tins::Utils::resolve_hwaddr(gateway_ip, sender);
}

std::string format_addr(const in6_addr& addr) noexcept {
  char buf[INET6_ADDRSTRLEN] = {};
  if (IN6_IS_ADDR_V4MAPPED(&addr)) {
    inet_ntop(AF_INET, &addr.s6_addr32[3], buf, INET_ADDRSTRLEN);
  } else {
    inet_ntop(AF_INET6, &addr, buf, INET6_ADDRSTRLEN);
  }
  return std::string{buf};
}

void parse_addr(const std::string& src, in6_addr& dst) {
  auto delim = src.find_first_of(".:");
  if (delim != std::string::npos) {
    if (src[delim] == ':') {
      // IPv6 (x:x:x:x:x:x:x:x) or IPv4-mapped IPv6 (::ffff:d.d.d.d)
      if (inet_pton(AF_INET6, src.c_str(), &dst) != 1) {
        throw std::runtime_error("Invalid IPv6 or IPv4-mapped address: " + src);
      }
    } else {
      // IPv4 dotted (d.d.d.d)
      dst.s6_addr32[0] = 0;
      dst.s6_addr32[1] = 0;
      dst.s6_addr32[2] = 0xFFFF0000U;
      if (inet_pton(AF_INET, src.c_str(), &dst.s6_addr32[3]) != 1) {
        throw std::runtime_error("Invalid IPv4 address: " + src);
      }
    }
  } else {
    // IPv4 uint32
    dst.s6_addr32[0] = 0;
    dst.s6_addr32[1] = 0;
    dst.s6_addr32[2] = 0xFFFF0000U;
    dst.s6_addr32[3] = htonl(std::stoul(src));
  }
}

std::string demangle(const std::string& mangled_name) {
  char* realname =
      abi::__cxa_demangle(mangled_name.c_str(), nullptr, nullptr, nullptr);
  auto s = std::string{realname};
  free(realname);
  return s;
}

}  // namespace caracal::Utilities
