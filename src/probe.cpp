#include "probe.hpp"

#include <arpa/inet.h>

#include <iostream>

std::string Probe::human_dst_addr() const {
  char buf[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &dst_addr, buf, INET_ADDRSTRLEN);
  return std::string{buf};
}

bool Probe::operator==(const Probe& other) const {
  return (dst_addr.s_addr == other.dst_addr.s_addr) &&
         (src_port == other.src_port) && (dst_port == other.dst_port) &&
         (ttl == other.ttl);
}

std::ostream& operator<<(std::ostream& os, Probe const& v) {
  os << v.src_port << ":" << v.human_dst_addr() << ":" << v.dst_port << "@"
     << uint(v.ttl);
  return os;
}
