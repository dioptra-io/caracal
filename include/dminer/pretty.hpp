#pragma once
#include <arpa/inet.h>

inline std::ostream& operator<<(std::ostream& os, in_addr const& v) {
  char buf[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &v, buf, INET_ADDRSTRLEN);
  os << buf;
  return os;
}

inline std::ostream& operator<<(std::ostream& os, in6_addr const& v) {
  char buf[INET6_ADDRSTRLEN] = {};
  inet_ntop(AF_INET6, &v, buf, INET6_ADDRSTRLEN);
  os << buf;
  return os;
}

inline std::ostream& operator<<(std::ostream& os, sockaddr_in const& v) {
  os << v.sin_addr << ":" << ntohs(v.sin_port);
  return os;
}

inline std::ostream& operator<<(std::ostream& os, sockaddr_in6 const& v) {
  os << "[" << v.sin6_addr << "]:" << ntohs(v.sin6_port);
  return os;
}
