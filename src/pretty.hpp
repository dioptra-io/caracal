#pragma once
#include <arpa/inet.h>

std::ostream& operator<<(std::ostream& os, in_addr const& v) {
  char buf[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &v, buf, INET_ADDRSTRLEN);
  os << buf;
  return os;
}

std::ostream& operator<<(std::ostream& os, sockaddr_in const& v) {
  os << v.sin_addr << ":" << ntohs(v.sin_port);
  return os;
}
