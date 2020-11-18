#pragma once

#include <arpa/inet.h>

#include <iostream>

struct Probe {
  // Network order (managed by inet_pton/ntop)
  in_addr dst_addr;
  // Host order
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t ttl;
  std::string human_dst_addr() const;
};

std::ostream& operator<<(std::ostream& os, Probe const& v);
