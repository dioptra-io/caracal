#pragma once

#include <arpa/inet.h>
#include <pfring.h>
#include <sys/time.h>
#include <tins/tins.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

#include "probe.hpp"
#include "rate_limiter.hpp"
#include "sender.hpp"

namespace fs = std::filesystem;

class pf_ring_sender_t : public Sender {
 public:
  pf_ring_sender_t(const int family, const std::string& protocol,
                   const Tins::NetworkInterface iface, const uint32_t pps);
  ~pf_ring_sender_t();
  void send(const Probe& probe, int n_packets) override;

 private:
  pfring* m_pf_ring;
  int m_family;
  uint8_t m_proto;
  std::string m_payload;
  uint8_t* m_buffer;
  RateLimiter m_rl;
};
