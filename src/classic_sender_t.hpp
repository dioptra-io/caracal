#pragma once

#include <netinet/in.h>
#include <tins/tins.h>

#include <string>

#include "probe.hpp"
#include "rate_limiter.hpp"
#include "sender.hpp"

class classic_sender_t : public Sender {
 public:
  classic_sender_t(const uint8_t family, const std::string& protocol,
                   const Tins::NetworkInterface interface, const int pps);
  ~classic_sender_t();
  double current_rate() const override;
  void send(const Probe& probe, const int n_packets) override;

 private:
  int m_socket;
  uint8_t m_family;
  uint8_t m_proto;
  uint8_t* m_buffer;
  sockaddr_in m_src_addr;
  std::string m_payload;

  RateLimiter m_rl;
};
