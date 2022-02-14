#pragma once

#include <tins/tins.h>

#include <string>
#include <thread>
#include <vector>

#include "rate_limiter.hpp"
#include "reply.hpp"
#include "sender.hpp"

namespace caracal::Experimental {

class Sniffer {
 public:
  Sniffer(const std::string& interface_name, uint64_t buffer_size,
          uint16_t caracal_id, bool integrity_check);
  ~Sniffer();
  void start() noexcept;
  void stop() noexcept;
  // TODO: Make private + get/flush.
  std::vector<Reply> replies;

 private:
  Tins::Sniffer sniffer_;
  std::thread thread_;
  uint16_t caracal_id_;
  bool integrity_check_;
};

class Prober {
 public:
  Prober(const std::string& interface, uint64_t probing_rate,
         uint64_t buffer_size, uint16_t caracal_id, bool integrity_check);
  std::vector<Reply> probe(const std::vector<Probe>& probes,
                           uint64_t timeout_ms,
                           std::function<void()>& check_exception);

 private:
  Sender sender_;
  Sniffer sniffer_;
  RateLimiter rate_limiter_;
};

}  // namespace caracal::Experimental
