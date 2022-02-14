#include <fmt/format.h>
#include <spdlog/fmt/fmt.h>
#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>

#include <caracal/experimental.hpp>
#include <string>

#include "caracal/parser.hpp"
#include "caracal/utilities.hpp"

using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::steady_clock;

namespace caracal::Experimental {

Prober::Prober(const std::string &interface, const uint64_t probing_rate,
               const uint64_t buffer_size, const uint16_t caracal_id,
               const bool integrity_check)
    : sender_{interface, caracal_id},
      sniffer_{Sniffer{interface, buffer_size, caracal_id, integrity_check}},
      rate_limiter_{probing_rate, 1, "auto"} {
  sniffer_.start();
}

std::vector<Reply> Prober::probe(const std::vector<Probe> &probes,
                                 const uint64_t timeout_ms,
                                 std::function<void()> &check_exception) {
  sniffer_.replies.clear();
  for (auto probe : probes) {
    sender_.send(probe);
    rate_limiter_.wait();
    check_exception();
  }
  auto start_tp = steady_clock::now();
  auto timeout = milliseconds{timeout_ms};
  while (duration_cast<milliseconds>(steady_clock::now() - start_tp) <
         timeout) {
    if (sniffer_.replies.size() >= probes.size()) {
      break;
    }
    check_exception();
    std::this_thread::sleep_for(milliseconds{10});
  }
  return sniffer_.replies;
}

Sniffer::Sniffer(const std::string &interface_name, const uint64_t buffer_size,
                 const uint16_t caracal_id, bool integrity_check)
    : sniffer_{interface_name},
      caracal_id_{caracal_id},
      integrity_check_{integrity_check} {
  Tins::NetworkInterface interface{interface_name};

  std::vector<std::string> address_filters;
  for (auto address : Utilities::all_ipv4_for(interface)) {
    address_filters.push_back(fmt::format("dst {}", address.to_string()));
  }
  for (auto address : Utilities::all_ipv6_for(interface)) {
    address_filters.push_back(fmt::format("dst {}", address.to_string()));
  }

  auto filter_template =
      "({}) and (icmp or icmp6) and ("
      "icmp[icmptype] = icmp-echoreply or"
      " icmp[icmptype] = icmp-timxceed or"
      " icmp[icmptype] = icmp-unreach or"
      " icmp6[icmp6type] = icmp6-echoreply or"
      " icmp6[icmp6type] = icmp6-timeexceeded or"
      " icmp6[icmp6type] = icmp6-destinationunreach"
      ")";
  auto filter = fmt::format(fmt::runtime(filter_template),
                            fmt::join(address_filters, " or "));
  spdlog::info("sniffer_filter={}", filter);

  Tins::SnifferConfiguration config;
  config.set_buffer_size(buffer_size);
  config.set_filter(filter);
  config.set_immediate_mode(true);
  sniffer_ = Tins::Sniffer(interface_name, config);
}

Sniffer::~Sniffer() { stop(); }

void Sniffer::start() noexcept {
  auto handler = [this](Tins::Packet &packet) {
    auto reply = Parser::parse(packet);
    if (reply && (!integrity_check_ || reply->is_valid(caracal_id_))) {
      spdlog::trace(reply.value());
      replies.emplace_back(reply.value());
    } else {
      auto data = packet.pdu()->serialize();
      spdlog::trace("invalid_packet_hex={:02x}", fmt::join(data, ""));
    }
    return true;
  };
  thread_ = std::thread([this, handler]() { sniffer_.sniff_loop(handler); });
}

void Sniffer::stop() noexcept {
  if (thread_.joinable()) {
    sniffer_.stop_sniff();
    thread_.join();
  }
}
}  // namespace caracal::Experimental
