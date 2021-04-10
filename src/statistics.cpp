#include <algorithm>
#include <caracal/statistics.hpp>
#include <chrono>
#include <ostream>

using std::chrono::nanoseconds;

namespace caracal::Statistics {

RateLimiter::RateLimiter()
    : steps_{1}, target_delta_{}, effective_{}, inter_call_{} {}

RateLimiter::RateLimiter(uint64_t steps, nanoseconds target_delta) noexcept
    : steps_{steps}, target_delta_{target_delta}, effective_{}, inter_call_{} {}

void RateLimiter::log_effective_delta(nanoseconds delta) noexcept {
  effective_.push_back(delta.count());
}

void RateLimiter::log_inter_call_delta(nanoseconds delta) noexcept {
  inter_call_.push_back(delta.count());
}

double RateLimiter::average_utilization() const noexcept {
  return inter_call_.average() / target_delta_.count();
}

double RateLimiter::average_rate() const noexcept {
  const auto average = effective_.average();
  return average > 0 ? (steps_ * nanoseconds::period::den / average) : 0;
}

std::ostream& operator<<(std::ostream& os, Prober const& v) {
  os << "probes_read=" << v.read;
  os << " packets_sent=" << v.sent;
  os << " packets_failed=" << v.failed;
  os << " filtered_low_ttl=" << v.filtered_lo_ttl;
  os << " filtered_high_ttl=" << v.filtered_hi_ttl;
  os << " filtered_prefix_excl=" << v.filtered_prefix_excl;
  os << " filtered_prefix_not_incl=" << v.filtered_prefix_not_incl;
  return os;
}

std::ostream& operator<<(std::ostream& os, RateLimiter const& v) {
  os << "average_rate=" << v.average_rate();
  os << " average_utilization=" << v.average_utilization() * 100;
  return os;
}

std::ostream& operator<<(std::ostream& os, Sniffer const& v) {
  os << "packets_received=" << v.received_count;
  os << " packets_received_invalid=" << v.received_invalid_count;
  os << " icmp_distinct_incl_dest=" << v.icmp_messages_all.size();
  os << " icmp_distinct_excl_dest=" << v.icmp_messages_path.size();
  return os;
}

}  // namespace caracal::Statistics
