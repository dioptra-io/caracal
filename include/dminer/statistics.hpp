#pragma once

#include <algorithm>
#include <chrono>
#include <numeric>
#include <ostream>
#include <unordered_set>

using std::chrono::nanoseconds;

namespace dminer::Statistics {

template <typename T, size_t N>
class CircularArray {
 public:
  using array_type = std::array<T, N>;
  using size_type = typename array_type::size_type;
  using const_iterator = typename array_type::const_iterator;

  void push_back(T val) {
    values_[cursor_ % N] = val;
    cursor_++;
  }

  [[nodiscard]] T accumulate() const {
    return std::accumulate(begin(), end(), T());
  }

  [[nodiscard]] T average() const {
    return size() > 0 ? (accumulate() / size()) : 0;
  }

  [[nodiscard]] size_type size() const { return std::min(N, cursor_); }

  [[nodiscard]] const_iterator begin() const { return values_.begin(); }

  [[nodiscard]] const_iterator end() const {
    return std::next(begin(), size());
  }

 private:
  array_type values_;
  size_type cursor_;
};

struct Prober {
  uint64_t read = 0;
  uint64_t sent = 0;
  uint64_t failed = 0;
  uint64_t filtered_lo_ttl = 0;
  uint64_t filtered_hi_ttl = 0;
  uint64_t filtered_prefix_excl = 0;
  uint64_t filtered_prefix_not_incl = 0;
};

inline std::ostream& operator<<(std::ostream& os, Prober const& v) {
  os << "probes_read=" << v.read;
  os << " packets_sent=" << v.sent;
  os << " packets_failed=" << v.failed;
  os << " filtered_low_ttl=" << v.filtered_lo_ttl;
  os << " filtered_high_ttl=" << v.filtered_hi_ttl;
  os << " filtered_prefix_excl=" << v.filtered_prefix_excl;
  os << " filtered_prefix_not_incl=" << v.filtered_prefix_not_incl;
  return os;
}

struct RateLimiter {
  RateLimiter() : target_delta_{}, effective_{}, inter_call_{} {};

  explicit RateLimiter(nanoseconds target_delta)
      : target_delta_{target_delta}, effective_{}, inter_call_{} {};

  void log_effective_delta(nanoseconds delta) {
    effective_.push_back(delta.count());
  }

  void log_inter_call_delta(nanoseconds delta) {
    inter_call_.push_back(delta.count());
  }

  [[nodiscard]] double average_utilization() const {
    return inter_call_.average() / target_delta_.count();
  }

  [[nodiscard]] double average_rate() const {
    const auto average = effective_.average();
    return average > 0 ? (nanoseconds::period::den / average) : 0;
  }

 private:
  nanoseconds target_delta_;
  CircularArray<double, 64> effective_;
  CircularArray<double, 64> inter_call_;
};

inline std::ostream& operator<<(std::ostream& os, RateLimiter const& v) {
  os << "average_rate=" << v.average_rate();
  os << " average_utilization=" << v.average_utilization() * 100;
  return os;
}

struct Sniffer {
  uint64_t received_count = 0;
  uint64_t received_invalid_count = 0;
  std::unordered_set<uint32_t> icmp_messages_all;
  std::unordered_set<uint32_t> icmp_messages_path;
};

inline std::ostream& operator<<(std::ostream& os, Sniffer const& v) {
  os << "packets_received=" << v.received_count;
  os << " packets_received_invalid=" << v.received_invalid_count;
  os << " icmp_distinct_incl_dest=" << v.icmp_messages_all.size();
  os << " icmp_distinct_excl_dest=" << v.icmp_messages_path.size();
  return os;
}

}  // namespace dminer::Statistics
