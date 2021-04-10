#pragma once

#include <netinet/in.h>

#include <algorithm>
#include <array>
#include <caracal/constants.hpp>
#include <chrono>
#include <numeric>
#include <ostream>
#include <unordered_set>

using std::chrono::nanoseconds;

namespace caracal::Statistics {

// Operators for using in6_addr in an unordered_map
template <class T>
inline void hash_combine(std::size_t& seed, const T& v) {
  std::hash<T> hasher;
  seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

class in6_addr_equal_to {
 public:
  bool operator()(const in6_addr& lhs, const in6_addr& rhs) const {
    return IN6_ARE_ADDR_EQUAL(&lhs, &rhs);
  }
};

class in6_addr_hash {
 public:
  size_t operator()(const in6_addr& addr) const noexcept {
    size_t seed = 0;
    hash_combine(seed, addr.s6_addr32[0]);
    hash_combine(seed, addr.s6_addr32[1]);
    hash_combine(seed, addr.s6_addr32[2]);
    hash_combine(seed, addr.s6_addr32[3]);
    return seed;
  }
};

template <typename T, size_t N>
class CircularArray {
 public:
  using array_type = std::array<T, N>;
  using size_type = typename array_type::size_type;
  using const_iterator = typename array_type::const_iterator;

  void push_back(T val) noexcept {
    values_[cursor_ % N] = val;
    cursor_++;
  }

  [[nodiscard]] T accumulate() const noexcept {
    return std::accumulate(begin(), end(), T());
  }

  [[nodiscard]] T average() const noexcept {
    return size() > 0 ? (accumulate() / size()) : 0;
  }

  [[nodiscard]] size_type size() const noexcept { return std::min(N, cursor_); }

  [[nodiscard]] const_iterator begin() const noexcept {
    return values_.begin();
  }

  [[nodiscard]] const_iterator end() const noexcept {
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

struct RateLimiter {
  RateLimiter();

  explicit RateLimiter(uint64_t steps, nanoseconds target_delta) noexcept;

  void log_effective_delta(nanoseconds delta) noexcept;

  void log_inter_call_delta(nanoseconds delta) noexcept;

  [[nodiscard]] double average_utilization() const noexcept;

  [[nodiscard]] double average_rate() const noexcept;

 private:
  uint64_t steps_;
  nanoseconds target_delta_;
  CircularArray<double, 64> effective_;
  CircularArray<double, 64> inter_call_;
};

struct Sniffer {
  uint64_t received_count = 0;
  uint64_t received_invalid_count = 0;
  std::unordered_set<in6_addr, in6_addr_hash, in6_addr_equal_to>
      icmp_messages_all;
  std::unordered_set<in6_addr, in6_addr_hash, in6_addr_equal_to>
      icmp_messages_path;
};

std::ostream& operator<<(std::ostream& os, Prober const& v);
std::ostream& operator<<(std::ostream& os, RateLimiter const& v);
std::ostream& operator<<(std::ostream& os, Sniffer const& v);

}  // namespace caracal::Statistics
