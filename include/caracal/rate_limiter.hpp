#pragma once

#include <chrono>

#include "statistics.hpp"

using std::chrono::milliseconds;
using std::chrono::nanoseconds;
using std::chrono::steady_clock;

namespace caracal {

class RateLimiter {
 public:
  explicit RateLimiter(uint64_t target_rate);

  void wait() noexcept;

  [[nodiscard]] const Statistics::RateLimiter &statistics() const noexcept;

  [[nodiscard]] static nanoseconds sleep_precision() noexcept;

  [[nodiscard]] static bool test(uint64_t target_rate) noexcept;

 private:
  nanoseconds sleep_precision_;
  nanoseconds target_delta_;
  nanoseconds current_delta_;
  steady_clock::time_point curr_tp_;
  steady_clock::time_point last_tp_;
  Statistics::RateLimiter statistics_;
};

}  // namespace caracal
