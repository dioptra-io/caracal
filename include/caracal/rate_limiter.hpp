#pragma once

#include <chrono>
#include <string>

#include "statistics.hpp"

using std::chrono::milliseconds;
using std::chrono::nanoseconds;
using std::chrono::steady_clock;

namespace caracal {

enum class RateLimitingMethod { Auto, Active, Sleep, None };

class RateLimiter {
 public:
  explicit RateLimiter(uint64_t target_rate, uint64_t steps = 1,
                       const std::string& method = "auto");

  void wait() noexcept;

  [[nodiscard]] const Statistics::RateLimiter& statistics() const noexcept;

  [[nodiscard]] static nanoseconds sleep_precision() noexcept;

  [[nodiscard]] static bool test(uint64_t target_rate) noexcept;

 private:
  RateLimitingMethod method_;
  nanoseconds sleep_precision_;
  nanoseconds target_delta_;
  steady_clock::time_point curr_tp_;
  steady_clock::time_point last_tp_;
  Statistics::RateLimiter statistics_;
};

}  // namespace caracal
