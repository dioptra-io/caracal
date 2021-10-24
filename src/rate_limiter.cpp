#include <algorithm>
#include <caracal/rate_limiter.hpp>
#include <caracal/statistics.hpp>
#include <chrono>
#include <stdexcept>
#include <thread>

using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::nanoseconds;
using std::chrono::steady_clock;

namespace caracal {

RateLimiter::RateLimiter(const uint64_t target_rate, const uint64_t steps,
                         const std::string& method)
    : sleep_precision_{sleep_precision()},
      target_delta_{0},
      curr_tp_{steady_clock::now()},
      last_tp_{curr_tp_} {
  if (target_rate <= 0) {
    throw std::domain_error("target_rate must be > 0");
  }
  if (method == "auto") {
    method_ = RateLimitingMethod::Auto;
  } else if (method == "active") {
    method_ = RateLimitingMethod::Active;
  } else if (method == "sleep") {
    method_ = RateLimitingMethod::Sleep;
  } else if (method == "none") {
    method_ = RateLimitingMethod::None;
  } else {
    throw std::invalid_argument("method must be auto|active|sleep|none");
  }
  target_delta_ = nanoseconds{steps * 1'000'000'000 / target_rate};
  statistics_ = Statistics::RateLimiter{steps, target_delta_};
}

void RateLimiter::wait() noexcept {
  curr_tp_ = steady_clock::now();
  nanoseconds current_delta = duration_cast<nanoseconds>(curr_tp_ - last_tp_);
  statistics_.log_inter_call_delta(current_delta);

  // (1) Early return if we do not need to wait.
  if (current_delta >= target_delta_) {
    last_tp_ = steady_clock::now();
    statistics_.log_effective_delta(current_delta);
    return;
  }

  // (2) Wait if possible.
  if ((method_ == RateLimitingMethod::Auto ||
       method_ == RateLimitingMethod::Sleep) &&
      sleep_precision_ < (target_delta_ - current_delta)) {
    std::this_thread::sleep_for(target_delta_ - current_delta);
  }

  // (3) Spin wait.
  do {
    curr_tp_ = steady_clock::now();
    current_delta = duration_cast<nanoseconds>(curr_tp_ - last_tp_);
  } while ((method_ == RateLimitingMethod::Auto ||
            method_ == RateLimitingMethod::Active) &&
           current_delta < target_delta_);

  statistics_.log_effective_delta(current_delta);
  last_tp_ = steady_clock::now();
}

const Statistics::RateLimiter& RateLimiter::statistics() const noexcept {
  return statistics_;
}

nanoseconds RateLimiter::sleep_precision() noexcept {
  nanoseconds worst_case{0};
  for (auto i = 0; i < 5; i++) {
    auto start = steady_clock::now();
    std::this_thread::sleep_for(nanoseconds{1});
    auto delta = steady_clock::now() - start;
    worst_case = std::max(worst_case, delta);
  }
  return worst_case;
}

}  // namespace caracal
