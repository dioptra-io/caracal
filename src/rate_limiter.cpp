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

RateLimiter::RateLimiter(const uint64_t target_rate,
                         const bool allow_sleep_wait)
    : allow_sleep_wait_{allow_sleep_wait},
      sleep_precision_{sleep_precision()},
      target_delta_{0},
      current_delta_{0},
      curr_tp_{steady_clock::now()},
      last_tp_{curr_tp_} {
  if (target_rate <= 0) {
    throw std::domain_error("target_rate must be > 0");
  }
  target_delta_ = nanoseconds{static_cast<uint64_t>(1e9 / target_rate)};
  statistics_ = Statistics::RateLimiter{target_delta_};
}

void RateLimiter::wait() noexcept {
  curr_tp_ = steady_clock::now();
  current_delta_ = duration_cast<nanoseconds>(curr_tp_ - last_tp_);
  statistics_.log_inter_call_delta(current_delta_);

  // (1) Early return if we do not need to wait.
  if (current_delta_ >= target_delta_) {
    last_tp_ = steady_clock::now();
    statistics_.log_effective_delta(current_delta_);
    return;
  }

  // (2) Wait if possible.
  if (allow_sleep_wait_ &&
      (sleep_precision_ < (target_delta_ - current_delta_))) {
    std::this_thread::sleep_for(target_delta_ - current_delta_);
  }

  // (3) Spin wait.
  do {
    curr_tp_ = steady_clock::now();
    current_delta_ = duration_cast<nanoseconds>(curr_tp_ - last_tp_);
  } while (current_delta_ < target_delta_);

  statistics_.log_effective_delta(current_delta_);
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

bool RateLimiter::test(uint64_t target_rate) noexcept {
  RateLimiter rl{target_rate};
  auto start = steady_clock::now();
  for (unsigned int i = 0; i < target_rate; i++) {
    rl.wait();
  }
  auto delta = duration_cast<milliseconds>(steady_clock::now() - start);
  return (delta > milliseconds{800}) && (delta < milliseconds{1200});
}

}  // namespace caracal
