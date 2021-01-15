#pragma once

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <thread>

#include "statistics.hpp"

using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::nanoseconds;
using std::chrono::steady_clock;

namespace dminer {

class RateLimiter {
 public:
  explicit RateLimiter(uint64_t target_rate)
      : sleep_precision_{sleep_precision()},
        target_delta_{0},
        current_delta_{0},
        curr_tp_{steady_clock::now()},
        last_tp_{curr_tp_} {
    if (target_rate <= 0) {
      throw std::domain_error("target_rate must be > 0");
    }
    target_delta_ = nanoseconds{(uint64_t)(1e9 / target_rate)};
    statistics_ = Statistics::RateLimiter{target_delta_};
  }

  void wait() {
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
    if (sleep_precision_ < (target_delta_ - current_delta_)) {
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

  const Statistics::RateLimiter &statistics() const { return statistics_; }

  static nanoseconds sleep_precision() {
    nanoseconds worst_case{0};
    for (auto i = 0; i < 5; i++) {
      auto start = steady_clock::now();
      std::this_thread::sleep_for(nanoseconds{1});
      auto delta = steady_clock::now() - start;
      worst_case = std::max(worst_case, delta);
    }
    return worst_case;
  }

  static bool test(uint64_t target_rate) {
    RateLimiter rl{target_rate};
    auto start = steady_clock::now();
    for (unsigned int i = 0; i < target_rate; i++) {
      rl.wait();
    }
    auto delta = duration_cast<milliseconds>(steady_clock::now() - start);
    return (delta > milliseconds{800}) && (delta < milliseconds{1200});
  }

 private:
  nanoseconds sleep_precision_;
  nanoseconds target_delta_;
  nanoseconds current_delta_;
  steady_clock::time_point curr_tp_;
  steady_clock::time_point last_tp_;
  Statistics::RateLimiter statistics_;
};

}  // namespace dminer
