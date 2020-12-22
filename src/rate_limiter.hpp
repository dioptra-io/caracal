#pragma once

#include <chrono>
#include <stdexcept>
#include <thread>

using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::nanoseconds;
using std::chrono::steady_clock;

class RateLimiter {
 public:
  explicit RateLimiter(unsigned int target_rate)
      : m_sleep_precision{sleep_precision()},
        m_current_delta{0},
        m_curr_tp{steady_clock::now()},
        m_last_tp{m_curr_tp} {
    if (target_rate <= 0) {
      throw std::domain_error("target_rate must be > 0");
    }
    m_target_delta = nanoseconds{(uint64_t)(1e9 / target_rate)};
  }

  void wait() {
    // x2 to allow 50% time outside wait.
    if ((m_sleep_precision * 2) < m_target_delta) {
      wait_sleep();
    } else {
      wait_spin();
    }
  }

  void wait_sleep() {
    m_curr_tp = steady_clock::now();
    m_current_delta = duration_cast<nanoseconds>(m_curr_tp - m_last_tp);
    if (m_current_delta < m_target_delta) {
      std::this_thread::sleep_for(m_target_delta - m_current_delta);
    }
    m_last_tp = steady_clock::now();
  }

  void wait_spin() {
    do {
      m_curr_tp = steady_clock::now();
      m_current_delta = duration_cast<nanoseconds>(m_curr_tp - m_last_tp);
    } while (m_current_delta < m_target_delta);
    m_last_tp = m_curr_tp;
  }

  double current_rate() const { return 1e9 / m_current_delta.count(); }

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

  static bool test(unsigned int target_rate) {
    RateLimiter rl{target_rate};
    auto start = steady_clock::now();
    for (unsigned int i = 0; i < target_rate; i++) {
      rl.wait();
    }
    auto delta = duration_cast<milliseconds>(steady_clock::now() - start);
    return (delta > milliseconds{800}) && (delta < milliseconds{1200});
  }

 private:
  nanoseconds m_sleep_precision;
  nanoseconds m_target_delta;
  nanoseconds m_current_delta;
  steady_clock::time_point m_curr_tp;
  steady_clock::time_point m_last_tp;
};
