#pragma once

#include <chrono>
#include <stdexcept>

using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::nanoseconds;
using std::chrono::steady_clock;

class RateLimiter {
 public:
  explicit RateLimiter(unsigned int target_rate)
      : m_target_rate(target_rate),
        m_current_rate(0),
        m_curr_tp(steady_clock::now()),
        m_last_tp(steady_clock::now()),
        m_delta(nanoseconds(0)) {
    if (m_target_rate <= 0) {
      throw std::domain_error("target_rate must be > 0");
    }
  }

  void wait() {
    do {
      m_curr_tp = steady_clock::now();
      m_delta = duration_cast<nanoseconds>(m_curr_tp - m_last_tp);
      m_current_rate = 1e9 / m_delta.count();
    } while (m_current_rate > m_target_rate);
    m_last_tp = m_curr_tp;
    m_delta = nanoseconds(0);
  }

  double current_rate() const { return m_current_rate; }

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
  const double m_target_rate;  // Calls per second.
  double m_current_rate;
  steady_clock::time_point m_curr_tp;
  steady_clock::time_point m_last_tp;
  nanoseconds m_delta;
};
