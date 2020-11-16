#pragma once

#include <chrono>

using std::chrono::nanoseconds;
using std::chrono::steady_clock;

class RateLimiter {
 public:
  RateLimiter(unsigned int target_rate);
  void wait();
  double current_rate() const;

 private:
  const double m_target_rate;  // Calls per second.
  double m_current_rate;
  steady_clock::time_point m_curr_tp;
  steady_clock::time_point m_last_tp;
  nanoseconds m_delta;
};
