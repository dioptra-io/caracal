#include "rate_limiter.hpp"

#include <chrono>
#include <stdexcept>

using std::chrono::duration_cast;
using std::chrono::nanoseconds;
using std::chrono::steady_clock;

RateLimiter::RateLimiter(unsigned int target_rate)
    : m_target_rate(target_rate),
      m_current_rate(0),
      m_curr_tp(steady_clock::now()),
      m_last_tp(steady_clock::now()),
      m_delta(nanoseconds(0)) {
  if (m_target_rate <= 0) {
    throw std::domain_error("target_rate must be > 0");
  }
}

void RateLimiter::wait() {
  do {
    m_curr_tp = steady_clock::now();
    m_delta = duration_cast<nanoseconds>(m_curr_tp - m_last_tp);
    m_current_rate = 1e9 / m_delta.count();
  } while (m_current_rate > m_target_rate);
  m_last_tp = m_curr_tp;
  m_delta = nanoseconds(0);
}

double RateLimiter::current_rate() const { return m_current_rate; }
