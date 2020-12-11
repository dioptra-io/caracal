#include "rate_limiter.hpp"

#include <catch2/catch.hpp>
#include <chrono>
#include <iostream>

using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::steady_clock;

template <typename F>
milliseconds measure_time(F lambda) {
  auto start = steady_clock::now();
  lambda();
  auto stop = steady_clock::now();
  return duration_cast<milliseconds>(stop - start);
}

TEST_CASE("RateLimiter") {
  RateLimiter rl{500};

  SECTION("250 packets at 500pps should take at-least 0.5s") {
    auto delta = measure_time([&rl]() {
      for (auto i = 0; i < 250; i++) {
        rl.wait();
      }
    });
    // NOTE: We use `.count()` to allow Catch2 to show
    // the values if the assertion fails.
    REQUIRE(delta.count() >= milliseconds{450}.count());
    REQUIRE(delta.count() <= milliseconds{1000}.count());
  }

  SECTION("750 packets at 500pps should take at-least 1.5s") {
    auto delta = measure_time([&rl]() {
      for (auto i = 0; i < 750; i++) {
        rl.wait();
      }
    });
    REQUIRE(delta.count() >= milliseconds{1250}.count());
    REQUIRE(delta.count() <= milliseconds{2000}.count());
  }
}
