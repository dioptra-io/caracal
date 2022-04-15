#include <caracal/rate_limiter.hpp>
#include <catch2/catch.hpp>
#include <chrono>

#include "./environment.hpp"

using caracal::RateLimiter;
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
  SECTION("750 packets at 500pps should take at-least 1.5s") {
    RateLimiter rl{500};
    auto delta = measure_time([&rl]() {
      for (auto i = 0; i < 750; i++) {
        rl.wait();
      }
    });
    if (is_github && is_macos) {
      REQUIRE(delta.count() >= milliseconds{1250}.count());
    } else {
      // NOTE: We use `.count()` to allow Catch2 to show
      // the values if the assertion fails.
      REQUIRE(delta.count() >= milliseconds{1250}.count());
      REQUIRE(delta.count() <= milliseconds{2000}.count());
    }
  }

  SECTION("750 packets at 500pps should take at-least 1.5s (steps = 10)") {
    RateLimiter rl{500, 10};
    auto delta = measure_time([&rl]() {
      for (auto i = 0; i < 75; i++) {
        rl.wait();
      }
    });
    if (is_github && is_macos) {
      REQUIRE(delta.count() >= milliseconds{1250}.count());
    } else {
      REQUIRE(delta.count() >= milliseconds{1250}.count());
      REQUIRE(delta.count() <= milliseconds{2000}.count());
    }
  }

  SECTION("50k packets at 100k pps should take at-least 0.5s") {
    RateLimiter rl{100000};
    auto delta = measure_time([&rl]() {
      for (auto i = 0; i < 50000; i++) {
        rl.wait();
      }
    });
    if (is_github && is_macos) {
      REQUIRE(delta.count() >= milliseconds{450}.count());
    } else {
      REQUIRE(delta.count() >= milliseconds{450}.count());
      REQUIRE(delta.count() <= milliseconds{1000}.count());
    }
  }

  SECTION("50k packets at 100k pps should take at-least 0.5s (steps = 100)") {
    RateLimiter rl{100000, 100};
    auto delta = measure_time([&rl]() {
      for (auto i = 0; i < 500; i++) {
        rl.wait();
      }
    });
    if (is_github && is_macos) {
      REQUIRE(delta.count() >= milliseconds{450}.count());
    } else {
      REQUIRE(delta.count() >= milliseconds{450}.count());
      REQUIRE(delta.count() <= milliseconds{1000}.count());
    }
  }

  SECTION("Invalid arguments") { REQUIRE_THROWS(RateLimiter{0}); }
}
