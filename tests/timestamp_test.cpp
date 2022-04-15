#include <caracal/timestamp.hpp>
#include <catch2/catch.hpp>
#include <chrono>
#include <thread>

#include "./environment.hpp"

namespace Timestamp = caracal::Timestamp;

using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::steady_clock;

TEST_CASE("Timestamp") {
  auto enc = Timestamp::encode(
      Timestamp::cast<Timestamp::tenth_ms>(steady_clock::now()));
  std::this_thread::sleep_for(milliseconds(250));
  auto diff = Timestamp::difference(
      Timestamp::cast<Timestamp::tenth_ms>(steady_clock::now()), enc);

  if (is_github && is_macos) {
    REQUIRE(diff / 10 >= 245);
  } else {
    // We allow some tolerance for systems where sleep_for is not precise
    // (e.g. macOS).
    REQUIRE(diff / 10 >= 245);
    REQUIRE(diff / 10 <= 255);
  }

  for (uint64_t i = 0; i < 65535; i++) {
    auto dec = Timestamp::decode(131069 + i, Timestamp::encode(131069));
    REQUIRE(dec == 131069);
  }

  // TODO: Test when the current clock is below the encoded clock.
  // TODO: Test RTT recovery (sorted time from measurement time).
}
