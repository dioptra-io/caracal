#include <catch2/catch.hpp>
#include <chrono>
#include <dminer/timestamp.hpp>
#include <iostream>
#include <thread>

using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::steady_clock;

TEST_CASE("timestamp") {
  auto enc = encode_timestamp(to_timestamp<tenth_ms>(steady_clock::now()));
  std::this_thread::sleep_for(milliseconds(250));
  auto diff =
      decode_difference(to_timestamp<tenth_ms>(steady_clock::now()), enc);
  // We allow some tolerance for systems where sleep_for is not precise (e.g.
  // macOS).
  REQUIRE(diff / 10 >= 245);
  REQUIRE(diff / 10 <= 255);

  for (uint64_t i = 0; i < 65535; i++) {
    auto dec = decode_timestamp(131069 + i, encode_timestamp(131069));
    REQUIRE(dec == 131069);
  }

  // TODO: Test when the current clock is below the encoded clock.
  // TODO: Test RTT recovery (sorted time from measurement time).
}
