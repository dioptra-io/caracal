#include <arpa/inet.h>

#include <catch2/catch.hpp>
#include <dminer/checked.hpp>
#include <stdexcept>

using dminer::Checked::cast;

TEST_CASE("cast") {
  constexpr uint8_t u8 = 255;
  constexpr uint16_t u8_16 = 255;
  constexpr uint16_t u16 = 65535;

  // These expressions should be available at compile-time.
  // If not, this test will not compile.
  constexpr auto compile_time_check_1 = cast<uint8_t>(u8);
  constexpr auto compile_time_check_2 = cast<uint8_t>(u8_16);
  constexpr auto compile_time_check_3 = cast<uint16_t>(u16);

  static_assert(compile_time_check_1 == u8);
  static_assert(compile_time_check_2 == u8_16);
  static_assert(compile_time_check_3 == u16);

  REQUIRE(cast<uint8_t>(u8) == u8);
  REQUIRE(cast<uint8_t>(u8_16) == u8);
  REQUIRE(cast<uint16_t>(u8) == u8_16);
  REQUIRE(cast<uint16_t>(u8_16) == u8_16);
  REQUIRE(cast<uint16_t>(u16) == u16);

  REQUIRE_THROWS_AS(cast<uint8_t>(u16), std::invalid_argument);
}

TEST_CASE("hton") {
  uint16_t u16 = 65535;
  uint32_t u32 = 4294967295;
  REQUIRE(dminer::Checked::htons(u16) == htons(u16));
  REQUIRE(dminer::Checked::htonl(u16) == htonl(u16));
  REQUIRE(dminer::Checked::htonl(u32) == htonl(u32));
  REQUIRE_THROWS_AS(dminer::Checked::htons(u32), std::invalid_argument);
}
