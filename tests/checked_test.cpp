#include <arpa/inet.h>

#include <caracal/checked.hpp>
#include <catch2/catch.hpp>
#include <stdexcept>

using caracal::Checked::hton;
using caracal::Checked::numeric_cast;

TEST_CASE("Checked::numeric_cast") {
  constexpr uint8_t u8 = 255;
  constexpr uint16_t u8_16 = 255;
  constexpr uint16_t u16 = 65535;

  // These expressions should be available at compile-time.
  // If not, this test will not compile.
  constexpr auto compile_time_check_1 = numeric_cast<uint8_t>(u8);
  constexpr auto compile_time_check_2 = numeric_cast<uint8_t>(u8_16);
  constexpr auto compile_time_check_3 = numeric_cast<uint16_t>(u16);

  STATIC_REQUIRE(compile_time_check_1 == u8);
  STATIC_REQUIRE(compile_time_check_2 == u8_16);
  STATIC_REQUIRE(compile_time_check_3 == u16);

  REQUIRE(numeric_cast<uint8_t>(u8) == u8);
  REQUIRE(numeric_cast<uint8_t>(u8_16) == u8);
  REQUIRE(numeric_cast<uint16_t>(u8) == u8_16);
  REQUIRE(numeric_cast<uint16_t>(u8_16) == u8_16);
  REQUIRE(numeric_cast<uint16_t>(u16) == u16);

  REQUIRE_THROWS_AS(numeric_cast<uint8_t>(u16), std::invalid_argument);
}

TEST_CASE("Checked::hton") {
  uint16_t u16 = 65534;
  uint32_t u32 = 4294967294;
  REQUIRE(hton<uint16_t>(u16) == htons(u16));
  REQUIRE(hton<uint32_t>(u16) == htonl(u16));
  REQUIRE(hton<uint32_t>(u32) == htonl(u32));
  REQUIRE_THROWS_AS(hton<uint16_t>(u32), std::invalid_argument);
}
