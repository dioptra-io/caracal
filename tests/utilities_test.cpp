#include <arpa/inet.h>

#include <caracal/utilities.hpp>
#include <catch2/catch.hpp>

using caracal::Utilities::format_addr;
using caracal::Utilities::parse_addr;

inline in6_addr parse_addr(const std::string& src) {
  in6_addr dst;
  parse_addr(src, dst);
  return dst;
}

TEST_CASE("Utilities::parse_addr") {
  REQUIRE(format_addr(parse_addr("192.168.123.254")) == "192.168.123.254");
  REQUIRE(format_addr(parse_addr("134743044")) == "8.8.4.4");
  REQUIRE(format_addr(parse_addr("8.8.4.4")) == "8.8.4.4");
  REQUIRE(format_addr(parse_addr("::ffff:8.8.4.4")) == "8.8.4.4");
  REQUIRE(format_addr(parse_addr("2001:4860:4860::8888")) ==
          "2001:4860:4860::8888");

  // Invalid values
  REQUIRE_THROWS(parse_addr("8.8.4.4.0"));
  REQUIRE_THROWS(parse_addr("2001:4860:4860::8888::0000"));
}
