#include <catch2/catch.hpp>
#include <dminer/pretty.hpp>
#include <sstream>

TEST_CASE("<< in_addr") {
  in_addr addr{};
  inet_pton(AF_INET, "8.8.4.4", &addr);
  std::stringstream ss;
  ss << addr;
  REQUIRE(ss.str() == "8.8.4.4");
}
