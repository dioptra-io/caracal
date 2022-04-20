#include <caracal/statistics.hpp>
#include <catch2/catch.hpp>

using caracal::Statistics::CircularArray;

TEST_CASE("CircularArray") {
  CircularArray<double, 4> a{};
  SECTION("Empty") {
    REQUIRE(a.accumulate() == 0);
    REQUIRE(a.average() == 0);
  }
  SECTION("Base") {
    a.push_back(1);
    a.push_back(1);
    REQUIRE(a.accumulate() == 2);
    REQUIRE(a.average() == 1);
  }
  SECTION("Overflow") {
    a.push_back(1);
    a.push_back(1);
    a.push_back(1);
    a.push_back(1);
    a.push_back(4);
    REQUIRE(a.accumulate() == 7);
    REQUIRE(a.average() == 1.75);
  }
}
