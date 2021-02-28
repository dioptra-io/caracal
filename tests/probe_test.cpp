#include <catch2/catch_test_macros.hpp>
#include <dminer/probe.hpp>
#include <dminer/utilities.hpp>
#include <sstream>

using dminer::Probe;
using dminer::Utilities::format_addr;

template <typename T>
std::string to_string(T x) {
  std::stringstream ss;
  ss << x;
  return ss.str();
}

TEST_CASE("Probe::from_csv") {
  SECTION("IPv4 dotted") {
    Probe probe = Probe::from_csv("0.0.0.0,1,2,3");
    REQUIRE(to_string(probe) == "1:0.0.0.0:2@3");
    REQUIRE(format_addr(probe.dst_addr) == "0.0.0.0");
    REQUIRE(probe.dst_addr.s6_addr[3] == 0);
    REQUIRE(probe.src_port == 1);
    REQUIRE(probe.dst_port == 2);
    REQUIRE(probe.ttl == 3);
    REQUIRE(probe.v4() == true);
  }

  SECTION("IPv4 uint32") {
    // Python: int(ip_address("8.8.4.4"))
    Probe probe = Probe::from_csv("134743044,0010,1000,050");
    REQUIRE(to_string(probe) == "10:8.8.4.4:1000@50");
    REQUIRE(format_addr(probe.dst_addr) == "8.8.4.4");
    REQUIRE(probe.src_port == 10);
    REQUIRE(probe.dst_port == 1000);
    REQUIRE(probe.ttl == 50);
    REQUIRE(probe.v4() == true);
  }

  SECTION("IPv4-mapped IPv6") {
    Probe probe = Probe::from_csv("::ffff:8.8.4.4,10,1000,50");
    REQUIRE(to_string(probe) == "10:8.8.4.4:1000@50");
    REQUIRE(format_addr(probe.dst_addr) == "8.8.4.4");
    REQUIRE(probe.src_port == 10);
    REQUIRE(probe.dst_port == 1000);
    REQUIRE(probe.ttl == 50);
    REQUIRE(probe.v4() == true);
  }

  SECTION("IPv6") {
    Probe probe = Probe::from_csv("2001:4860:4860::8888,10,1000,50");
    REQUIRE(to_string(probe) == "10:[2001:4860:4860::8888]:1000@50");
    REQUIRE(format_addr(probe.dst_addr) == "2001:4860:4860::8888");
    REQUIRE(probe.v4() == false);
    REQUIRE(probe.src_port == 10);
    REQUIRE(probe.dst_port == 1000);
    REQUIRE(probe.ttl == 50);
  }

  SECTION("Invalid") {
    // Missing fields
    REQUIRE_THROWS(Probe::from_csv("8.8.8.8,1,2"));
    // Invalid values
    REQUIRE_THROWS(Probe::from_csv("a,b,c,d"));
    // Out-of-range values
    REQUIRE_THROWS(Probe::from_csv("8.8.8.8,131072,131072,1"));
    REQUIRE_THROWS(Probe::from_csv("8.8.8.8,1,2,512"));
  }
}
