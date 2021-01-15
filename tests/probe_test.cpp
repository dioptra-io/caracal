#include <catch2/catch.hpp>
#include <dminer/probe.hpp>

using dminer::Probe;

TEST_CASE("Probe::from_csv") {
  SECTION("IPv4 dotted") {
    Probe probe = Probe::from_csv("0.0.0.0,1,2,3");
    REQUIRE(probe.human_dst_addr() == "0.0.0.0");
    REQUIRE(probe.dst_addr.s6_addr[3] == 0);
    REQUIRE(probe.src_port == 1);
    REQUIRE(probe.dst_port == 2);
    REQUIRE(probe.ttl == 3);
    REQUIRE(probe.v4() == true);
  }

  SECTION("IPv4 dotted and padded") {
    Probe probe = Probe::from_csv("008.008.004.004,0010,1000,050");
    REQUIRE(probe.human_dst_addr() == "8.8.4.4");
    REQUIRE(probe.src_port == 10);
    REQUIRE(probe.dst_port == 1000);
    REQUIRE(probe.ttl == 50);
    REQUIRE(probe.v4() == true);
    REQUIRE(Probe::from_csv(probe.to_csv()) == probe);
  }

  SECTION("IPv4 uint32") {
    // Python: int(ip_address("8.8.4.4"))
    Probe probe = Probe::from_csv("134743044,0010,1000,050");
    REQUIRE(probe.human_dst_addr() == "8.8.4.4");
    REQUIRE(probe.src_port == 10);
    REQUIRE(probe.dst_port == 1000);
    REQUIRE(probe.ttl == 50);
    REQUIRE(probe.v4() == true);
  }

  SECTION("IPv4-mapped IPv6") {
    Probe probe = Probe::from_csv("::ffff:8.8.4.4,10,1000,50");
    REQUIRE(probe.human_dst_addr() == "8.8.4.4");
    REQUIRE(probe.src_port == 10);
    REQUIRE(probe.dst_port == 1000);
    REQUIRE(probe.ttl == 50);
    REQUIRE(probe.v4() == true);
  }

  SECTION("IPv6") {
    Probe probe = Probe::from_csv("2001:4860:4860::8888,10,1000,50");
    REQUIRE(probe.human_dst_addr() == "2001:4860:4860::8888");
    REQUIRE(probe.v4() == false);
    REQUIRE(probe.src_port == 10);
    REQUIRE(probe.dst_port == 1000);
    REQUIRE(probe.ttl == 50);
  }
}
