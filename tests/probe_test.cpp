#include <caracal/probe.hpp>
#include <caracal/protocols.hpp>
#include <caracal/utilities.hpp>
#include <catch2/catch.hpp>
#include <sstream>

using caracal::Probe;
using caracal::Utilities::format_addr;

namespace Protocols = caracal::Protocols;

template <typename T>
std::string to_string(T x) {
  std::stringstream ss;
  ss << x;
  return ss.str();
}

TEST_CASE("Probe::from_csv") {
  SECTION("IPv4 dotted") {
    Probe probe = Probe::from_csv("0.0.0.0,1,2,3,udp");
    REQUIRE(
        to_string(probe) ==
        "dst_addr=0.0.0.0 src_port=1 dst_port=2 ttl=3 protocol=udp wait_us=0");
    REQUIRE(format_addr(probe.dst_addr) == "0.0.0.0");
    REQUIRE(Probe::from_csv(probe.to_csv()) == probe);
    REQUIRE(probe.dst_addr.s6_addr[3] == 0);
    REQUIRE(probe.src_port == 1);
    REQUIRE(probe.dst_port == 2);
    REQUIRE(probe.ttl == 3);
    REQUIRE(probe.l3_protocol() == Protocols::L3::IPv4);
    REQUIRE(probe.l4_protocol() == Protocols::L4::UDP);

    BENCHMARK("IPv4 dotted") { return Probe::from_csv("0.0.0.0,1,2,3,udp"); };
  }

  SECTION("IPv4 uint32") {
    // Python: int(ip_address("8.8.4.4"))
    Probe probe = Probe::from_csv("134743044,0010,1000,050,icmp");
    REQUIRE(to_string(probe) ==
            "dst_addr=8.8.4.4 src_port=10 dst_port=1000 ttl=50 protocol=icmp "
            "wait_us=0");
    REQUIRE(format_addr(probe.dst_addr) == "8.8.4.4");
    REQUIRE(Probe::from_csv(probe.to_csv()) == probe);
    REQUIRE(probe.src_port == 10);
    REQUIRE(probe.dst_port == 1000);
    REQUIRE(probe.ttl == 50);
    REQUIRE(probe.l3_protocol() == Protocols::L3::IPv4);
    REQUIRE(probe.l4_protocol() == Protocols::L4::ICMP);

    BENCHMARK("IPv4 uint32") {
      return Probe::from_csv("134743044,0010,1000,050,icmp");
    };
  }

  SECTION("IPv4-mapped IPv6") {
    Probe probe = Probe::from_csv("::ffff:8.8.4.4,10,1000,50,icmp");
    REQUIRE(to_string(probe) ==
            "dst_addr=8.8.4.4 src_port=10 dst_port=1000 ttl=50 protocol=icmp "
            "wait_us=0");
    REQUIRE(format_addr(probe.dst_addr) == "8.8.4.4");
    REQUIRE(Probe::from_csv(probe.to_csv()) == probe);
    REQUIRE(probe.src_port == 10);
    REQUIRE(probe.dst_port == 1000);
    REQUIRE(probe.ttl == 50);
    REQUIRE(probe.l3_protocol() == Protocols::L3::IPv4);
    REQUIRE(probe.l4_protocol() == Protocols::L4::ICMP);

    BENCHMARK("IPv4-mapped IPv6") {
      return Probe::from_csv("::ffff:8.8.4.4,10,1000,50,icmp");
    };
  }

  SECTION("IPv6") {
    Probe probe = Probe::from_csv("2001:4860:4860::8888,10,1000,50,icmp6");
    REQUIRE(to_string(probe) ==
            "dst_addr=2001:4860:4860::8888 src_port=10 dst_port=1000 ttl=50 "
            "protocol=icmp6 wait_us=0");
    REQUIRE(format_addr(probe.dst_addr) == "2001:4860:4860::8888");
    REQUIRE(Probe::from_csv(probe.to_csv()) == probe);
    REQUIRE(probe.src_port == 10);
    REQUIRE(probe.dst_port == 1000);
    REQUIRE(probe.ttl == 50);
    REQUIRE(probe.l3_protocol() == Protocols::L3::IPv6);
    REQUIRE(probe.l4_protocol() == Protocols::L4::ICMPv6);

    BENCHMARK("IPv6") {
      return Probe::from_csv("2001:4860:4860::8888,10,1000,50,icmp6");
    };
  }

  SECTION("Wait") {
    Probe probe = Probe::from_csv("0.0.0.0,1,2,3,udp,42");
    REQUIRE(
        to_string(probe) ==
        "dst_addr=0.0.0.0 src_port=1 dst_port=2 ttl=3 protocol=udp wait_us=42");
    REQUIRE(probe.wait_us == 42);
  }

  SECTION("Invalid") {
    // Missing fields
    REQUIRE_THROWS(Probe::from_csv("8.8.8.8,1,2,3"));
    // Extra fields
    REQUIRE_THROWS(Probe::from_csv("8.8.8.8,1,2,3,icmp,5,6"));
    // Invalid values
    REQUIRE_THROWS(Probe::from_csv("a,b,c,d"));
    // Out-of-range values
    REQUIRE_THROWS(Probe::from_csv("8.8.8.8,131072,131072,1,icmp"));
    REQUIRE_THROWS(Probe::from_csv("8.8.8.8,1,2,512,icmp"));
    REQUIRE_THROWS(Probe::from_csv("8.8.8.8,1,2,3,icmp,-1"));
  }
}
