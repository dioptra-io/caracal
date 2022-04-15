#include <netinet/in.h>

#include <caracal/protocols.hpp>
#include <catch2/catch.hpp>

using caracal::Protocols::L3;
using caracal::Protocols::L4;
using caracal::Protocols::l4_from_string;
using caracal::Protocols::posix_value;
using caracal::Protocols::to_string;

TEST_CASE("Protocols::l4_from_string") {
  REQUIRE(l4_from_string(to_string(L4::ICMP)) == L4::ICMP);
  REQUIRE(l4_from_string(to_string(L4::ICMPv6)) == L4::ICMPv6);
  REQUIRE(l4_from_string(to_string(L4::UDP)) == L4::UDP);
  REQUIRE_THROWS_AS(l4_from_string("invalid"), std::runtime_error);
}

TEST_CASE("Protocols::posix_value") {
  REQUIRE(posix_value(L3::IPv4) == IPPROTO_IP);
  REQUIRE(posix_value(L3::IPv6) == IPPROTO_IPV6);
  REQUIRE(posix_value(L4::ICMP) == IPPROTO_ICMP);
  REQUIRE(posix_value(L4::ICMPv6) == IPPROTO_ICMPV6);
  REQUIRE(posix_value(L4::UDP) == IPPROTO_UDP);
}
