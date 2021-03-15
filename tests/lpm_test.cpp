#include <catch2/catch_test_macros.hpp>
#include <dminer/lpm.hpp>
#include <dminer/utilities.hpp>
#include <fstream>

using dminer::LPM;
using dminer::Utilities::parse_addr;

TEST_CASE("LPM") {
  std::ofstream ofs;
  ofs.open("zzz_input.csv");
  ofs << "192.168.150.0/24\n";
  ofs << "abcd:abcd::/32\n";
  ofs << "aaaa:bbbb:cccc::/48\n";
  ofs.close();

  LPM lpm;
  lpm.insert_file("zzz_input.csv");

  REQUIRE(lpm.lookup("192.168.150.0"));
  REQUIRE(lpm.lookup("192.168.150.42"));
  REQUIRE(lpm.lookup("192.168.150.255"));
  REQUIRE(!lpm.lookup("192.168.151.1"));
  REQUIRE(lpm.lookup("abcd:abcd::1"));
  REQUIRE(!lpm.lookup("abcd:1234::1"));
  REQUIRE(lpm.lookup("aaaa:bbbb:cccc::1"));
  REQUIRE(!lpm.lookup("aaaa:bbbb:dddd::1"));

  in6_addr addr{};
  parse_addr("aaaa:bbbb:cccc::2", addr);
  REQUIRE(lpm.lookup(addr));
  parse_addr("192.168.150.1", addr);
  REQUIRE(lpm.lookup(addr));
}