#include <caracal/lpm.hpp>
#include <caracal/utilities.hpp>
#include <catch2/catch.hpp>
#include <fstream>

using caracal::LPM;
using caracal::Utilities::parse_addr;

TEST_CASE("LPM") {
  std::ofstream ofs;
  ofs.open("zzz_input.csv");
  ofs << "192.168.150.0/24\n";
  ofs << "# Some comment\n";
  ofs << "::ffff:192.168.160.0/24\n";
  ofs << "abcd:abcd::/32\n";
  ofs << "aaaa:bbbb:cccc::/48\n";
  ofs.close();

  LPM lpm;
  lpm.insert_file("zzz_input.csv");

  REQUIRE(lpm.lookup("192.168.150.0"));
  REQUIRE(lpm.lookup("192.168.150.42"));
  REQUIRE(lpm.lookup("192.168.150.255"));
  REQUIRE(!lpm.lookup("192.168.151.1"));
  REQUIRE(lpm.lookup("192.168.160.1"));
  REQUIRE(lpm.lookup("::ffff:192.168.160.1"));
  REQUIRE(!lpm.lookup("192.168.161.1"));
  REQUIRE(!lpm.lookup("::ffff:192.168.161.1"));
  REQUIRE(lpm.lookup("abcd:abcd::1"));
  REQUIRE(!lpm.lookup("abcd:1234::1"));
  REQUIRE(lpm.lookup("aaaa:bbbb:cccc::1"));
  REQUIRE(!lpm.lookup("aaaa:bbbb:dddd::1"));

  in6_addr addr{};
  parse_addr("aaaa:bbbb:cccc::2", addr);
  REQUIRE(lpm.lookup(addr));
  parse_addr("192.168.150.1", addr);
  REQUIRE(lpm.lookup(addr));

  REQUIRE_THROWS_AS(lpm.insert_file("zzz"), std::invalid_argument);
  REQUIRE_THROWS_AS(lpm.insert("zzz"), std::runtime_error);
  REQUIRE_THROWS_AS(lpm.lookup("zzz"), std::runtime_error);
}
