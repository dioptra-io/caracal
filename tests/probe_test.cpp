#include <catch2/catch.hpp>
#include <dminer/probe.hpp>

TEST_CASE("Probe::from_csv") {
  Probe probe1 = Probe::from_csv("0.0.0.0,1,2,3");
  REQUIRE(probe1.human_dst_addr() == "0.0.0.0");
  REQUIRE(probe1.dst_addr.s_addr == 0);
  REQUIRE(probe1.src_port == 1);
  REQUIRE(probe1.dst_port == 2);
  REQUIRE(probe1.ttl == 3);

  Probe probe2 = Probe::from_csv("008.008.004.004,0010,1000,050");
  REQUIRE(probe2.human_dst_addr() == "8.8.4.4");
  REQUIRE(probe2.src_port == 10);
  REQUIRE(probe2.dst_port == 1000);
  REQUIRE(probe2.ttl == 50);
  REQUIRE(Probe::from_csv(probe2.to_csv()) == probe2);

  // Python: int(ip_address("8.8.4.4"))
  Probe probe3 = Probe::from_csv("134743044,0010,1000,050");
  REQUIRE(probe3.human_dst_addr() == "8.8.4.4");
  REQUIRE(probe3.src_port == 10);
  REQUIRE(probe3.dst_port == 1000);
  REQUIRE(probe3.ttl == 50);
}
