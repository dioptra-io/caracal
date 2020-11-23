#include "probe.hpp"

#include <catch2/catch.hpp>

TEST_CASE("probe_from_csv") {
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
}
