#include <caracal/integrity.hpp>
#include <catch2/catch_test_macros.hpp>

namespace Integrity = caracal::Integrity;

TEST_CASE("Integrity") {
  uint32_t caracal_id = 2064386465;
  uint32_t dst_addr = 134743044;
  uint16_t src_port = 24000;
  uint8_t ttl = 7;
  auto checksum = Integrity::checksum(caracal_id, dst_addr, src_port, ttl);
  REQUIRE(Integrity::checksum(caracal_id, dst_addr, src_port, ttl) == checksum);
  REQUIRE(Integrity::checksum(caracal_id, dst_addr - 1, src_port, ttl + 1) !=
          checksum);
  REQUIRE(Integrity::checksum(caracal_id, dst_addr, src_port + 2, ttl) !=
          checksum);
}
