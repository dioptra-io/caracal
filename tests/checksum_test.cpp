#include <caracal/checksum.hpp>
#include <catch2/catch.hpp>

using caracal::Checksum::caracal_checksum;
using caracal::Checksum::ip_checksum;
using caracal::Checksum::ip_checksum_add;
using caracal::Checksum::ip_checksum_fold;

// TODO: Pseudo-header checksum;

TEST_CASE("Checksum::caracal_checksum") {
  uint32_t caracal_id = 2064386465;
  uint32_t dst_addr = 134743044;
  uint16_t src_port = 24000;
  uint8_t ttl = 7;
  auto checksum = caracal_checksum(caracal_id, dst_addr, src_port, ttl);
  REQUIRE(caracal_checksum(caracal_id, dst_addr, src_port, ttl) == checksum);
  REQUIRE(caracal_checksum(caracal_id, dst_addr - 1, src_port, ttl + 2) !=
          checksum);
  REQUIRE(caracal_checksum(caracal_id, dst_addr, src_port + 2, ttl) !=
          checksum);
}

TEST_CASE("Checksum::ip_checksum") {
  // Example from https://tools.ietf.org/html/rfc1071
  //              Byte-by-byte "Normal"  Swapped
  //                             Order    Order
  // Byte 0/1:    00   01        0001      0100
  // Byte 2/3:    f2   03        f203      03f2
  // Byte 4/5:    f4   f5        f4f5      f5f4
  // Byte 6/7:    f6   f7        f6f7      f7f6
  // Sum2:        dd   f2        ddf2      f2dd
  uint8_t data_1[8] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
  uint8_t data_2[8] = {0x01, 0x00, 0x03, 0xf2, 0xf5, 0xf4, 0xf7, 0xf6};
  REQUIRE(ip_checksum_fold(ip_checksum_add(0, &data_1, sizeof(data_1))) ==
          0xf2dd);
  REQUIRE(ip_checksum_fold(ip_checksum_add(0, &data_2, sizeof(data_2))) ==
          0xddf2);

  // Example from Wikipedia
  uint8_t data_3[18] = {0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40,
                        0x11, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7};
  REQUIRE(ip_checksum(&data_3, sizeof(data_3)) == 0x61b8);

  // Odd number of bytes
  uint8_t data_4[7] = {0x95, 0xea, 0xd0, 0xcc, 0x7d, 0x55, 0x04};
  REQUIRE(ip_checksum(&data_4, sizeof(data_4)) == 0xf317);

  BENCHMARK("Checksum::ip_checksum") {
    return ip_checksum(&data_3, sizeof(data_3));
  };
}
