#include <checksum.h>

#include <caracal/integrity.hpp>

namespace caracal::Integrity {

uint16_t checksum(uint32_t caracal_id, uint32_t dst_addr, uint16_t src_port,
                  uint8_t ttl) {
  // For a comparison of the IP checksum with CRCs, see:
  // "Performance of Checksums and CRCs over Real Data"
  // ftp://ftp.cis.upenn.edu/pub/mbgreen/papers/ton98.pdf
  // TODO: Better way of packing all the arguments together?
  uint8_t data[11] = {0};
  *reinterpret_cast<uint32_t*>(&data[0]) = caracal_id;
  *reinterpret_cast<uint32_t*>(&data[4]) = dst_addr;
  *reinterpret_cast<uint16_t*>(&data[8]) = src_port;
  *reinterpret_cast<uint8_t*>(&data[10]) = ttl;
  uint16_t checksum = 0;
  for (const uint8_t byte : data) {
    checksum = update_crc_16(checksum, byte);
  }
  return checksum;
}

}  // namespace caracal::Integrity
