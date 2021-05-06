#include <caracal/checksum.hpp>
#include <caracal/constants.hpp>

namespace caracal::Checksum {

// For the IP checksum computation, see:
// https://tools.ietf.org/html/draft-heikkila-ip-checksum-00

uint16_t caracal_checksum(uint32_t caracal_id, uint32_t dst_addr,
                          uint16_t src_port, uint8_t ttl) {
  return ip_checksum_finish(caracal_id + dst_addr + src_port + ttl);
}

uint64_t ip_checksum_add(uint64_t sum, const void* data, size_t len) {
  // Sum 32-bit words
  auto data_32 = reinterpret_cast<const uint32_t*>(data);
  while (len >= 4) {
    sum += *(data_32++);
    len -= 4;
  }
  // Sum remaining 16-bit words
  auto data_16 = reinterpret_cast<const uint16_t*>(data_32);
  while (len >= 2) {
    sum += *(data_16++);
    len -= 2;
  }
  // Sum remaining byte
  auto data_8 = reinterpret_cast<const uint8_t*>(data_16);
  if (len == 1) {
    sum += *data_8;
  }
  return sum;
}

uint16_t ip_checksum_fold(uint64_t sum) {
  return static_cast<uint16_t>(sum % 65535);
}

uint16_t ip_checksum_finish(uint64_t sum) { return ~ip_checksum_fold(sum); }

uint16_t ip_checksum(const void* data, size_t len) {
  return ip_checksum_finish(ip_checksum_add(0, data, len));
}

uint64_t ipv4_pseudo_header_sum(const ip* ip_header,
                                const uint16_t transport_length) {
  uint64_t sum = 0;
  sum += ip_header->ip_src.s_addr;
  sum += ip_header->ip_dst.s_addr;
  sum += htons(ip_header->ip_p);
  sum += htons(transport_length);
  return sum;
}

uint64_t ipv6_pseudo_header_sum(const ip6_hdr* ip_header,
                                const uint32_t transport_length,
                                const uint8_t transport_protocol) {
  uint64_t sum = 0;
  sum += ip_header->ip6_src.s6_addr32[0];
  sum += ip_header->ip6_src.s6_addr32[1];
  sum += ip_header->ip6_src.s6_addr32[2];
  sum += ip_header->ip6_src.s6_addr32[3];
  sum += ip_header->ip6_dst.s6_addr32[0];
  sum += ip_header->ip6_dst.s6_addr32[1];
  sum += ip_header->ip6_dst.s6_addr32[2];
  sum += ip_header->ip6_dst.s6_addr32[3];
  sum += htonl(transport_length);
  sum += transport_protocol;
  return sum;
}

}  // namespace caracal::Checksum
