#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

// Must be included after netinet/ip.h on macOS.
#include <netinet/icmp6.h>

#include <caracal/builder.hpp>
#include <caracal/checksum.hpp>
#include <caracal/constants.hpp>
#include <caracal/packet.hpp>
#include <caracal/protocols.hpp>

namespace caracal::Builder {

void assert_payload_size(Packet packet, size_t min_size) {
  if (packet.payload_size() < min_size) {
    auto msg = "The payload must be at-least " + std::to_string(min_size) +
               " bytes long to allow for a custom checksum";
    throw std::invalid_argument{msg};
  }
}

uint16_t transport_checksum(Packet packet) {
  uint64_t sum = Checksum::ip_checksum_add(0, packet.l4(), packet.l4_size());
  if (packet.l3_protocol() == Protocols::L3::IPv4) {
    const auto ip_header = reinterpret_cast<ip *>(packet.l3());
    sum += Checksum::ipv4_pseudo_header_sum(ip_header, packet.l4_size());
  } else {
    const auto ip_header = reinterpret_cast<ip6_hdr *>(packet.l3());
    sum += Checksum::ipv6_pseudo_header_sum(ip_header, packet.l4_size(),
                                            posix_value(packet.l4_protocol()));
  }
  return Checksum::ip_checksum_finish(sum);
}

uint16_t tweak_payload(const uint16_t original_checksum,
                       const uint16_t target_checksum) {
  uint32_t original_le = ~ntohs(original_checksum) & 0xFFFFU;
  uint32_t target_le = ~ntohs(target_checksum) & 0xFFFFU;
  if (target_le < original_le) {
    target_le += 0xFFFFU;
  }
  return htons(static_cast<uint16_t>(target_le - original_le));
}

}  // namespace caracal::Builder

namespace caracal::Builder::Loopback {

void init(Packet packet) {
  auto loopback_header = reinterpret_cast<uint32_t *>(packet.l2());
  if (packet.l3_protocol() == Protocols::L3::IPv4) {
    *loopback_header = 2;
  } else {
    *loopback_header = 30;
  }
}

}  // namespace caracal::Builder::Loopback

namespace caracal::Builder::Ethernet {

void init(Packet packet, const std::array<uint8_t, ETHER_ADDR_LEN> &src_addr,
          const std::array<uint8_t, ETHER_ADDR_LEN> &dst_addr) {
  auto eth_header = reinterpret_cast<ether_header *>(packet.l2());
  std::copy(src_addr.begin(), src_addr.end(), eth_header->ether_shost);
  std::copy(dst_addr.begin(), dst_addr.end(), eth_header->ether_dhost);
  if (packet.l3_protocol() == Protocols::L3::IPv4) {
    eth_header->ether_type = htons(ETHERTYPE_IP);
  } else {
    eth_header->ether_type = htons(ETHERTYPE_IPV6);
  }
}

}  // namespace caracal::Builder::Ethernet

namespace caracal::Builder::IPv4 {

void init(Packet packet, const in_addr src_addr, const in_addr dst_addr,
          const uint8_t ttl, const uint16_t id) {
  auto ip_header = reinterpret_cast<ip *>(packet.l3());
  ip_header->ip_hl = 5;
  ip_header->ip_v = 4;
  ip_header->ip_tos = 0;
  ip_header->ip_p = posix_value(packet.l4_protocol());
  ip_header->ip_src = src_addr;
  ip_header->ip_dst = dst_addr;
  ip_header->ip_ttl = ttl;
  ip_header->ip_id = htons(id);
  ip_header->ip_len = htons(packet.l3_size());
  ip_header->ip_sum = 0;
  ip_header->ip_sum = Checksum::ip_checksum(ip_header, sizeof(ip));
}

}  // namespace caracal::Builder::IPv4

namespace caracal::Builder::IPv6 {

void init(Packet packet, const in6_addr src_addr, const in6_addr dst_addr,
          const uint8_t ttl) {
  auto ip_header = reinterpret_cast<ip6_hdr *>(packet.l3());
  // We cannot store the TTL in the flow-ID field, since it is used for LB,
  // unlike IPv4. We rely on the payload length instead.
  // https://homepages.dcc.ufmg.br/~cunha/papers/almeida17pam-mda6.pdf
  // 4 bits version, 8 bits TC, 20 bits flow-ID.
  // Version = 6, TC = 0, flow-ID = 0.
  ip_header->ip6_flow = htonl(0x60000000U);
  ip_header->ip6_nxt = posix_value(packet.l4_protocol());
  ip_header->ip6_src = src_addr;
  ip_header->ip6_dst = dst_addr;
  ip_header->ip6_hops = ttl;
  ip_header->ip6_plen = htons(packet.l4_size());
}

}  // namespace caracal::Builder::IPv6

namespace caracal::Builder::ICMP {

void init(Packet packet, const uint16_t target_checksum,
          const uint16_t target_sequence) {
  assert_payload_size(packet, PAYLOAD_TWEAK_BYTES);

  auto icmp_header = reinterpret_cast<icmp *>(packet.l4());
  icmp_header->icmp_type = 8;  // ICMP Echo Request
  icmp_header->icmp_code = 0;  // ICMP Echo Request
  icmp_header->icmp_cksum = 0;
  icmp_header->icmp_hun.ih_idseq.icd_id = htons(target_checksum);
  icmp_header->icmp_hun.ih_idseq.icd_seq = htons(target_sequence);

  // Encode the flow ID in the checksum.
  const uint16_t original_checksum =
      Checksum::ip_checksum(icmp_header, ICMP_HEADER_SIZE);
  *reinterpret_cast<uint16_t *>(packet.payload()) =
      tweak_payload(original_checksum, htons(target_checksum));
  icmp_header->icmp_cksum = htons(target_checksum);
}

}  // namespace caracal::Builder::ICMP

namespace caracal::Builder::ICMPv6 {

void init(Packet packet, const uint16_t target_checksum,
          const uint16_t target_seq) {
  assert_payload_size(packet, PAYLOAD_TWEAK_BYTES);

  auto icmp6_header = reinterpret_cast<icmp6_hdr *>(packet.l4());
  icmp6_header->icmp6_type = 128;  // ICMPv6 Echo Request
  icmp6_header->icmp6_code = 0;    // ICMPv6 Echo Request
  icmp6_header->icmp6_cksum = 0;
  icmp6_header->icmp6_id = htons(target_checksum);
  icmp6_header->icmp6_seq = htons(target_seq);

  // Encode the flow ID in the checksum.
  // NOTE: The checksum computation is *different* from ICMPv4.
  const uint16_t original_checksum = transport_checksum(packet);
  *reinterpret_cast<uint16_t *>(packet.payload()) =
      tweak_payload(original_checksum, htons(target_checksum));
  icmp6_header->icmp6_cksum = htons(target_checksum);
}

}  // namespace caracal::Builder::ICMPv6

namespace caracal::Builder::UDP {

void init(Packet packet, const uint16_t target_checksum,
          const uint16_t src_port, const uint16_t dst_port) {
  assert_payload_size(packet, PAYLOAD_TWEAK_BYTES);
  auto udp_header = reinterpret_cast<udphdr *>(packet.l4());
  udp_header->uh_ulen = htons(packet.l4_size());
  udp_header->uh_sport = htons(src_port);
  udp_header->uh_dport = htons(dst_port);
  udp_header->uh_sum = 0;
  const uint16_t original_checksum = transport_checksum(packet);
  *reinterpret_cast<uint16_t *>(packet.payload()) =
      tweak_payload(original_checksum, htons(target_checksum));
  udp_header->uh_sum = htons(target_checksum);
}

}  // namespace caracal::Builder::UDP
