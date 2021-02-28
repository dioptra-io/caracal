#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

extern "C" {
#include <netutils/checksum.h>
}

#include <dminer/builder.hpp>
#include <dminer/checked.hpp>
#include <dminer/constants.hpp>
#include <dminer/packet.hpp>

namespace dminer::Builder {

uint16_t transport_checksum(Packet packet) {
  // (1) Sum the pseudo header.
  uint32_t current = 0;
  if (packet.l3_protocol() == IPPROTO_IP) {
    const auto ip_header = reinterpret_cast<ip *>(packet.l3());
    current = ipv4_pseudo_header_checksum(
        ip_header, Checked::numeric_cast<uint16_t>(packet.l4_size()));
  } else {
    const auto ip_header = reinterpret_cast<ip6_hdr *>(packet.l3());
    current = ipv6_pseudo_header_checksum(
        ip_header, Checked::numeric_cast<uint16_t>(packet.l4_size()),
        packet.l4_protocol());
  }
  // (2) Sum the transport header and the payload.
  current = ip_checksum_add(current, packet.l4(), packet.l4_size());
  // (3) Fold and close the sum.
  return ip_checksum_finish(current);
}

uint16_t tweak_payload(const uint16_t original_checksum,
                       const uint16_t target_checksum) {
  uint32_t original_le = ~ntohs(original_checksum) & 0xFFFFU;
  uint32_t target_le = ~ntohs(target_checksum) & 0xFFFFU;
  if (target_le < original_le) {
    target_le += 0xFFFFU;
  }
  return Checked::hton<uint16_t>(target_le - original_le);
}

}  // namespace dminer::Builder

namespace dminer::Builder::Loopback {

void init(Packet packet, const bool is_v4) {
  auto loopback_header = reinterpret_cast<uint32_t *>(packet.l2());
  *loopback_header = is_v4 ? 2 : 30;
}

}  // namespace dminer::Builder::Loopback

/// Build the Ethernet header.
namespace dminer::Builder::Ethernet {

void init(Packet packet, const bool is_v4,
          const std::array<uint8_t, ETHER_ADDR_LEN> &src_addr,
          const std::array<uint8_t, ETHER_ADDR_LEN> &dst_addr) {
  auto eth_header = reinterpret_cast<ether_header *>(packet.l2());
  std::copy(src_addr.begin(), src_addr.end(), eth_header->ether_shost);
  std::copy(dst_addr.begin(), dst_addr.end(), eth_header->ether_dhost);
  eth_header->ether_type = htons(is_v4 ? ETHERTYPE_IP : ETHERTYPE_IPV6);
}

}  // namespace dminer::Builder::Ethernet

/// Build IP probes.
/// In the IP header, the type of service, protocol, source and destination
/// address fields are used for per-flow load-balancing.
/// We also encode the TTL in the ID field in order to retrieve it in the ICMP
/// destination unreachable/TTL exceeded messages since the TTL field is
/// decreased/modified at each hop.
namespace dminer::Builder::IP {

/// Init the IPv4 header.
/// @param packet the packet buffer, including the IP header.
/// @param protocol the L4 protocol number.
/// @param src_addr the source IPv4 address.
/// @param dst_addr the destination IPv4 address.
/// @param ttl the TTL.
void init(Packet packet, const uint8_t protocol, const in_addr src_addr,
          const in_addr dst_addr, const uint8_t ttl) {
  auto ip_header = reinterpret_cast<ip *>(packet.l3());
  ip_header->ip_hl = 5;
  ip_header->ip_v = 4;
  ip_header->ip_tos = 0;
  ip_header->ip_p = protocol;
  ip_header->ip_src = src_addr;
  ip_header->ip_dst = dst_addr;
  ip_header->ip_ttl = ttl;
  ip_header->ip_id = Checked::hton<uint16_t>(ttl);
  ip_header->ip_len = Checked::hton<uint16_t>(packet.l3_size());
  ip_header->ip_sum = 0;
  ip_header->ip_sum = ip_checksum(ip_header, sizeof(ip));
}

/// Init the IPv6 header.
/// @param packet the packet buffer, including the IP header.
/// @param protocol the L4 protocol number.
/// @param src_addr the source IPv6 address.
/// @param dst_addr the destination IPv6 address.
/// @param ttl the TTL.
void init(Packet packet, const uint8_t protocol, const in6_addr src_addr,
          const in6_addr dst_addr, const uint8_t ttl) {
  auto ip_header = reinterpret_cast<ip6_hdr *>(packet.l3());
  // We cannot store the TTL in the flow-ID field, since it is used for LB,
  // unlike IPv4. We rely on the payload length instead.
  // https://homepages.dcc.ufmg.br/~cunha/papers/almeida17pam-mda6.pdf
  // 4 bits version, 8 bits TC, 20 bits flow-ID.
  // Version = 6, TC = 0, flow-ID = 0.
  ip_header->ip6_flow = htonl(0x60000000U);
  ip_header->ip6_nxt = protocol;
  ip_header->ip6_src = src_addr;
  ip_header->ip6_dst = dst_addr;
  ip_header->ip6_hops = ttl;
  ip_header->ip6_plen = Checked::hton<uint16_t>(packet.l4_size());
}

}  // namespace dminer::Builder::IP

/// Build ICMP echo probes.
/// In the ICMP echo header, the code and checksum fields are used for per-flow
/// load-balancing. We encode the flow ID in the checksum field to vary the flow
/// ID, and in the id field. We encode the timestamp in the sequence field.
/// Since echo replies, in contrast to destination unreachable messages, doesn't
/// contain the original probe packet (including the original TTL and flow ID),
/// we ignore them in the packet parser.
namespace dminer::Builder::ICMP {

// TODO: ICMPv6
// TODO: Fix checksum for ICMPv6.

/// Build an ICMP echo probe.
/// @param packet the packet buffer, including the IP header.
/// @param target_checksum the custom ICMP checksum, in host order.
/// @param target_seq the custom sequence field, in host order.
void init(Packet packet, const uint16_t target_checksum,
          const uint16_t target_seq) {
  if (packet.payload_size() < PAYLOAD_TWEAK_BYTES) {
    throw std::invalid_argument{"The payload must be at-least " +
                                std::to_string(PAYLOAD_TWEAK_BYTES) +
                                " bytes long to allow for a custom checksum"};
  }

  auto icmp_header = reinterpret_cast<icmp *>(packet.l4());
  icmp_header->icmp_type = 8;  // ICMP Echo Request
  icmp_header->icmp_code = 0;  // ICMP Echo Request
  icmp_header->icmp_cksum = 0;
  icmp_header->icmp_hun.ih_idseq.icd_id = htons(target_checksum);
  icmp_header->icmp_hun.ih_idseq.icd_seq = htons(target_seq);

  // Encode the flow ID in the checksum.
  const uint16_t original_checksum = ip_checksum(icmp_header, ICMP_HEADER_SIZE);
  *reinterpret_cast<uint16_t *>(packet.payload()) =
      tweak_payload(original_checksum, htons(target_checksum));
  icmp_header->icmp_cksum = htons(target_checksum);
}

}  // namespace dminer::Builder::ICMP

/// Build TCP probes.
/// In the TCP header, the source and destination ports are used for per-flow
/// load-balancing. We use those for encoding the flow ID, and we encode the
/// timestamp as well as the TTL in the 32-bit sequence field.
namespace dminer::Builder::TCP {

/// Init the TCP header.
/// @param packet the packet buffer, including the IP header.
void init(Packet packet) {
  auto tcp_header = reinterpret_cast<tcphdr *>(packet.l4());
  tcp_header->th_ack = 0;
  tcp_header->th_off = 5;
  // Do not send TCP SYN because of SYN Flood, do not put any TCP flags
  //    tcp_header->th_flags |= TH_SYN;
  //    tcp_header->th_flags |= TH_ACK;
  tcp_header->th_x2 = 0;
  tcp_header->th_flags = 0;
  tcp_header->th_win = htons(50);
  tcp_header->th_urp = 0;
}

/// Compute and set the checksum in the TCP header.
/// The packet must not be modified afterward to ensure that the checksum is
/// valid.
/// @param packet the packet buffer, including the IP header.
void set_checksum(Packet packet) {
  auto tcp_header = reinterpret_cast<tcphdr *>(packet.l4());
  tcp_header->th_sum = 0;
  tcp_header->th_sum = transport_checksum(packet);
}

/// Set the ports in the TCP header.
/// @param packet the packet buffer, including the IP header.
/// @param src_port the source port, in host order.
/// @param dst_port the destination port, in host order.
void set_ports(Packet packet, const uint16_t src_port,
               const uint16_t dst_port) {
  auto tcp_header = reinterpret_cast<tcphdr *>(packet.l4());
  tcp_header->th_sport = htons(src_port);
  tcp_header->th_dport = htons(dst_port);
}

/// Encode two 16-bit values in the 32-bit sequence field ((seq1 << 16) + seq2).
/// @param packet the packet buffer, including the IP header.
/// @param seq1 the first value to encode, in host order.
/// @param seq2 the second value to encode, in host order.
void set_sequence(Packet packet, const uint16_t seq1, const uint16_t seq2) {
  auto tcp_header = reinterpret_cast<tcphdr *>(packet.l4());
  uint32_t seq = (static_cast<uint32_t>(seq1) << 16) + seq2;
  tcp_header->th_seq = htonl(seq);
}

}  // namespace dminer::Builder::TCP

/// Build UDP probes.
/// In the UDP header, the source and destination ports are used for per-flow
/// load-balancing. We use those for encoding the flow ID, and we encode the
/// timestamp in the checksum (which doesn't affect the flow ID).
/// The TTL is encoded in the payload length, in addition to the TTL field in
/// the IP header. The payload is all zeros, except two bytes used to ensure
/// that the custom checksum is valid.
namespace dminer::Builder::UDP {

/// Compute and set the checksum in the UDP header.
/// The packet must not be modified afterward to ensure that the checksum is
/// valid.
/// @param packet the packet buffer, including the IP header.
void set_checksum(Packet packet) {
  auto udp_header = reinterpret_cast<udphdr *>(packet.l4());
  udp_header->uh_sum = 0;
  udp_header->uh_sum = transport_checksum(packet);
}

/// Set a custom checksum in the UDP header, and ensure that the checksum is
/// valid by tweaking the payload.
/// @param packet the packet buffer, including the IP header.
/// @param target_checksum the custom checksum, in host order.
void set_checksum(Packet packet, const uint16_t target_checksum) {
  if (packet.payload_size() < PAYLOAD_TWEAK_BYTES) {
    // TODO: Builder::Exception::PayloadTooSmall exception ?
    throw std::invalid_argument{"The payload must be at-least " +
                                std::to_string(PAYLOAD_TWEAK_BYTES) +
                                " bytes long to allow for a custom checksum"};
  }
  auto udp_header = reinterpret_cast<udphdr *>(packet.l4());
  udp_header->uh_sum = 0;
  const uint16_t original_checksum = transport_checksum(packet);
  *reinterpret_cast<uint16_t *>(packet.payload()) =
      tweak_payload(original_checksum, htons(target_checksum));
  udp_header->uh_sum = htons(target_checksum);
}

/// Set the length in the UDP header.
/// @param packet the packet buffer, including the IP header.
void set_length(Packet packet) {
  auto udp_header = reinterpret_cast<udphdr *>(packet.l4());
  udp_header->uh_ulen = Checked::hton<uint16_t>(packet.l4_size());
}

/// Set the ports in the UDP header.
/// @param packet the packet buffer, including the IP header.
/// @param src_port the source port, in host order.
/// @param dst_port the destination port, in host order.
void set_ports(Packet packet, const uint16_t src_port,
               const uint16_t dst_port) {
  auto udp_header = reinterpret_cast<udphdr *>(packet.l4());
  udp_header->uh_sport = htons(src_port);
  udp_header->uh_dport = htons(dst_port);
}

}  // namespace dminer::Builder::UDP
