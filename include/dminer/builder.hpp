#pragma once

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

extern "C" {
#include <netutils/checksum.h>
}

#include <span>

/// Build probe packets.
namespace dminer::Builder {

typedef std::span<std::byte> Packet;

/// Compute the transport-level checksum.
/// @param packet the packet buffer, including the IP header.
/// @return the transport-level checksum in network order.
[[nodiscard]] inline uint16_t transport_checksum(Packet packet) {
  const auto ip_header = reinterpret_cast<iphdr *>(packet.data());
  // (1) Sum the pseudo header.
  uint32_t current =
      ipv4_pseudo_header_checksum(ip_header, packet.size() - sizeof(ip));
  // (2) Sum the transport header and the payload.
  const auto payload = packet.subspan(sizeof(ip));
  current = ip_checksum_add(current, payload.data(), payload.size());
  // (3) Fold and close the sum.
  return ip_checksum_finish(current);
}

/// Return the two bytes of the payload to ensure that the target checksum is
/// valid.
/// @param original_checksum the transport-level checksum of the packet.
/// @param target_checksum the target transport-level checksum.
/// @return the two bytes of the payload.
[[nodiscard]] inline uint16_t tweak_payload(const uint16_t original_checksum,
                                            const uint16_t target_checksum) {
  uint32_t original_le = ~ntohs(original_checksum) & 0xFFFF;
  uint32_t target_le = ~ntohs(target_checksum) & 0xFFFF;
  if (target_le < original_le) {
    target_le += 0xFFFF;
  }
  return htons(target_le - original_le);
}

}  // namespace dminer::Builder

/// Build IPv4 probes.
/// In the IP header, the type of service, protocol, source and destination
/// address fields are used for per-flow load-balancing.
/// We also encode the TTL in the ID field in order to retrieve it in the ICMP
/// destination unreachable/TTL exceeded messages since the TTL field is
/// decreased/modified at each hop.
namespace dminer::Builder::IPv4 {

/// Init the IPv4 header.
/// @param packet the packet buffer, including the IP header.
/// @param protocol the IP protocol number.
/// @param src_addr the source IPv4 address.
/// @param dst_addr the destination IPv4 address.
/// @param ttl the TTL.
inline void init(Packet packet, const uint8_t protocol, const in_addr src_addr,
                 const in_addr dst_addr, const uint8_t ttl) {
  auto ip_header = reinterpret_cast<ip *>(packet.data());
  ip_header->ip_hl = 5;
  ip_header->ip_v = 4;
  ip_header->ip_tos = 0;
  ip_header->ip_p = protocol;
  ip_header->ip_src = src_addr;
  ip_header->ip_dst = dst_addr;
  ip_header->ip_ttl = ttl;
  ip_header->ip_id = htons(ttl);
  ip_header->ip_len = htons(packet.size());

#ifdef __APPLE__
  ip_header->ip_len = htons(ip_header->ip_len);
#endif

  ip_header->ip_sum = 0;
  ip_header->ip_sum = ip_checksum(ip_header, sizeof(ip));
}

}  // namespace dminer::Builder::IPv4

/// Build ICMP echo probes.
/// In the ICMP echo header, the code and checksum fields are used for per-flow
/// load-balancing. We encode the flow ID in the checksum field to vary the flow
/// ID, and in the id field. We encode the timestamp in the sequence field.
/// Since echo replies, in contrast to destination unreachable messages, doesn't
/// contain the original probe packet (including the original TTL and flow ID),
/// we ignore them in the packet parser.
namespace dminer::Builder::ICMP {

/// Build an ICMP echo probe.
/// @param packet the packet buffer, including the IP header.
/// @param target_checksum the custom ICMP checksum, in host order.
/// @param target_seq the custom sequence field, in host order.
inline void init(Packet packet, const uint16_t target_checksum,
                 const uint16_t target_seq) {
  if (packet.size() < (sizeof(ip) + sizeof(icmphdr) + 2)) {
    throw std::invalid_argument{
        "The payload must be at-least two bytes long to allow for a custom "
        "checksum"};
  }

  auto icmp_header =
      reinterpret_cast<icmphdr *>(packet.subspan(sizeof(ip)).data());
  icmp_header->type = 8;  // ICMP Echo Request
  icmp_header->code = 0;  // ICMP Echo Request
  icmp_header->checksum = 0;
  icmp_header->un.echo.id = htons(target_checksum);
  icmp_header->un.echo.sequence = htons(target_seq);

  // Encode the flow ID in the checksum.
  const uint16_t original_checksum = ip_checksum(icmp_header, sizeof(icmphdr));
  *reinterpret_cast<uint16_t *>(
      packet.subspan(sizeof(ip) + sizeof(icmphdr)).data()) =
      tweak_payload(original_checksum, htons(target_checksum));
  icmp_header->checksum = htons(target_checksum);
}

}  // namespace dminer::Builder::ICMP

/// Build TCP probes.
/// In the TCP header, the source and destination ports are used for per-flow
/// load-balancing. We use those for encoding the flow ID, and we encode the
/// timestamp as well as the TTL in the 32-bit sequence field.
namespace dminer::Builder::TCP {

/// Init the TCP header.
/// @param packet the packet buffer, including the IP header.
inline void init(Packet packet) {
  auto tcp_header =
      reinterpret_cast<tcphdr *>(packet.subspan(sizeof(ip)).data());
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
inline void set_checksum(Packet packet) {
  auto tcp_header =
      reinterpret_cast<tcphdr *>(packet.subspan(sizeof(ip)).data());
  tcp_header->th_sum = 0;
  tcp_header->th_sum = transport_checksum(packet);
}

/// Set the ports in the TCP header.
/// @param packet the packet buffer, including the IP header.
/// @param src_port the source port, in host order.
/// @param dst_port the destination port, in host order.
inline void set_ports(Packet packet, const uint16_t src_port,
                      const uint16_t dst_port) {
  auto tcp_header =
      reinterpret_cast<tcphdr *>(packet.subspan(sizeof(ip)).data());
  tcp_header->th_sport = htons(src_port);
  tcp_header->th_dport = htons(dst_port);
}

/// Encode two 16-bit values in the 32-bit sequence field ((seq1 << 16) + seq2).
/// @param packet the packet buffer, including the IP header.
/// @param seq1 the first value to encode, in host order.
/// @param seq2 the second value to encode, in host order.
inline void set_sequence(Packet packet, const uint16_t seq1,
                         const uint16_t seq2) {
  auto tcp_header =
      reinterpret_cast<tcphdr *>(packet.subspan(sizeof(ip)).data());
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
inline void set_checksum(Packet packet) {
  auto udp_header =
      reinterpret_cast<udphdr *>(packet.subspan(sizeof(ip)).data());
  udp_header->uh_sum = 0;
  udp_header->uh_sum = transport_checksum(packet);
}

/// Set a custom checksum in the UDP header, and ensure that the checksum is
/// valid by tweaking the payload.
/// @param packet the packet buffer, including the IP header.
/// @param target_checksum the custom checksum, in host order.
inline void set_checksum(Packet packet, const uint16_t target_checksum) {
  if (packet.size() < (sizeof(ip) + sizeof(udphdr) + 2)) {
    throw std::invalid_argument{
        "The payload must be at-least two bytes long to allow for a custom "
        "checksum"};
  }
  auto udp_header =
      reinterpret_cast<udphdr *>(packet.subspan(sizeof(ip)).data());
  udp_header->uh_sum = 0;
  const uint16_t original_checksum = transport_checksum(packet);
  *reinterpret_cast<uint16_t *>(
      packet.subspan(sizeof(ip) + sizeof(udphdr)).data()) =
      tweak_payload(original_checksum, htons(target_checksum));
  udp_header->uh_sum = htons(target_checksum);
}

/// Set the length in the UDP header.
/// @param packet the packet buffer, including the IP header.
inline void set_length(Packet packet) {
  auto udp_header =
      reinterpret_cast<udphdr *>(packet.subspan(sizeof(ip)).data());
  udp_header->len = htons(packet.size() - sizeof(ip));
}

/// Set the ports in the UDP header.
/// @param packet the packet buffer, including the IP header.
/// @param src_port the source port, in host order.
/// @param dst_port the destination port, in host order.
inline void set_ports(Packet packet, const uint16_t src_port,
                      const uint16_t dst_port) {
  auto udp_header =
      reinterpret_cast<udphdr *>(packet.subspan(sizeof(ip)).data());
  udp_header->uh_sport = htons(src_port);
  udp_header->uh_dport = htons(dst_port);
}

}  // namespace dminer::Builder::UDP
