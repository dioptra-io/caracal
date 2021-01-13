#pragma once

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

extern "C" {
#include <netutils/checksum.h>
}

#include <iostream>

#include "timestamp.hpp"

using dminer::encode_timestamp;

/// Build probe packets.
namespace dminer::Builder {

/// Compute the transport-level checksum.
/// @param buffer the packet buffer, including the IP header.
/// @param transport_length the IP payload length (including the L4 header).
/// @return the transport-level checksum in network order.
inline uint16_t checksum(uint8_t *buffer, const uint16_t transport_length) {
  auto *ip_header = reinterpret_cast<iphdr *>(buffer);
  // (1) Sum the pseudo header.
  uint32_t current = ipv4_pseudo_header_checksum(ip_header, transport_length);
  // (2) Sum the transport header and the payload.
  current = ip_checksum_add(current, buffer + sizeof(ip), transport_length);
  // (3) Fold and close the sum.
  return ip_checksum_finish(current);
}

/// Return the two bytes of the payload to ensure that the target checksum is
/// valid.
/// @param original_checksum the transport-level checksum of the packet.
/// @param target_checksum the target transport-level checksum.
/// @return the two bytes of the payload.
uint16_t tweak_payload(uint16_t original_checksum, uint16_t target_checksum) {
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
/// @param buffer the packet buffer, including the IP header.
/// @param protocol the IP protocol number.
/// @param src_addr the source IPv4 address.
/// @param dst_addr the destination IPv4 address.
/// @param ttl the TTL.
/// @param payload_len the IP payload length (including the L4 header).
inline void init(uint8_t *buffer, uint8_t protocol, in_addr src_addr,
                 in_addr dst_addr, uint8_t ttl, uint16_t payload_len) {
  auto *ip_header = reinterpret_cast<ip *>(buffer);

  ip_header->ip_hl = 5;
  ip_header->ip_v = 4;
  ip_header->ip_tos = 0;
  ip_header->ip_p = protocol;
  ip_header->ip_src = src_addr;
  ip_header->ip_dst = dst_addr;
  ip_header->ip_ttl = ttl;
  ip_header->ip_id = htons(ttl);

  if (protocol == IPPROTO_UDP) {
    ip_header->ip_len = htons(sizeof(ip) + sizeof(udphdr) + payload_len);
  } else if (protocol == IPPROTO_TCP) {
    ip_header->ip_len = htons(sizeof(ip) + sizeof(tcphdr) + payload_len);
  } else if (protocol == IPPROTO_ICMP) {
    ip_header->ip_len = htons(sizeof(ip) + sizeof(icmphdr) + payload_len);
  }

#ifdef __APPLE__
  ip_header->ip_len = htons(ip_header->ip_len);
#endif

  ip_header->ip_sum = 0;
  ip_header->ip_sum = ip_checksum(ip_header, sizeof(ip));
}

}  // namespace dminer::Builder::IPv4

/// Build TCP probes.
/// In the TCP header, the source and destination ports are used for per-flow
/// load-balancing. We use those for encoding the flow ID, and we encode the
/// timestamp as well as the TTL in the 32-bit sequence field.
namespace dminer::Builder::TCP {

/// Init the TCP header.
/// @param buffer the packet buffer, including the IP header.
inline void init(uint8_t *buffer) {
  auto *tcp_header = reinterpret_cast<tcphdr *>(buffer + sizeof(ip));
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
/// @param buffer the packet buffer, including the IP header.
/// @param payload_len the TCP payload length.
inline void set_checksum(uint8_t *buffer, uint16_t payload_len) {
  auto *tcp_header = reinterpret_cast<tcphdr *>(buffer + sizeof(ip));
  tcp_header->th_sum = 0;
  tcp_header->th_sum = checksum(buffer, sizeof(tcphdr) + payload_len);
}

/// Set the ports in the TCP header.
/// @param buffer the packet buffer, including the IP header.
/// @param src_port the source port, in host order.
/// @param dst_port the destination port, in host order.
inline void set_ports(uint8_t *buffer, const uint16_t src_port,
                      const uint16_t dst_port) {
  auto *tcp_header = reinterpret_cast<tcphdr *>(buffer + sizeof(ip));
  tcp_header->th_sport = htons(src_port);
  tcp_header->th_dport = htons(dst_port);
}

/// Encode the TTL and the timestamp in the 32-bit sequence field
/// (27 bits for the timestamp and 5 bits for the TTL).
/// @param buffer the packet buffer, including the IP header.
/// @param timestamp the timestamp to encode.
/// @param ttl the TTL to encode.
inline void set_sequence(uint8_t *buffer, const uint64_t timestamp,
                         const uint8_t ttl) {
  auto *tcp_header = reinterpret_cast<tcphdr *>(buffer + sizeof(ip));
  // The sequence number is 27 bits of timestamp + 5 bits of TTL
  uint32_t msb_ttl = static_cast<uint32_t>(ttl) << 27;
  uint32_t seq_no = encode_timestamp(timestamp) + msb_ttl;
  tcp_header->th_seq = htonl(seq_no);
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
/// @param buffer the packet buffer, including the IP header.
/// @param payload_len the UDP payload length.
inline void set_checksum(uint8_t *buffer, const uint16_t payload_len) {
  auto *udp_header = reinterpret_cast<udphdr *>(buffer + sizeof(ip));
  udp_header->uh_sum = 0;
  udp_header->uh_sum = checksum(buffer, sizeof(udphdr) + payload_len);
}

/// Set the length in the UDP header.
/// @param buffer the packet buffer, including the IP header.
/// @param payload_len the UDP payload length.
inline void set_length(uint8_t *buffer, const uint16_t payload_len) {
  auto *udp_header = reinterpret_cast<udphdr *>(buffer + sizeof(ip));
  udp_header->len = htons(sizeof(udphdr) + payload_len);
}

/// Set the ports in the UDP header.
/// @param buffer the packet buffer, including the IP header.
/// @param src_port the source port, in host order.
/// @param dst_port the destination port, in host order.
inline void set_ports(uint8_t *buffer, const uint16_t src_port,
                      const uint16_t dst_port) {
  auto *udp_header = reinterpret_cast<udphdr *>(buffer + sizeof(ip));
  udp_header->uh_sport = htons(src_port);
  udp_header->uh_dport = htons(dst_port);
}

/// Encode the timestamp in the UDP checksum, and ensure that the checksum is
/// valid by tweaking the payload.
/// @param buffer the packet buffer, including the IP header.
/// @param payload_len the UDP payload length.
/// @param timestamp the timestamp to encode.
inline void set_timestamp(uint8_t *buffer, const size_t payload_len,
                          const uint64_t timestamp) {
  auto *udp_header = reinterpret_cast<udphdr *>(buffer + sizeof(ip));
  udp_header->uh_sum = 0;
  const uint16_t original_checksum =
      checksum(buffer, sizeof(udphdr) + payload_len);
  const uint16_t target_checksum = encode_timestamp(timestamp);
  *reinterpret_cast<uint16_t *>(buffer + sizeof(ip) + sizeof(udphdr)) =
      tweak_payload(original_checksum, target_checksum);
  udp_header->uh_sum = target_checksum;
}

}  // namespace dminer::Builder::UDP

/// Build ICMP echo probes.
/// In the ICMP echo header, the code and checksum fields are used for per-flow
/// load-balancing. We encode the flow ID in the checksum field to vary the flow
/// ID, and in the id field. We encode the timestamp in the sequence field.
/// Since echo replies, in contrast to destination unreachable messages, doesn't
/// contain the original probe packet (including the original TTL and flow ID),
/// we ignore them in the packet parser.
namespace dminer::Builder::ICMP {

/// Build an ICMP echo probe.
/// @param buffer the packet buffer, including the IP header.
/// @param flow_id the flow ID to be encoded in the checksum.
/// @param timestamp the timestamp to be encoded in the sequence field.
void init(uint8_t *buffer, const uint16_t flow_id, const size_t payload_len,
          const uint64_t timestamp) {
  auto *icmp_header = reinterpret_cast<icmphdr *>(buffer + sizeof(ip));
  icmp_header->type = 8;  // ICMP Echo Request
  icmp_header->code = 0;  // ICMP Echo Request
  icmp_header->checksum = 0;
  icmp_header->un.echo.id = flow_id;
  icmp_header->un.echo.sequence = encode_timestamp(timestamp);

  // Encode the flow ID in the checksum.
  const uint16_t original_checksum = ip_checksum(icmp_header, sizeof(icmphdr));
  *reinterpret_cast<uint16_t *>(buffer + sizeof(ip) + sizeof(icmphdr)) =
      tweak_payload(original_checksum, flow_id);
  icmp_header->checksum = flow_id;
}

}  // namespace dminer::Builder::ICMP
