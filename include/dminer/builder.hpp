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

namespace dminer::Builder {

inline uint16_t checksum(uint8_t *buffer, const uint16_t transport_length) {
  auto *ip_header = reinterpret_cast<iphdr *>(buffer);
  // (1) Sum the pseudo header.
  uint32_t current = ipv4_pseudo_header_checksum(ip_header, transport_length);
  // (2) Sum the transport header and the payload.
  current = ip_checksum_add(current, buffer + sizeof(ip), transport_length);
  // (3) Fold and close the sum.
  return ip_checksum_finish(current);
}

void fill(uint8_t *buffer, const uint16_t length, const uint8_t value) {
  for (uint16_t i = 0; i < length; ++i) {
    buffer[i] = value;
  }
}

}  // namespace dminer::Builder

namespace dminer::Builder::IP {
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
}  // namespace dminer::Builder::IP

namespace dminer::Builder::TCP {
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

inline void set_ports(uint8_t *buffer, const uint16_t src_port,
                      const uint16_t dst_port) {
  auto *tcp_header = reinterpret_cast<tcphdr *>(buffer + sizeof(ip));
  tcp_header->th_sport = htons(src_port);
  tcp_header->th_dport = htons(dst_port);
}

inline void set_timestamp(uint8_t *buffer, const uint64_t timestamp,
                          const uint8_t ttl) {
  auto *tcp_header = reinterpret_cast<tcphdr *>(buffer + sizeof(ip));
  // The sequence number is 27 bits of diff time + 5 bits of ttl
  uint32_t msb_ttl = static_cast<uint32_t>(ttl) << 27;
  uint32_t seq_no = encode_timestamp(timestamp) + msb_ttl;
  tcp_header->th_seq = htonl(seq_no);
}

inline void set_checksum(uint8_t *buffer, uint16_t payload_len) {
  auto *tcp_header = reinterpret_cast<tcphdr *>(buffer + sizeof(ip));
  tcp_header->th_sum = 0;
  tcp_header->th_sum = checksum(buffer, sizeof(tcphdr) + payload_len);
}

}  // namespace dminer::Builder::TCP

namespace dminer::Builder::UDP {
inline void set_ports(uint8_t *buffer, uint16_t src_port, uint16_t dst_port) {
  auto *udp_header = reinterpret_cast<udphdr *>(buffer + sizeof(ip));
  udp_header->uh_sport = htons(src_port);
  udp_header->uh_dport = htons(dst_port);
}

inline void set_checksum(uint8_t *buffer, uint16_t payload_len) {
  auto *udp_header = reinterpret_cast<udphdr *>(buffer + sizeof(ip));
  udp_header->uh_sum = 0;
  udp_header->uh_sum = checksum(buffer, sizeof(udphdr) + payload_len);
}

inline void set_length(uint8_t *buffer, const uint16_t payload_len) {
  auto *udp_header = reinterpret_cast<udphdr *>(buffer + sizeof(ip));
  udp_header->len = htons(sizeof(udphdr) + payload_len);
  // +2 because 2 bytes are minimum to be able to fully tweak the checksum
}

inline void set_timestamp(uint8_t *buffer, const size_t payload_len,
                          const uint64_t timestamp) {
  auto *udp_header = reinterpret_cast<udphdr *>(buffer + sizeof(ip));
  udp_header->uh_sum = 0;
  uint32_t wrong_checksum =
      ~ntohs(checksum(buffer, sizeof(udphdr) + payload_len)) & 0xFFFF;

  // Encode the send time in the checksum
  auto target_checksum = static_cast<uint16_t>(encode_timestamp(timestamp));
  if (target_checksum == 0) {
    udp_header->uh_sum = 0;
    return;
  }

  uint32_t target_checksum_little_endian = ~ntohs(target_checksum) & 0xFFFF;
  uint32_t c = target_checksum_little_endian;
  if (c < wrong_checksum) {
    c += 0xFFFF;
  }

  uint32_t payload = c - wrong_checksum;

  // First 2 bytes of payload make the checksum vary. Other bytes are just
  // padding.
  auto *checksum_tweak_data =
      reinterpret_cast<uint16_t *>(buffer + sizeof(ip) + sizeof(udphdr));
  *checksum_tweak_data = htons(payload);

  udp_header->uh_sum = target_checksum;
}
}  // namespace dminer::Builder::UDP

namespace dminer::Builder::ICMP {
void init(uint8_t *buffer, const uint16_t target_checksum,
          const uint64_t timestamp) {
  auto *icmp_header = reinterpret_cast<icmphdr *>(buffer + sizeof(ip));
  icmp_header->type = 8;  // ICMP ECHO request
  icmp_header->code = 0;  // ICMP ECHO request
  icmp_header->checksum = 0;
  icmp_header->un.echo.id = target_checksum;  // Redundant for checksum
  icmp_header->un.echo.sequence =
      encode_timestamp(timestamp);  // Has to encode timestamp

  uint32_t target_checksum_little_endian = ~ntohs(target_checksum) & 0xFFFF;
  // Deconstruct the checksum
  // Little endian checksum
  uint32_t wrong_checksum =
      ~ntohs(ip_checksum(icmp_header, sizeof(icmphdr))) & 0xFFFF;

  uint32_t c = target_checksum_little_endian;
  if (c < wrong_checksum) {
    c += 0xFFFF;
  }
  uint32_t payload = c - wrong_checksum;

  // First 2 bytes of payload make the checksum vary. Other bytes are just
  // padding.
  auto *checksum_tweak_data =
      reinterpret_cast<uint16_t *>(buffer + sizeof(ip) + sizeof(icmphdr));
  *checksum_tweak_data = htons(payload);

  icmp_header->checksum = target_checksum;
}
}  // namespace dminer::Builder::ICMP
