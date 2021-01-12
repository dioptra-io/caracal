#pragma once

#include <net/ethernet.h>
#include <netinet/ip.h>

#include <iostream>

#include "network_utils_t.hpp"
#include "timestamp.hpp"

using dminer::encode_timestamp;
using utils::compact_ip_hdr;
using utils::in_cksum;
using utils::one_s_complement_bits32_sum_to_16;
using utils::pseudo_header;
using utils::pseudo_header_udp;
using utils::sum;
using utils::tcphdr;
using utils::udphdr;
using utils::wrapsum;

namespace packets_utils {

inline void init_ip_header(uint8_t *buffer, uint8_t ip_proto,
                           uint32_t uint_src_addr) {
  compact_ip_hdr *ip_header = reinterpret_cast<compact_ip_hdr *>(buffer);
  ip_header->ip_hl = 5;
  ip_header->ip_v = 4;
  ip_header->ip_tos = 0;

  //    ip_header->ip_off = htons(0);
  //    m_ip_hdr.ip_id = htons(54321);
  //    m_ip_hdr.ip_ttl = 64; // hops
  ip_header->ip_p = ip_proto;  // Transport protocol

  ip_header->ip_src = uint_src_addr;
}

inline void init_tcp_header(uint8_t *transport_buffer) {
  tcphdr *tcp_header = reinterpret_cast<tcphdr *>(transport_buffer);

  tcp_header->th_ack = 0;
  tcp_header->th_off = 5;
  // Do not send TCP SYN because of SYN Flood, do not put any TCP flags
  //    tcp_header->th_flags |= TH_SYN;
  //    tcp_header->th_flags |= TH_ACK;
  tcp_header->th_x2 = 0;
  tcp_header->th_flags = 0;
  tcp_header->th_win = htons(50);
  //    tcp_header->th_chksum = 0; // Fill later
  tcp_header->th_urp = 0;
}

inline void complete_ip_header(uint8_t *ip_buffer, uint32_t destination,
                               uint8_t ttl, uint8_t proto,
                               uint16_t payload_len) {
  compact_ip_hdr *ip_header = reinterpret_cast<compact_ip_hdr *>(ip_buffer);
  ip_header->ip_dst = destination;
  ip_header->ip_ttl = ttl;
  ip_header->ip_id = htons(ttl);

  // Encode 16 last bits of the IP address in IP checksum to avoid NATs
  //    uint16_t lsb_16_destination = n_last_bits(ntohl(destination), 16);
  //    ip_header->ip_sum = lsb_16_destination;
  //    adjust_payload_len(ip_buffer, lsb_16_destination, proto);

  // Compute the payload length so that it has the good checksum.
  if (proto == IPPROTO_UDP) {
#ifdef __APPLE__

    ip_header->ip_len = sizeof(ip) + sizeof(udphdr) + payload_len;
#else
    ip_header->ip_len = htons(sizeof(ip) + sizeof(udphdr) + payload_len);
#endif
  } else if (proto == IPPROTO_TCP) {
#ifdef __APPLE__

    ip_header->ip_len = sizeof(ip) + sizeof(tcphdr) + payload_len;
#else
    ip_header->ip_len = htons(sizeof(ip) + sizeof(tcphdr) + payload_len);
#endif
  }

  // Reset the checksum before computation
  ip_header->ip_sum = 0;

  // Value of the checksum in big endian
  ip_header->ip_sum =
      wrapsum(in_cksum((unsigned char *)ip_header, sizeof(*ip_header), 0));
}

inline void add_udp_ports(uint8_t *transport_buffer, uint16_t sport,
                          uint16_t dport) {
  udphdr *udp_header = reinterpret_cast<udphdr *>(transport_buffer);

  // Network order values.
  udp_header->uh_sport = sport;
  udp_header->uh_dport = dport;
}

inline void add_transport_checksum(uint8_t *transport_buffer,
                                   uint8_t *ip_buffer, uint8_t proto,
                                   char *payload, uint16_t payload_len) {
  compact_ip_hdr *ip_header = reinterpret_cast<compact_ip_hdr *>(ip_buffer);
  // Calculate the checksum for integrity
  // Now the UDP checksum using the pseudo header
  pseudo_header psh;
  psh.source_address = ip_header->ip_src;
  psh.dest_address = ip_header->ip_dst;
  psh.placeholder = 0;
  psh.protocol = proto;

  if (proto == IPPROTO_UDP) {
    udphdr *udp_header = reinterpret_cast<udphdr *>(transport_buffer);
    // Set this field later
    udp_header->uh_sum = 0;
    psh.transport_length = htons(sizeof(struct udphdr) + payload_len);
    // Implementation to avoid memcpy system call
    uint32_t pseudo_header_sum_16 =
        sum(reinterpret_cast<uint16_t *>(&psh), sizeof(pseudo_header));
    uint32_t udp_header_sum_16 =
        sum(reinterpret_cast<uint16_t *>(udp_header), sizeof(udphdr));
    uint32_t payload_sum_16 =
        sum(reinterpret_cast<uint16_t *>(payload), payload_len);
    //    udp_header->uh_sum = csum(reinterpret_cast<uint16_t *>(pseudogram) ,
    //    psize);
    udp_header->uh_sum = one_s_complement_bits32_sum_to_16(
        pseudo_header_sum_16 + udp_header_sum_16 + payload_sum_16);

    if (udp_header->uh_sum == 0) {
      udp_header->uh_sum = 0xFFFF;
    }

  } else if (proto == IPPROTO_TCP) {
    tcphdr *tcp_header = reinterpret_cast<tcphdr *>(transport_buffer);
    tcp_header->th_sum = 0;
    psh.transport_length = htons(sizeof(struct tcphdr) + payload_len);
    // Implementation to avoid memcpy system call
    uint32_t pseudo_header_sum_16 =
        sum(reinterpret_cast<uint16_t *>(&psh), sizeof(pseudo_header));
    uint32_t tcp_header_sum_16 =
        sum(reinterpret_cast<uint16_t *>(tcp_header), sizeof(tcphdr));
    uint32_t payload_sum_16 =
        sum(reinterpret_cast<uint16_t *>(payload), payload_len);
    //    udp_header->uh_sum = csum(reinterpret_cast<uint16_t *>(pseudogram) ,
    //    psize);
    tcp_header->th_sum = one_s_complement_bits32_sum_to_16(
        pseudo_header_sum_16 + tcp_header_sum_16 + payload_sum_16);
  }

  //    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) +
  //    m_payload.size(); char pseudogram[psize];
  //
  //    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
  //    memcpy(pseudogram + sizeof(struct pseudo_header) , udp_header ,
  //    sizeof(struct udphdr) + m_payload.size());
}

inline void add_tcp_ports(uint8_t *transport_buffer, const uint16_t sport,
                          const uint16_t dport) {
  tcphdr *tcp_header = reinterpret_cast<tcphdr *>(transport_buffer);
  // Network order values.
  tcp_header->th_sport = sport;
  tcp_header->th_dport = dport;
}

inline void add_tcp_timestamp(uint8_t *transport_buffer,
                              const uint64_t timestamp, const uint8_t ttl) {
  tcphdr *tcp_header = reinterpret_cast<tcphdr *>(transport_buffer);
  // The sequence number is 27 bits of diff time + 5 bits of ttl
  uint32_t msb_ttl = static_cast<uint32_t>(ttl) << 27;
  uint32_t seq_no = encode_timestamp(timestamp) + msb_ttl;
  tcp_header->th_seq = htonl(seq_no);
}

inline void add_udp_length(uint8_t *transport_buffer,
                           const uint16_t payload_length) {
  udphdr *udp_header = reinterpret_cast<udphdr *>(transport_buffer);
  udp_header->len = htons(sizeof(udphdr) + payload_length);
  // +2 because 2 bytes are minimum to be able to fully tweak the checksum
}

inline void add_udp_timestamp(uint8_t *transport_buffer,
                              const uint64_t timestamp) {
  udphdr *udp_header = reinterpret_cast<udphdr *>(transport_buffer);
  // TODO: Encode timestamp.
  // udp_header->uh_sum = encode_timestamp(timestamp);
  udp_header->uh_sum = 0;

  // // Payload
  // // (A) "Tweak bytes"
  // // => Craft the first two bytes to ensure that our custom checksum is
  // // valid.
  // auto tweak_bytes = advance<uint16_t>(ptr);
  // uint32_t original_checksum =
  //     base_.pseudo_header_checksum(IPPROTO_UDP, payload_length);
  // uint32_t target_checksum_le = ~ntohs(timestamp) & 0xFFFF;
  // if (target_checksum_le < original_checksum) {
  //   target_checksum_le += 0xFFFF;
  // }
  // *tweak_bytes = htons(target_checksum_le - original_checksum);
  //
  // // (B) Padding
  // // => Pad with zeros since we encode the TTL in the payload length.
  // auto padding = advance<uint8_t>(ptr);
  // for (size_t i = 0; i < payload_length; i++) {
  //   padding[i] = 0;
  // }
}

}  // namespace packets_utils
