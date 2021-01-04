#pragma once

#include <tins/tins.h>

#include <chrono>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "network_utils_t.hpp"
#include "timestamp.hpp"

using Tins::ICMP;
using Tins::IP;
using Tins::Packet;
using Tins::PDU;
using Tins::RawPDU;
using Tins::TCP;
using Tins::UDP;
using Tins::Endian::be_to_host;
using Tins::Endian::host_to_be;
using utils::compact_ip_hdr;
using utils::tcphdr;

using std::nullopt;
using std::optional;
using std::vector;
using std::chrono::duration_cast;
using std::chrono::microseconds;

struct TracerouteReply {
  // Reply attributes (IP)
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t size;
  uint8_t ttl;
  // Reply attributes (IP->ICMP)
  // 0 if not an ICMP reply.
  uint8_t icmp_code;
  uint8_t icmp_type;
  // Probe attributes (IP->ICMP->IP)
  // The IP that was targeted by the probe.
  // If we receive a reply from this IP, then src_ip == inner_dst_ip.
  uint32_t inner_dst_ip;
  uint16_t inner_size;
  uint8_t inner_ttl;
  uint8_t inner_proto;
  // Probe attributes (IP->ICMP->IP->UDP/TCP)
  uint16_t inner_src_port;
  uint16_t inner_dst_port;
  // 0 if not an UDP reply.
  uint8_t inner_ttl_from_udp_len;
  // Estimated attributes
  double rtt;

  // The /24 destination prefix.
  uint32_t prefix() const { return (inner_dst_ip >> 8) << 8; }

  std::string to_csv() const {
    std::ostringstream oss;
    oss.precision(1);
    oss << std::fixed << dst_ip << "," << prefix() << "," << inner_dst_ip << ","
        << src_ip << "," << uint(inner_proto) << "," << inner_src_port << ","
        << inner_dst_port << "," << uint(inner_ttl) << ","
        << uint(inner_ttl_from_udp_len) << "," << uint(icmp_type) << ","
        << uint(icmp_code) << "," << rtt << "," << uint(ttl) << "," << size;
    return oss.str();
  }
};

inline optional<TracerouteReply> parse_icmp4(const uint64_t timestamp,
                                             const IP* ip, const ICMP* icmp,
                                             const bool estimate_rtt) {
  if (icmp->type() != ICMP::DEST_UNREACHABLE &&
      icmp->type() != ICMP::TIME_EXCEEDED) {
    return nullopt;
  }

  const RawPDU* inner_raw = icmp->find_pdu<RawPDU>();
  if (!inner_raw) {
    return nullopt;
  }

  // Extract the protocol of the inner IP packet.
  // Tins is not capable of building an incomplete TCP header,
  // so if the protocol is TCP and the inner packet is incomplete,
  // we pad it with zeros.
  vector<uint8_t> inner_payload = inner_raw->payload();
  const uint8_t inner_proto = inner_payload[9];
  if (inner_proto == IPPROTO_TCP) {
    const int padding =
        sizeof(compact_ip_hdr) + sizeof(tcphdr) - inner_payload.size();
    for (int i = 0; i < padding; i++) {
      inner_payload.push_back(0);
    }

    // Create a fake TCP header for Tins.
    if (padding > 0) {
      tcphdr* fake = reinterpret_cast<tcphdr*>(inner_payload.data() +
                                               sizeof(compact_ip_hdr));
      fake->th_ack = 1;
      fake->th_flags |= TH_ACK;
      fake->th_off = 5;
      fake->th_urp = 0;
      fake->th_win = htons(32767);
    }
  }

  const IP inner_ip =
      IP(inner_payload.data(), static_cast<uint32_t>(inner_payload.size()));

  // Reply attributes
  const uint32_t src_ip = be_to_host(uint32_t(ip->src_addr()));
  const uint32_t dst_ip = be_to_host(uint32_t(ip->dst_addr()));
  const uint16_t size = ip->tot_len();
  const uint8_t ttl = ip->ttl();

  // Probe attributes
  const uint32_t inner_dst_ip = be_to_host(uint32_t(inner_ip.dst_addr()));
  const uint16_t inner_size =
      inner_ip.tot_len();                   // NOTE: This field is useless.
  const uint8_t inner_ttl = inner_ip.id();  // NOTE: `id` here, not `ttl`.

  // UDP probe
  const UDP* inner_udp = inner_ip.find_pdu<UDP>();
  if (inner_udp) {
    const uint16_t inner_src_port = inner_udp->sport();
    const uint16_t inner_dst_port = inner_udp->dport();

    double rtt = 0.0;
    if (estimate_rtt) {
      // Recover the timestamp and compute the RTT.
      // TODO: Why is host_to_be(...) required here?
      const uint16_t inner_checksum = host_to_be(inner_udp->checksum());
      rtt = decode_difference(timestamp, inner_checksum) / 10.0;
    }

    // (?)
    const uint8_t inner_ttl_from_udp_len = inner_udp->length() - 10;

    return TracerouteReply{src_ip,
                           dst_ip,
                           size,
                           ttl,
                           icmp->code(),
                           static_cast<uint8_t>(icmp->type()),
                           inner_dst_ip,
                           inner_size,
                           inner_ttl,
                           IPPROTO_UDP,
                           inner_src_port,
                           inner_dst_port,
                           inner_ttl_from_udp_len,
                           rtt};
  }

  // TCP probe
  const TCP* inner_tcp = inner_ip.find_pdu<TCP>();
  if (inner_tcp) {
    const uint16_t inner_src_port = inner_tcp->sport();
    const uint16_t inner_dst_port = inner_tcp->dport();

    // TODO: Recover the timestamp and compute the RTT>
    // const uint64_t timestamp =
    //     to_timestamp<tenth_ms>(microseconds(packet.timestamp()));
    // Extract the last 27 bits.
    // const uint16_t inner_seq = inner_tcp->seq() & ((1 << 27) - 1);
    // const double rtt = decode_difference(timestamp, inner_seq) / 10.0;

    return TracerouteReply{src_ip,
                           dst_ip,
                           size,
                           ttl,
                           icmp->code(),
                           static_cast<uint8_t>(icmp->type()),
                           inner_dst_ip,
                           inner_size,
                           inner_ttl,
                           IPPROTO_TCP,
                           inner_src_port,
                           inner_dst_port,
                           0,
                           -1};
  }

  return nullopt;
}

inline optional<TracerouteReply> parse_tcp(const uint64_t timestamp,
                                           const IP* ip, const TCP* tcp,
                                           const bool estimate_rtt) {
  // const uint32_t src_ip = be_to_host(uint32_t(ip->src_addr()));
  // const uint32_t dst_ip = be_to_host(uint32_t(ip->dst_addr()));
  // const uint16_t size = ip->tot_len();
  // const uint8_t ttl = ip->ttl();

  // TODO: RTT
  // TODO: Probe TTL

  // const uint16_t inner_src_port = tcp->sport();
  // const uint16_t inner_dst_port = tcp->dport();

  return nullopt;
}

inline optional<TracerouteReply> parse(const Packet& packet,
                                       const bool estimate_rtt) {
  const uint64_t timestamp =
      duration_cast<tenth_ms>(microseconds(packet.timestamp())).count();

  const PDU* pdu = packet.pdu();
  if (!pdu) {
    return nullopt;
  }

  // TODO: IPv6
  const IP* ip = pdu->find_pdu<IP>();
  if (!ip) {
    return nullopt;
  }

  // ICMP reply.
  const ICMP* icmp = ip->find_pdu<ICMP>();
  if (icmp) {
    return parse_icmp4(timestamp, ip, icmp, estimate_rtt);
  }

  // TCP reply.
  const TCP* tcp = ip->find_pdu<TCP>();
  if (tcp) {
    return parse_tcp(timestamp, ip, tcp, estimate_rtt);
  }

  return nullopt;
}

inline optional<TracerouteReply> parse(const Packet& packet) {
  return parse(packet, true);
}
