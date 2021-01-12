#pragma once

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <tins/tins.h>

#include <chrono>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

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

using std::nullopt;
using std::optional;
using std::vector;
using std::chrono::duration_cast;
using std::chrono::microseconds;

namespace dminer {

/// A traceroute reply (all values are in host order, including the IP
/// addresses).
struct TracerouteReply {
  /// @name Reply attributes (IP)
  /// @{
  uint32_t src_ip;  ///< The source IP of the reply packet.
  uint32_t dst_ip;  ///< The destination IP of the reply packet.
  uint16_t size;    ///< The size in bytes of the reply packet.
  uint8_t ttl;      ///< The TTL of the reply packet.
  /// @}

  /// @name Reply attributes (IP → ICMP)
  /// @{
  uint8_t icmp_code;  ///< ICMP code (0 if not an ICMP reply)
  uint8_t icmp_type;  ///< ICMP type (0 if not an ICMP reply)
  /// @}

  /// @name Probe attributes (IP → ICMP → IP)
  /// @{
  uint32_t inner_dst_ip;  ///< The IP that was targeted by the probe,
                          ///< if we received a reply from this IP,
                          ///< then \ref src_ip == \ref inner_dst_ip.
  uint16_t inner_size;    ///< The size in bytes of the probe packet.
  uint8_t inner_ttl;      ///< The TTL of the probe packet.
  uint8_t inner_proto;    ///< The protocol of the probe packet.
  /// @}

  /// @name Probe attributes (IP → ICMP → IP → ICMP/TCP/UDP)
  /// @{
  uint16_t inner_src_port;  ///< The source port of the probe packet.
                            ///< For ICMP probes, we encode the source port
                            ///< in the ICMP checksum and ID fields
                            ///< in order to vary the flow ID.
  uint16_t inner_dst_port;  ///< The destination port of the probe packet,
                            ///< 0 for ICMP probes.
  uint8_t
      inner_ttl_from_udp_len;  ///< The TTL that was encoded in the UDP
                               ///< probe packet length, 0 if not an UDP probe.
  /// @}

  /// @name Estimated attributes
  /// @{
  double rtt;  ///< The estimated round-trip time, in milliseconds.
  /// @}

  /// The /24 destination prefix, computed from \ref inner_dst_ip.
  uint32_t prefix() const { return (inner_dst_ip >> 8) << 8; }

  /// Serialize the reply in the CSV format.
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

/// Parse an ICMPv4 ECHO_REPLY.
inline optional<TracerouteReply> parse_icmp4_echo(const uint64_t timestamp,
                                                  const IP* ip,
                                                  const ICMP* icmp,
                                                  const bool estimate_rtt) {
  // TODO: Implement.
  return nullopt;
  //  // Reply attributes
  // const uint32_t src_ip = be_to_host(uint32_t(ip->src_addr()));
  // const uint32_t dst_ip = be_to_host(uint32_t(ip->dst_addr()));
  // const uint16_t size = ip->tot_len();
  // const uint8_t ttl = ip->ttl();
  //
  // // Probe attributes
  // const uint32_t inner_dst_ip = src_ip;
  // const uint16_t inner_size = ip.tot_len();
  // const uint8_t inner_ttl = inner_ip.id();  // NOTE: `id` here, not `ttl`.
  //
  // // UDP probe
  // const UDP* inner_udp = inner_ip.find_pdu<UDP>();
  // if (inner_udp) {
  //   const uint16_t inner_src_port = inner_udp->sport();
  //   const uint16_t inner_dst_port = inner_udp->dport();
  //
  //   double rtt = 0.0;
  //   if (estimate_rtt) {
  //     const uint16_t inner_checksum = host_to_be(inner_udp->checksum());
  //     rtt = decode_difference(timestamp, inner_checksum) / 10.0;
  //   }
  //
  //   // Why -10?
  //   const uint8_t inner_ttl_from_udp_len = inner_udp->length() - 10;
  //
  //   return TracerouteReply{src_ip,
  //                          dst_ip,
  //                          size,
  //                          ttl,
  //                          icmp->code(),
  //                          static_cast<uint8_t>(icmp->type()),
  //                          inner_dst_ip,
  //                          inner_size,
  //                          inner_ttl,
  //                          IPPROTO_UDP,
  //                          inner_src_port,
  //                          inner_dst_port,
  //                          inner_ttl_from_udp_len,
  //                          rtt};
  //  }
}

/// Parse an ICMPv4 DEST_UNREACHABLE or TIME_EXCEEDED reply.
inline optional<TracerouteReply> parse_icmp4(const uint64_t timestamp,
                                             const IP* ip, const ICMP* icmp,
                                             const bool estimate_rtt) {
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
    const int padding = sizeof(ip) + sizeof(tcphdr) - inner_payload.size();
    for (int i = 0; i < padding; i++) {
      inner_payload.push_back(0);
    }

    // Create a fake TCP header for Tins.
    if (padding > 0) {
      tcphdr* fake =
          reinterpret_cast<tcphdr*>(inner_payload.data() + sizeof(ip));
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
      const uint16_t inner_checksum = host_to_be(inner_udp->checksum());
      rtt = decode_difference(timestamp, inner_checksum) / 10.0;
    }

    // Why -10?
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

  // ICMP probe
  const ICMP* inner_icmp = inner_ip.find_pdu<ICMP>();
  if (inner_icmp) {
    const uint16_t inner_src_port = inner_icmp->id();
    const uint16_t inner_dst_port = 0;  // Not encoded in ICMP probes.

    double rtt = 0.0;
    if (estimate_rtt) {
      const uint16_t inner_seq = host_to_be(inner_icmp->sequence());
      rtt = decode_difference(timestamp, inner_seq) / 10.0;
    }

    return TracerouteReply{src_ip,
                           dst_ip,
                           size,
                           ttl,
                           icmp->code(),
                           static_cast<uint8_t>(icmp->type()),
                           inner_dst_ip,
                           inner_size,
                           inner_ttl,
                           IPPROTO_ICMP,
                           inner_src_port,
                           inner_dst_port,
                           0,
                           rtt};
  }

  return nullopt;
}

/// Parse a TCP reply.
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

/// Parse a reply packet.
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
    if (icmp->type() == ICMP::DEST_UNREACHABLE ||
        icmp->type() == ICMP::TIME_EXCEEDED) {
      return parse_icmp4(timestamp, ip, icmp, estimate_rtt);
    }
    if (icmp->type() == ICMP::ECHO_REPLY) {
      return parse_icmp4_echo(timestamp, ip, icmp, estimate_rtt);
    }
    return nullopt;
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

}  // namespace dminer
