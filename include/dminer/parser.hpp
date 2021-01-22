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

#include "reply.hpp"
#include "timestamp.hpp"

using Tins::Packet;
using Tins::PDU;
using Tins::RawPDU;
using Tins::Endian::be_to_host;
using Tins::Endian::host_to_be;

using std::nullopt;
using std::optional;
using std::chrono::duration_cast;
using std::chrono::microseconds;

/// Parse ICMP replies.
namespace dminer::Parser::ICMP {

/// Parse an ICMPv4 DEST_UNREACHABLE or TIME_EXCEEDED reply.
[[nodiscard]] inline optional<Reply> parse(const uint64_t timestamp,
                                           const Tins::IP* ip,
                                           const Tins::ICMP* icmp) {
  const auto inner_raw = icmp->find_pdu<RawPDU>();
  if (!inner_raw) {
    return nullopt;
  }

  // TODO: Avoid this.
  // icmp->find_pdu<IP> doesn't seems to work directly...
  const auto inner_payload = inner_raw->payload();
  const auto inner_ip = Tins::IP(inner_payload.data(),
                                 static_cast<uint32_t>(inner_payload.size()));

  // Reply attributes
  const uint32_t src_ip = be_to_host(uint32_t(ip->src_addr()));
  const uint32_t dst_ip = be_to_host(uint32_t(ip->dst_addr()));
  const uint16_t size = ip->tot_len();
  const uint8_t ttl = ip->ttl();

  // Probe attributes
  const uint32_t inner_dst_ip = be_to_host(uint32_t(inner_ip.dst_addr()));
  const uint16_t inner_size =
      inner_ip.tot_len();  // NOTE: This field is useless. Why?
  const auto inner_ttl = static_cast<uint8_t>(inner_ip.id());

  // ICMP probe
  const auto inner_icmp = inner_ip.find_pdu<Tins::ICMP>();
  if (inner_icmp) {
    const uint16_t inner_src_port = inner_icmp->id();
    const uint16_t inner_dst_port = 0;           // Not encoded in ICMP probes.
    const uint8_t inner_ttl_from_transport = 0;  // Not encoded in ICMP probes.
    const double rtt =
        decode_difference(timestamp, inner_icmp->sequence()) / 10.0;

    return Reply{src_ip,
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
                 inner_ttl_from_transport,
                 rtt};
  }

  // TCP probe
  const auto inner_tcp = inner_ip.find_pdu<Tins::TCP>();
  if (inner_tcp) {
    const uint16_t inner_src_port = inner_tcp->sport();
    const uint16_t inner_dst_port = inner_tcp->dport();

    const auto seq1 = static_cast<uint16_t>(inner_tcp->seq() >> 16);
    const auto seq2 = static_cast<uint16_t>(inner_tcp->seq());

    const double rtt = decode_difference(timestamp, seq1) / 10.0;
    const auto inner_ttl_from_transport = static_cast<uint8_t>(seq2);

    return Reply{src_ip,
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
                 inner_ttl_from_transport,
                 rtt};
  }

  // UDP probe
  const auto inner_udp = inner_ip.find_pdu<Tins::UDP>();
  if (inner_udp) {
    const uint16_t inner_src_port = inner_udp->sport();
    const uint16_t inner_dst_port = inner_udp->dport();
    const double rtt =
        decode_difference(timestamp, inner_udp->checksum()) / 10.0;

    const uint8_t inner_ttl_from_transport =
        inner_udp->length() - sizeof(udphdr) - 2;

    return Reply{src_ip,
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
                 inner_ttl_from_transport,
                 rtt};
  }

  return nullopt;
}

}  // namespace dminer::Parser::ICMP

/// Parse TCP replies.
namespace dminer::Parser::TCP {

// /// Parse a TCP reply.
// [[nodiscard]] inline optional<Reply> parse(const uint64_t timestamp,
//                                           const Tins::IP* ip,
//                                           const Tins::TCP* tcp) {
//  // const uint32_t src_ip = be_to_host(uint32_t(ip->src_addr()));
//  // const uint32_t dst_ip = be_to_host(uint32_t(ip->dst_addr()));
//  // const uint16_t size = ip->tot_len();
//  // const uint8_t ttl = ip->ttl();
//
//  // TODO: Probe TTL
//  // TODO: Parse TCP resets.
//
//  // const uint16_t inner_src_port = tcp->sport();
//  // const uint16_t inner_dst_port = tcp->dport();
//
//  return nullopt;
// }

}  // namespace dminer::Parser::TCP

/// Parse traceroute replies.
namespace dminer::Parser {

/// Parse a reply packet.
/// @param packet the packet to parse.
/// @param estimate_rtt whether to estimate the RTT or not.
/// @return the parsed reply.
[[nodiscard]] inline optional<Reply> parse(const Packet& packet) {
  const uint64_t timestamp =
      duration_cast<tenth_ms>(microseconds(packet.timestamp())).count();

  const PDU* pdu = packet.pdu();
  if (!pdu) {
    return nullopt;
  }

  // TODO: IPv6
  const auto ip = pdu->find_pdu<Tins::IP>();
  if (!ip) {
    return nullopt;
  }

  // ICMP reply.
  const auto icmp = ip->find_pdu<Tins::ICMP>();
  if (icmp) {
    if (icmp->type() == Tins::ICMP::DEST_UNREACHABLE ||
        icmp->type() == Tins::ICMP::TIME_EXCEEDED) {
      return ICMP::parse(timestamp, ip, icmp);
    }
    if (icmp->type() == Tins::ICMP::ECHO_REPLY) {
      // Reply from the destination.
      // TODO or ignore?
      return nullopt;
    }
    return nullopt;
  }

  // TODO: TCP reply.
  const auto tcp = ip->find_pdu<Tins::TCP>();
  if (tcp) {
    return nullopt;
  }

  return nullopt;
}

}  // namespace dminer::Parser
