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

#include "constants.hpp"
#include "reply.hpp"
#include "timestamp.hpp"

using Tins::PDU;
using Tins::RawPDU;
using Tins::Endian::be_to_host;
using Tins::Endian::host_to_be;

using std::nullopt;
using std::optional;
using std::chrono::duration_cast;
using std::chrono::microseconds;

/// Parse traceroute replies.
namespace dminer::Parser {

/// Alias to avoid the `ip` struct to be hidden by the `ip` variable.
using ip_hdr = ip;

// TODO: Document these functions.
inline void parse_outer(Reply& reply, const Tins::IP* ip) noexcept {
  reply.src_ip = be_to_host(uint32_t(ip->src_addr()));
  reply.dst_ip = be_to_host(uint32_t(ip->dst_addr()));
  reply.size = ip->tot_len();
  reply.ttl = ip->ttl();
}

inline void parse_outer(Reply& reply, const Tins::IPv6* ip) noexcept {
  // TODO
  reply.ttl = static_cast<uint8_t>(ip->hop_limit());
}

inline void parse_outer(Reply& reply, const Tins::ICMP* icmp) noexcept {
  reply.icmp_code = icmp->code();
  reply.icmp_type = static_cast<uint8_t>(icmp->type());
}

inline void parse_outer(Reply& reply, const Tins::ICMPv6* icmp) noexcept {
  reply.icmp_code = icmp->code();
  reply.icmp_type = static_cast<uint8_t>(icmp->type());
}

inline void parse_inner(Reply& reply, const Tins::IP* ip) noexcept {
  reply.inner_dst_ip = be_to_host(uint32_t(ip->dst_addr()));
  reply.inner_size = ip->tot_len();
  reply.inner_ttl = static_cast<uint8_t>(ip->id());
}

inline void parse_inner(Reply& reply, const Tins::IPv6* ip) noexcept {
  reply.src_ip = 0;  // TODO
  reply.dst_ip = 0;  // TODO
  reply.size = static_cast<uint16_t>(ip->size());

  // Can't store the TTL in the id field (see Builder::IP::init),
  // so we compute it from the payload length.
  const uint8_t protocol = ip->next_header();
  // TODO: ICMPv6
  if (protocol == IPPROTO_ICMP) {
    reply.inner_ttl =
        ip->payload_length() - ICMP_HEADER_SIZE - PAYLOAD_TWEAK_BYTES;
  } else if (protocol == IPPROTO_TCP) {
    reply.inner_ttl =
        ip->payload_length() - sizeof(tcphdr) - PAYLOAD_TWEAK_BYTES;
  } else if (protocol == IPPROTO_UDP) {
    reply.inner_ttl =
        ip->payload_length() - sizeof(udphdr) - PAYLOAD_TWEAK_BYTES;
  } else {
    reply.inner_ttl = 0;
  }
}

inline void parse_inner(Reply& reply, const Tins::ICMP* icmp,
                        const uint64_t timestamp) noexcept {
  reply.inner_proto = IPPROTO_ICMP;
  reply.inner_src_port = icmp->id();
  reply.inner_dst_port = 0;  // Not encoded in ICMP probes.
  reply.rtt = decode_difference(timestamp, icmp->sequence()) / 10.0;
}

inline void parse_inner(Reply& /* reply */, const Tins::ICMPv6* /* icmp */,
                        const uint64_t /* timestamp */) noexcept {
  // TODO
  // reply.inner_proto = IPPROTO_ICMPV6;
  // reply.inner_src_port = icmp->id();
  // reply.inner_dst_port = 0;            // Not encoded in ICMP probes.
  // reply.inner_ttl_from_transport = 0;  // Not encoded in ICMP probes.
  // reply.rtt = decode_difference(timestamp, icmp->sequence()) / 10.0;
}

inline void parse_inner(Reply& reply, const Tins::TCP* tcp,
                        const uint64_t timestamp) noexcept {
  const auto seq1 = static_cast<uint16_t>(tcp->seq() >> 16);
  const auto seq2 = static_cast<uint16_t>(tcp->seq());
  reply.inner_proto = IPPROTO_TCP;
  reply.inner_src_port = tcp->sport();
  reply.inner_dst_port = tcp->dport();
  reply.inner_ttl_from_transport = static_cast<uint8_t>(seq2);
  reply.rtt = decode_difference(timestamp, seq1) / 10.0;
}

inline void parse_inner(Reply& reply, const Tins::UDP* udp,
                        const uint64_t timestamp) noexcept {
  reply.inner_proto = IPPROTO_UDP;
  reply.inner_src_port = udp->sport();
  reply.inner_dst_port = udp->dport();
  reply.inner_ttl_from_transport =
      udp->length() - sizeof(udphdr) - PAYLOAD_TWEAK_BYTES;
  reply.rtt = decode_difference(timestamp, udp->checksum()) / 10.0;
}

// Retrieve the TTL encoded in the ICMP payload length.
inline void parse_inner_ttl_icmp(Reply& reply, const Tins::IP* ip) noexcept {
  reply.inner_ttl_from_transport =
      ip->tot_len() - sizeof(ip_hdr) - ICMP_HEADER_SIZE - PAYLOAD_TWEAK_BYTES;
}

// TODO: Explain why this is needed.
template <typename T>
[[nodiscard]] optional<T> build_inner(const RawPDU* pdu) noexcept {
  if (!pdu) {
    return nullopt;
  }
  const auto& inner_payload = pdu->payload();
  const auto inner_data = inner_payload.data();
  const auto inner_size = static_cast<uint32_t>(inner_payload.size());
  return T(inner_data, inner_size);
}

/// Parse a reply packet.
/// @param packet the packet to parse.
/// @param estimate_rtt whether to estimate the RTT or not.
/// @return the parsed reply.
[[nodiscard]] inline optional<Reply> parse(
    const Tins::Packet& packet) noexcept {
  const PDU* pdu = packet.pdu();
  if (!pdu) {
    return nullopt;
  }

  Reply reply{};
  const uint64_t timestamp =
      duration_cast<tenth_ms>(microseconds(packet.timestamp())).count();

  const auto ip4 = pdu->find_pdu<Tins::IP>();
  const auto ip6 = pdu->find_pdu<Tins::IPv6>();
  const auto icmp4 = pdu->find_pdu<Tins::ICMP>();
  const auto icmp6 = pdu->find_pdu<Tins::ICMPv6>();

  if (ip4) {
    // IPv4
    parse_outer(reply, ip4);
  } else if (ip6) {
    // IPv6
    parse_outer(reply, ip6);
  } else {
    // Packet is neither IPv4 or IPv6, discard it.
    return nullopt;
  }

  // ICMPv4 Destination Unreachable or Time Exceeded.
  if (icmp4 && (icmp4->type() == Tins::ICMP::DEST_UNREACHABLE ||
                icmp4->type() == Tins::ICMP::TIME_EXCEEDED)) {
    // IPv4 → ICMPv4
    parse_outer(reply, icmp4);
    const auto inner_ip = build_inner<Tins::IP>(icmp4->find_pdu<RawPDU>());
    if (inner_ip) {
      // IPv4 → ICMPv4 → IPv4
      parse_inner(reply, &inner_ip.value());
      const auto inner_icmp = inner_ip->find_pdu<Tins::ICMP>();
      const auto inner_tcp = inner_ip->find_pdu<Tins::TCP>();
      const auto inner_udp = inner_ip->find_pdu<Tins::UDP>();
      if (inner_icmp) {
        // IPv4 → ICMPv4 → IPv4 → ICMPv4
        parse_inner(reply, inner_icmp, timestamp);
        parse_inner_ttl_icmp(reply, &inner_ip.value());
      } else if (inner_tcp) {
        // IPv4 → ICMPv4 → IPv4 → TCP
        parse_inner(reply, inner_tcp, timestamp);
      } else if (inner_udp) {
        // IPv4 → ICMPv4 → IPv4 → UDP
        parse_inner(reply, inner_udp, timestamp);
      }
    }
    // We're done for this kind of ICMP replies.
    return reply;
  }

  // ICMPv6 Destination Unreachable or Time Exceeded.
  if (icmp6 && (icmp6->type() == Tins::ICMPv6::DEST_UNREACHABLE ||
                icmp6->type() == Tins::ICMPv6::TIME_EXCEEDED)) {
    // IPv6 → ICMPv6
    parse_outer(reply, icmp6);
    const auto inner_ip = build_inner<Tins::IPv6>(icmp6->find_pdu<RawPDU>());
    if (inner_ip) {
      // IPv6 → ICMPv6 → IPv6
      parse_inner(reply, &inner_ip.value());
      const auto inner_icmp = inner_ip->find_pdu<Tins::ICMP>();
      const auto inner_tcp = inner_ip->find_pdu<Tins::TCP>();
      const auto inner_udp = inner_ip->find_pdu<Tins::UDP>();
      if (inner_icmp) {
        // IPv6 → ICMPv6 → IPv6 → ICMPv6
        parse_inner(reply, inner_icmp, timestamp);
      } else if (inner_tcp) {
        // IPv6 → ICMPv6 → IPv6 → TCP
        parse_inner(reply, inner_tcp, timestamp);
      } else if (inner_udp) {
        // IPv6 → ICMPv6 → IPv6 → UDP
        parse_inner(reply, inner_udp, timestamp);
      }
    }
    // We're done for this kind of ICMP replies.
    return reply;
  }

  // ICMPv4 Echo Reply
  if (icmp4 && (icmp4->type() == Tins::ICMP::ECHO_REPLY)) {
    // IPv4 → ICMPv4
    parse_outer(reply, icmp4);
    parse_inner(reply, icmp4, timestamp);
    parse_inner_ttl_icmp(reply, ip4);
    return reply;
  }

  // ICMPv6 Echo Reply
  if (icmp6 && (icmp6->type() == Tins::ICMPv6::ECHO_REPLY)) {
    // Discard ICMPv6 echo replies for now.
    return nullopt;
  }

  // TODO: TCP (resets?) and UDP replies.
  return nullopt;
}

}  // namespace dminer::Parser
