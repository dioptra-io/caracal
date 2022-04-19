#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <tins/tins.h>

#include <caracal/constants.hpp>
#include <caracal/parser.hpp>
#include <caracal/reply.hpp>
#include <caracal/timestamp.hpp>
#include <chrono>
#include <optional>

using Tins::PDU;
using Tins::RawPDU;
using Tins::Endian::be_to_host;
using Tins::Endian::host_to_be;

using std::nullopt;
using std::optional;
using std::chrono::duration_cast;
using std::chrono::microseconds;

namespace caracal::Parser {

using ip_hdr = ip;

void copy(const Tins::IPv4Address& src, in6_addr& dst) noexcept {
  dst.s6_addr32[0] = 0;
  dst.s6_addr32[1] = 0;
  dst.s6_addr32[2] = 0xFFFF0000U;
  dst.s6_addr32[3] = uint32_t(src);
}

void copy(const Tins::IPv6Address& src, in6_addr& dst) noexcept {
  src.copy(dst.s6_addr);
}

void parse_outer(Reply& reply, const Tins::IP* ip) noexcept {
  copy(ip->src_addr(), reply.reply_src_addr);
  copy(ip->dst_addr(), reply.reply_dst_addr);
  reply.reply_id = ip->id();
  reply.reply_size = ip->tot_len();
  reply.reply_ttl = ip->ttl();
}

void parse_outer(Reply& reply, const Tins::IPv6* ip) noexcept {
  copy(ip->src_addr(), reply.reply_src_addr);
  copy(ip->dst_addr(), reply.reply_dst_addr);
  reply.probe_id = 0;  // Not implemented for IPv6.
  reply.reply_size = ip->payload_length();
  reply.reply_ttl = static_cast<uint8_t>(ip->hop_limit());
}

void parse_outer(Reply& reply, const Tins::ICMP* icmp) noexcept {
  reply.reply_protocol = IPPROTO_ICMP;
  reply.reply_icmp_code = icmp->code();
  reply.reply_icmp_type = static_cast<uint8_t>(icmp->type());
  for (const auto& ext : icmp->extensions().extensions()) {
    parse_outer(reply, ext);
  }
}

void parse_outer(Reply& reply, const Tins::ICMPv6* icmp) noexcept {
  reply.reply_protocol = IPPROTO_ICMPV6;
  reply.reply_icmp_code = icmp->code();
  reply.reply_icmp_type = static_cast<uint8_t>(icmp->type());
  for (const auto& ext : icmp->extensions().extensions()) {
    parse_outer(reply, ext);
  }
}

void parse_outer(Reply& reply, const Tins::ICMPExtension& ext) noexcept {
  // MPLS Label Stack, see https://tools.ietf.org/html/rfc4950 (sec. 7)
  if (ext.extension_class() == 1 && ext.extension_type() == 1) {
    auto payload = ext.payload();
    for (size_t i = 0; i <= (payload.size() - 4); i += 4) {
      Tins::MPLS mpls(payload.data() + i, 4);
      reply.reply_mpls_labels.emplace_back(
          std::tuple{mpls.label(), mpls.experimental(), mpls.bottom_of_stack(),
                     mpls.ttl()});
    }
  }
}

void parse_inner(Reply& reply, const Tins::IP* ip) noexcept {
  copy(ip->dst_addr(), reply.probe_dst_addr);
  reply.probe_id = ip->id();
  reply.probe_size = ip->tot_len();
  reply.quoted_ttl = ip->ttl();
}

void parse_inner(Reply& reply, const Tins::IPv6* ip) noexcept {
  copy(ip->dst_addr(), reply.probe_dst_addr);
  reply.probe_id = 0;  // Not implemented for IPv6.
  reply.probe_size = ip->payload_length();
  reply.quoted_ttl = ip->hop_limit();
}

void parse_inner(Reply& reply, const Tins::ICMP* icmp,
                 const microseconds timestamp) noexcept {
  reply.probe_protocol = IPPROTO_ICMP;
  reply.probe_src_port = icmp->id();
  reply.probe_dst_port = 0;  // Not encoded in ICMP probes.
  reply.rtt = Timestamp::difference(
      duration_cast<Timestamp::tenth_ms>(timestamp).count(), icmp->sequence());
}

void parse_inner(Reply& reply, const Tins::ICMPv6* icmp,
                 const microseconds timestamp) noexcept {
  reply.probe_protocol = IPPROTO_ICMPV6;
  reply.probe_src_port = icmp->identifier();
  reply.probe_dst_port = 0;  // Not encoded in ICMP probes.
  reply.rtt = Timestamp::difference(
      duration_cast<Timestamp::tenth_ms>(timestamp).count(), icmp->sequence());
}

void parse_inner(Reply& reply, const Tins::UDP* udp,
                 const microseconds timestamp) noexcept {
  reply.probe_protocol = IPPROTO_UDP;
  reply.probe_src_port = udp->sport();
  reply.probe_dst_port = udp->dport();
  reply.probe_ttl = udp->length() - sizeof(udphdr) - PAYLOAD_TWEAK_BYTES;
  reply.rtt = Timestamp::difference(
      duration_cast<Timestamp::tenth_ms>(timestamp).count(), udp->checksum());
}

// Retrieve the TTL encoded in the ICMP payload length.
void parse_inner_ttl_icmp(Reply& reply, const Tins::IP* ip) noexcept {
  reply.probe_ttl =
      ip->tot_len() - sizeof(ip_hdr) - ICMP_HEADER_SIZE - PAYLOAD_TWEAK_BYTES;
}

void parse_inner_ttl_icmp(Reply& reply, const Tins::IPv6* ip) noexcept {
  reply.probe_ttl =
      ip->payload_length() - ICMPV6_HEADER_SIZE - PAYLOAD_TWEAK_BYTES;
}

optional<Reply> parse(const Tins::Packet& packet) noexcept {
  const PDU* pdu = packet.pdu();
  if (!pdu) {
    return nullopt;
  }

  const auto capture_timestamp = microseconds(packet.timestamp());
  Reply reply{.capture_timestamp = capture_timestamp.count()};

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
      const auto inner_udp = inner_ip->find_pdu<Tins::UDP>();
      if (inner_icmp) {
        // IPv4 → ICMPv4 → IPv4 → ICMPv4
        parse_inner(reply, inner_icmp, capture_timestamp);
        parse_inner_ttl_icmp(reply, &inner_ip.value());
      } else if (inner_udp) {
        // IPv4 → ICMPv4 → IPv4 → UDP
        parse_inner(reply, inner_udp, capture_timestamp);
      }
    } else {
      // Discard the packet if it doesn't contain an inner IP packet.
      return nullopt;
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
      const auto inner_icmp = inner_ip->find_pdu<Tins::ICMPv6>();
      const auto inner_udp = inner_ip->find_pdu<Tins::UDP>();
      if (inner_icmp) {
        // IPv6 → ICMPv6 → IPv6 → ICMPv6
        parse_inner(reply, inner_icmp, capture_timestamp);
        parse_inner_ttl_icmp(reply, &inner_ip.value());
      } else if (inner_udp) {
        // IPv6 → ICMPv6 → IPv6 → UDP
        parse_inner(reply, inner_udp, capture_timestamp);
      }
    }
    // We're done for this kind of ICMP replies.
    return reply;
  }

  // ICMPv4 Echo Reply
  if (icmp4 && (icmp4->type() == Tins::ICMP::ECHO_REPLY)) {
    // IPv4 → ICMPv4
    parse_outer(reply, icmp4);
    parse_inner(reply, icmp4, capture_timestamp);
    parse_inner_ttl_icmp(reply, ip4);
    // Since there is no quoted ICMP header in an echo reply, we cannot retrieve
    // the *true* probe destination address. In previous versions of caracal,
    // we used to leave the `probe_dst_addr` field empty to indicate this.
    // However, this complicates downstream code, and in the vast majority of
    // the cases, the reply comes from the probe destination.
    // Users can still filter-out echo replies if they fear to infer false
    // links.
    reply.probe_dst_addr = reply.reply_src_addr;
    return reply;
  }

  // ICMPv6 Echo Reply
  if (icmp6 && (icmp6->type() == Tins::ICMPv6::ECHO_REPLY)) {
    parse_outer(reply, icmp6);
    parse_inner(reply, icmp6, capture_timestamp);
    parse_inner_ttl_icmp(reply, ip6);
    // Same remark as for ICMP(v4) echo replies.
    reply.probe_dst_addr = reply.reply_src_addr;
    return reply;
  }

  // TODO: UDP replies.
  return nullopt;
}

}  // namespace caracal::Parser
