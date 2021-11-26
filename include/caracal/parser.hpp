#pragma once

#include <optional>

#include "reply.hpp"

/// Parse traceroute replies.
namespace caracal::Parser {

// TODO: Document these functions.
void parse_outer(Reply& reply, const Tins::IP* ip) noexcept;

void parse_outer(Reply& reply, const Tins::IPv6* ip) noexcept;

void parse_outer(Reply& reply, const Tins::IP::option& opt) noexcept;

void parse_outer(Reply& reply, const Tins::ICMP* icmp) noexcept;

void parse_outer(Reply& reply, const Tins::ICMPv6* icmp) noexcept;

void parse_outer(Reply& reply, const Tins::ICMPExtension& ext) noexcept;

void parse_inner(Reply& reply, const Tins::IP* ip) noexcept;

void parse_inner(Reply& reply, const Tins::IPv6* ip) noexcept;

void parse_inner(Reply& reply, const Tins::ICMP* icmp,
                 uint64_t timestamp) noexcept;

void parse_inner(Reply& /* reply */, const Tins::ICMPv6* /* icmp */,
                 uint64_t /* timestamp */) noexcept;

void parse_inner(Reply& reply, const Tins::UDP* udp,
                 uint64_t timestamp) noexcept;

// Retrieve the TTL encoded in the ICMP payload length.
void parse_inner_ttl_icmp(Reply& reply, const Tins::IP* ip,
                          const Tins::ICMP* icmp) noexcept;

void parse_inner_ttl_icmp(Reply& reply, const Tins::IPv6* ip) noexcept;

// TODO: Explain why this is needed.
template <typename T>
[[nodiscard]] std::optional<T> build_inner(const Tins::RawPDU* pdu) noexcept {
  if (!pdu) {
    return std::nullopt;
  }
  const auto& inner_payload = pdu->payload();
  const auto inner_data = inner_payload.data();
  const auto inner_size = static_cast<uint32_t>(inner_payload.size());
  try {
    return T(inner_data, inner_size);
  } catch (const Tins::malformed_packet&) {
    return std::nullopt;
  }
}

/// Parse a reply packet.
/// @param packet the packet to parse.
/// @param estimate_rtt whether to estimate the RTT or not.
/// @return the parsed reply.
[[nodiscard]] std::optional<Reply> parse(const Tins::Packet& packet) noexcept;

}  // namespace caracal::Parser
