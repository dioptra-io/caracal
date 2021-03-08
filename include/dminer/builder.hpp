#pragma once

#include <net/ethernet.h>

#include <array>

#include "packet.hpp"

/// Build probe packets.
namespace dminer::Builder {

/// Compute the transport-level checksum.
/// @param packet the packet buffer, including the IP header.
/// @return the transport-level checksum in network order.
[[nodiscard]] uint16_t transport_checksum(Packet packet);

/// Return the two bytes of the payload to ensure that the target checksum is
/// valid.
/// @param original_checksum the transport-level checksum of the packet.
/// @param target_checksum the target transport-level checksum.
/// @return the two bytes of the payload.
[[nodiscard]] uint16_t tweak_payload(uint16_t original_checksum,
                                     uint16_t target_checksum);

}  // namespace dminer::Builder

/// Build the BSD/macOS Loopback header.
/// On Linux the loopback interface uses the Ethernet header,
/// but on macOS it uses a different 32-bit header.
namespace dminer::Builder::Loopback {

void init(Packet packet, bool is_v4);

}  // namespace dminer::Builder::Loopback

/// Build the Ethernet header.
namespace dminer::Builder::Ethernet {

void init(Packet packet, bool is_v4,
          const std::array<uint8_t, ETHER_ADDR_LEN> &src_addr,
          const std::array<uint8_t, ETHER_ADDR_LEN> &dst_addr);

}  // namespace dminer::Builder::Ethernet

/// Build IP probes.
/// In the IP header, the type of service, protocol, source and destination
/// address fields are used for per-flow load-balancing.
/// We also encode the TTL in the ID field in order to retrieve it in the ICMP
/// destination unreachable/TTL exceeded messages since the TTL field is
/// decreased/modified at each hop.
namespace dminer::Builder::IP {

/// Init the IPv4 header.
/// @param packet the packet buffer, including the IP header.
/// @param protocol the L4 protocol number.
/// @param src_addr the source IPv4 address.
/// @param dst_addr the destination IPv4 address.
/// @param ttl the TTL.
void init(Packet packet, uint8_t protocol, in_addr src_addr, in_addr dst_addr,
          uint8_t ttl);

/// Init the IPv6 header.
/// @param packet the packet buffer, including the IP header.
/// @param protocol the L4 protocol number.
/// @param src_addr the source IPv6 address.
/// @param dst_addr the destination IPv6 address.
/// @param ttl the TTL.
void init(Packet packet, uint8_t protocol, in6_addr src_addr, in6_addr dst_addr,
          uint8_t ttl);

}  // namespace dminer::Builder::IP

/// Build ICMP echo probes.
/// In the ICMP echo header, the code and checksum fields are used for per-flow
/// load-balancing. We encode the flow ID in the checksum field to vary the flow
/// ID, and in the id field. We encode the timestamp in the sequence field.
/// Since echo replies, in contrast to destination unreachable messages, doesn't
/// contain the original probe packet (including the original TTL and flow ID),
/// we ignore them in the packet parser.
namespace dminer::Builder::ICMP {

// TODO: ICMPv6
// TODO: Fix checksum for ICMPv6.

/// Build an ICMP echo probe.
/// @param packet the packet buffer, including the IP header.
/// @param target_checksum the custom ICMP checksum, in host order.
/// @param target_seq the custom sequence field, in host order.
void init(Packet packet, uint16_t target_checksum, uint16_t target_seq);

}  // namespace dminer::Builder::ICMP

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
void set_checksum(Packet packet);

/// Set a custom checksum in the UDP header, and ensure that the checksum is
/// valid by tweaking the payload.
/// @param packet the packet buffer, including the IP header.
/// @param target_checksum the custom checksum, in host order.
void set_checksum(Packet packet, uint16_t target_checksum);

/// Set the length in the UDP header.
/// @param packet the packet buffer, including the IP header.
void set_length(Packet packet);

/// Set the ports in the UDP header.
/// @param packet the packet buffer, including the IP header.
/// @param src_port the source port, in host order.
/// @param dst_port the destination port, in host order.
void set_ports(Packet packet, uint16_t src_port, uint16_t dst_port);

}  // namespace dminer::Builder::UDP
