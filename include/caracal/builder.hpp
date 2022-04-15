#pragma once

#include <sys/types.h>
#include <net/ethernet.h>

#include <array>

#include "./packet.hpp"

/// Build probe packets.
namespace caracal::Builder {

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

}  // namespace caracal::Builder

/// Build the BSD/macOS Loopback header.
/// On Linux the loopback interface uses the Ethernet header,
/// but on macOS it uses a different 32-bit header.
namespace caracal::Builder::Loopback {

void init(Packet packet);

}  // namespace caracal::Builder::Loopback

/// Build the Ethernet header.
namespace caracal::Builder::Ethernet {

void init(Packet packet, const std::array<uint8_t, ETHER_ADDR_LEN> &src_addr,
          const std::array<uint8_t, ETHER_ADDR_LEN> &dst_addr);

}  // namespace caracal::Builder::Ethernet

/// Build IPv4 probes.
/// In the IP header, the type of service, protocol, source and destination
/// address fields are used for per-flow load-balancing.
/// We also encode the TTL in the ID field in order to retrieve it in the ICMP
/// destination unreachable/TTL exceeded messages since the TTL field is
/// decreased/modified at each hop.
namespace caracal::Builder::IPv4 {

/// Init the IPv4 header.
/// @param packet the packet buffer, including the IP header.
/// @param src_addr the source IPv4 address.
/// @param dst_addr the destination IPv4 address.
/// @param ttl the TTL.
/// @param id the value of the ID field.
void init(Packet packet, in_addr src_addr, in_addr dst_addr, uint8_t ttl,
          uint16_t id);

}  // namespace caracal::Builder::IPv4

/// Build IPv6 probes.
namespace caracal::Builder::IPv6 {

/// Init the IPv6 header.
/// @param packet the packet buffer, including the IP header.
/// @param src_addr the source IPv6 address.
/// @param dst_addr the destination IPv6 address.
/// @param ttl the TTL.
void init(Packet packet, in6_addr src_addr, in6_addr dst_addr, uint8_t ttl);

}  // namespace caracal::Builder::IPv6

/// Build ICMP echo probes.
/// In the ICMP echo header, the code and checksum fields are used for per-flow
/// load-balancing. We encode the flow ID in the checksum field to vary the flow
/// ID, and in the id field. We encode the timestamp in the sequence field.
/// Since echo replies, in contrast to destination unreachable messages, doesn't
/// contain the original probe packet (including the original TTL and flow ID),
/// we ignore them in the packet parser.
namespace caracal::Builder::ICMP {

/// Build an ICMP echo probe.
/// @param packet the packet buffer, including the IP header.
/// @param target_checksum the custom ICMP checksum, in host order.
/// @param target_sequence the custom sequence field, in host order.
void init(Packet packet, uint16_t target_checksum, uint16_t target_sequence);

}  // namespace caracal::Builder::ICMP

/// Build ICMPv6 echo probes.
namespace caracal::Builder::ICMPv6 {

/// Build an ICMPv6 echo probe.
/// @param packet the packet buffer, including the IP header.
/// @param target_checksum the custom ICMP checksum, in host order.
/// @param target_sequence the custom sequence field, in host order.
void init(Packet packet, uint16_t target_checksum, uint16_t target_payload);

}  // namespace caracal::Builder::ICMPv6

/// Build UDP probes.
/// In the UDP header, the source and destination ports are used for per-flow
/// load-balancing. We use those for encoding the flow ID, and we encode the
/// timestamp in the checksum (which doesn't affect the flow ID).
/// The TTL is encoded in the payload length, in addition to the TTL field in
/// the IP header. The payload is all zeros, except two bytes used to ensure
/// that the custom checksum is valid.
namespace caracal::Builder::UDP {

/// Build an UDP probe.
/// @param packet the packet buffer, including the IP header.
/// @param target_checksum the custom checksum, in host order.
/// @param src_port the source port, in host order.
/// @param dst_port the destination port, in host order.
void init(Packet packet, uint16_t target_checksum, uint16_t src_port,
          uint16_t dst_port);

}  // namespace caracal::Builder::UDP
