#pragma once

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

/// IP checksum computation.
namespace caracal::Checksum {

/// Compute the probe checksum used to verify replies integrity.
uint16_t caracal_checksum(uint32_t caracal_id, uint32_t dst_addr,
                          uint16_t src_port, uint8_t ttl);

/// Compute the IP checksum of `data`.
uint16_t ip_checksum(const void* data, size_t len);

/// Fold the sum.
uint16_t ip_checksum_fold(uint64_t sum);

/// Fold the sum and take the 1-complement.
uint16_t ip_checksum_finish(uint64_t sum);

/// Sum `data` in a 64-bit accumulator.
uint64_t ip_checksum_add(uint64_t sum, const void* data, size_t len);

/// Sum the IPv4 pseudo-header.
uint64_t ipv4_pseudo_header_sum(const ip* ip_header, uint16_t transport_length);

/// Sum the IPv6 pseudo-header.
uint64_t ipv6_pseudo_header_sum(const ip6_hdr* ip_header,
                                uint32_t transport_length,
                                uint8_t transport_protocol);

}  // namespace caracal::Checksum
