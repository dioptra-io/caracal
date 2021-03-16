#pragma once

// L2 protocol types
#define L2PROTO_NONE 0
#define L2PROTO_BSDLOOPBACK 1
#define L2PROTO_ETHERNET 2

/// Number of bytes used in the payload to correct the checksum.
#define PAYLOAD_TWEAK_BYTES 2

/// `sizeof(icmp)` returns 28, but we use only the minimal 8 byte header.
#define ICMP_HEADER_SIZE 8

/// `sizeof(icmp6_hdr)` returns 8, but we use only the 4 byte header.
#define ICMPV6_HEADER_SIZE 4

// in6_addr.s6_addr32 is not defined on macOS.
#ifdef __APPLE__
#define s6_addr32 __u6_addr.__u6_addr32
#endif
