#pragma once

/// Number of bytes used in the payload to correct the checksum.
#define PAYLOAD_TWEAK_BYTES 2

/// `sizeof(icmp)` returns 28, but we use only the 8 byte header.
#define ICMP_HEADER_SIZE 8
#define ICMPV6_HEADER_SIZE 8

// in6_addr.s6_addr32 is not defined on BSD/macOS.
#ifndef __linux__
#define s6_addr32 __u6_addr.__u6_addr32
#endif

// Fix for the glibc version included in the Python manylinux2014 image...
#ifdef __GLIBC__
#ifndef __FAVOR_BSD
#define uh_sport source
#define uh_dport dest
#define uh_ulen len
#define uh_sum check
#endif
#endif
