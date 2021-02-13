#pragma once

// Number of bytes used in the payload to correct the checksum.
#define PAYLOAD_TWEAK_BYTES 2

// in6_addr.s6_addr32 is not defined on macOS.
#ifdef __APPLE__
#define s6_addr32 __u6_addr.__u6_addr32
#endif
