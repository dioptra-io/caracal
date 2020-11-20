#include <arpa/inet.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>

#include "../probe.hpp"
#include "../random_permutation.hpp"

class ExhaustiveProbeIterator {
 public:
  ExhaustiveProbeIterator(bool ended)
      : m_permutation{RandomPermutationIterator{UINT32_MAX}},
        m_permutation_end{RandomPermutationIterator{}},
        m_ended{ended} {
    next();
  }

  bool operator==(const ExhaustiveProbeIterator& other) const {
    return (m_ended == other.m_ended);
  }

  bool operator!=(const ExhaustiveProbeIterator& other) const {
    return !(*this == other);
  }

  const Probe& operator*() const { return m_probe; }

  ExhaustiveProbeIterator& operator++() {
    next();
    return *this;
  }

  void next() {
    if (m_permutation == m_permutation_end) {
      m_ended = true;
      return;
    }
    uint32_t val = *m_permutation;
    uint32_t addr = val & 0x00FFFFFF;        // pick out 24 bits of network
    uint8_t ttl = (val >> 24) & 0x0000001F;  // pick 5 bits for the TTL;
    uint32_t host_offset =
        val >> 29;  // pick the 3 remaining bits for the offset.
    auto little_endian_addr = ntohl(addr);
    auto last_byte = little_endian_addr >> 24;
    if (last_byte + host_offset <= 255) {
      little_endian_addr += host_offset;
    } else {
      little_endian_addr -= host_offset;
    }

    m_probe.dst_addr.s_addr = htonl(little_endian_addr);
    m_probe.src_port = 24000;
    m_probe.dst_port = 33434;
    m_probe.ttl = ttl;
    ++m_permutation;
  }

 private:
  Probe m_probe;
  bool m_ended;
  RandomPermutationIterator m_permutation;
  RandomPermutationIterator m_permutation_end;
};

class ExhaustiveProbeGenerator {
 public:
  ExhaustiveProbeIterator begin() { return ExhaustiveProbeIterator{false}; }
  ExhaustiveProbeIterator end() { return ExhaustiveProbeIterator{true}; }
};
