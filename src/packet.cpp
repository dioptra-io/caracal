#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <caracal/constants.hpp>
#include <caracal/packet.hpp>
#include <caracal/protocols.hpp>
#include <stdexcept>

namespace caracal {

Packet::Packet(std::byte* buffer, const size_t buffer_len,
               const Protocols::L2 l2_protocol, const Protocols::L3 l3_protocol,
               const Protocols::L4 l4_protocol, const size_t payload_size)
    : l2_protocol_{l2_protocol},
      l3_protocol_{l3_protocol},
      l4_protocol_{l4_protocol} {
  size_t l2_header_size;
  size_t l3_header_size;
  size_t l4_header_size;

  // Pad the beginning of the packet to align on a four-byte boundary.
  // See https://lwn.net/Articles/89597/.
  size_t padding;

  switch (l2_protocol) {
    case Protocols::L2::BSDLoopback:
      l2_header_size = sizeof(uint32_t);
      padding = 0;
      break;

    case Protocols::L2::Ethernet:
      l2_header_size = sizeof(ether_header);
      padding = 2;
      break;

    case Protocols::L2::None:
      l2_header_size = 0;
      padding = 0;
      break;
  }

  switch (l3_protocol) {
    case Protocols::L3::IPv4:
      l3_header_size = sizeof(ip);
      break;

    case Protocols::L3::IPv6:
      l3_header_size = sizeof(ip6_hdr);
      break;
  }

  switch (l4_protocol) {
    case Protocols::L4::ICMP:
      l4_header_size = ICMP_HEADER_SIZE;
      break;

    case Protocols::L4::ICMPv6:
      l4_header_size = ICMPV6_HEADER_SIZE;
      break;

    case Protocols::L4::UDP:
      l4_header_size = sizeof(udphdr);
      break;
  }

  begin_ = buffer;
  l2_ = begin_ + padding;
  l3_ = l2_ + l2_header_size;
  l4_ = l3_ + l3_header_size;
  payload_ = l4_ + l4_header_size;
  end_ = payload_ + payload_size;

  if (buffer_len < static_cast<uint64_t>(end_ - begin_)) {
    throw std::invalid_argument{"Packet buffer is too small"};
  }

  if ((end_ - begin_) > 65535) {
    throw std::invalid_argument("Packet is too large");
  }
}

std::byte* Packet::begin() const noexcept { return begin_; }

std::byte* Packet::end() const noexcept { return end_; }

std::byte* Packet::l2() const noexcept { return l2_; }

std::byte* Packet::l3() const noexcept { return l3_; }

std::byte* Packet::l4() const noexcept { return l4_; }

std::byte* Packet::payload() const noexcept { return payload_; }

uint16_t Packet::l2_size() const noexcept {
  return static_cast<uint16_t>(end_ - l2_);
}

uint16_t Packet::l3_size() const noexcept {
  return static_cast<uint16_t>(end_ - l3_);
}

uint16_t Packet::l4_size() const noexcept {
  return static_cast<uint16_t>(end_ - l4_);
}

uint16_t Packet::payload_size() const noexcept {
  return static_cast<uint16_t>(end_ - payload_);
}

Protocols::L2 Packet::l2_protocol() const noexcept { return l2_protocol_; }

Protocols::L3 Packet::l3_protocol() const noexcept { return l3_protocol_; }

Protocols::L4 Packet::l4_protocol() const noexcept { return l4_protocol_; }

}  // namespace caracal
