#include <netinet/ip.h>
#ifdef __APPLE__
#include <net/if.h>
#include <net/ndrv.h>
#elif __linux__
#include <netpacket/packet.h>
#endif
#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>
#include <tins/tins.h>

#include <algorithm>
#include <caracal/builder.hpp>
#include <caracal/constants.hpp>
#include <caracal/pretty.hpp>
#include <caracal/probe.hpp>
#include <caracal/sender.hpp>
#include <caracal/timestamp.hpp>
#include <caracal/utilities.hpp>
#include <chrono>
#include <string>

using std::chrono::system_clock;

namespace caracal {

Sender::Sender(const std::string &interface_name, uint16_t caracal_id)
    : buffer_{},
      l2_protocol_{Protocols::L2::Ethernet},
#ifdef __APPLE__
      socket_{AF_NDRV, SOCK_RAW, 0},
#elif __linux__
      socket_{AF_PACKET, SOCK_RAW, 0},
#endif
      if_{},
      src_mac_{},
      dst_mac_{},
      src_ip_v4_{},
      src_ip_v6_{},
      caracal_id_{caracal_id} {
  Tins::NetworkInterface interface{interface_name};

  // Find the interface type:
  // - Linux Ethernet link [Ethernet header -> IP header]
  // - Linux Loopback link: same as Ethernet but with 00... MAC addresses
  // - Linux IP link (e.g. VPN) [IP header]
  // - macOS Ethernet link [Ethernet header -> IP header]
  // - macOS Loopback link [BSD loopback header -> IP Header]
#ifdef __APPLE__
  if (interface.hw_address().to_string() == "00:00:00:00:00:00") {
    l2_protocol_ = Protocols::L2::BSDLoopback;
    spdlog::info("interface_type=bsd_loopback");
  }
#elif __linux__
  if (!interface.is_loopback() &&
      interface.hw_address().to_string() == "00:00:00:00:00:00") {
    l2_protocol_ = Protocols::L2::None;
    spdlog::info("interface_type=l3");
  }
#endif

  // Find the IPv4/v6 gateway.
  Tins::HWAddress<6> gateway_mac{"00:00:00:00:00:00"};
  try {
    spdlog::info("Resolving the gateway MAC address...");
    gateway_mac =
        Utilities::gateway_mac_for(interface, Tins::IPv4Address("8.8.8.8"));
  } catch (const std::runtime_error &e) {
    spdlog::warn(
        "Unable to resolve the gateway MAC address (this is expected on a "
        "loopback or tunnel interface): {}",
        e.what());
  }

  // Set the source/destination MAC addresses.
  auto if_mac = interface.hw_address();
  std::copy(if_mac.begin(), if_mac.end(), src_mac_.begin());
  std::copy(gateway_mac.begin(), gateway_mac.end(), dst_mac_.begin());

  // Initialize the source interface kernel structures.
#ifdef __APPLE__
  std::copy(interface_name.begin(), interface_name.end(), if_.snd_name);
  if_.snd_family = AF_NDRV;
  if_.snd_len = sizeof(sockaddr_ndrv);
  socket_.bind(&if_);
#elif __linux__
  std::copy(dst_mac_.begin(), dst_mac_.end(), if_.sll_addr);
  if_.sll_family = AF_PACKET;
  if_.sll_halen = ETHER_ADDR_LEN;
  if_.sll_ifindex = interface.id();
  if_.sll_protocol = 0;
#endif

  // Set the source IPv4 address.
  src_ip_v4_.sin_family = AF_INET;
  inet_pton(AF_INET, Utilities::source_ipv4_for(interface).to_string().c_str(),
            &src_ip_v4_.sin_addr);

  // Set the source IPv6 address.
  src_ip_v6_.sin6_family = AF_INET6;
  inet_pton(AF_INET6, Utilities::source_ipv6_for(interface).to_string().c_str(),
            &src_ip_v6_.sin6_addr);

  spdlog::info("dst_mac={:02x}", fmt::join(dst_mac_, ":"));
  spdlog::info("src_ip_v4={} src_ip_v6={}", src_ip_v4_.sin_addr,
               src_ip_v6_.sin6_addr);
}

void Sender::send(const Probe &probe) {
  const auto l3_protocol = probe.l3_protocol();
  const auto l4_protocol = probe.l4_protocol();

  const uint64_t timestamp =
      Timestamp::cast<Timestamp::tenth_ms>(system_clock::now());
  const uint16_t timestamp_enc = Timestamp::encode(timestamp);

  const uint16_t payload_length = probe.ttl + PAYLOAD_TWEAK_BYTES;
  const Packet packet{buffer_.data(), buffer_.size(), l2_protocol_,
                      l3_protocol,    l4_protocol,    payload_length};

  std::fill(packet.begin(), packet.end(), std::byte{0});

  switch (l2_protocol_) {
    case Protocols::L2::BSDLoopback:
      Builder::Loopback::init(packet);
      break;

    case Protocols::L2::Ethernet:
      Builder::Ethernet::init(packet, src_mac_, dst_mac_);
      break;

    case Protocols::L2::None:
      break;
  }

  switch (l3_protocol) {
    case Protocols::L3::IPv4:
      Builder::IPv4::init(packet, src_ip_v4_.sin_addr,
                          probe.sockaddr4().sin_addr, probe.ttl,
                          probe.checksum(caracal_id_));
      break;

    case Protocols::L3::IPv6:
      Builder::IPv6::init(packet, src_ip_v6_.sin6_addr,
                          probe.sockaddr6().sin6_addr, probe.ttl);
      break;
  }

  switch (l4_protocol) {
    case Protocols::L4::ICMP:
      Builder::ICMP::init(packet, probe.src_port, timestamp_enc);
      break;

    case Protocols::L4::ICMPv6:
      Builder::ICMPv6::init(packet, probe.src_port, timestamp_enc);
      break;

    case Protocols::L4::UDP:
      Builder::UDP::init(packet, timestamp_enc, probe.src_port, probe.dst_port);
      break;
  }

  socket_.sendto(packet.l2(), packet.l2_size(), 0, &if_);
}
}  // namespace caracal
