#pragma once

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
#include <array>
#include <chrono>
#include <map>
#include <string>

#include "builder.hpp"
#include "constants.hpp"
#include "pretty.hpp"
#include "probe.hpp"
#include "socket.hpp"
#include "timestamp.hpp"

using std::chrono::system_clock;

namespace dminer {

// TODO: Include the protocol in the probe struct instead?
static const std::map<std::string, uint8_t> l4_protocols = {
    {"icmp", IPPROTO_ICMP}, {"tcp", IPPROTO_TCP}, {"udp", IPPROTO_UDP}};

class Sender {
 public:
  Sender(const Tins::NetworkInterface &interface, const std::string &protocol)
      : buffer_{},
        l4_protocol_{l4_protocols.at(protocol)},
#ifdef __APPLE__
        socket_{AF_NDRV, SOCK_RAW, 0},
#elif __linux__
        socket_{AF_PACKET, SOCK_RAW, 0},
#endif
        if_{},
        src_mac_{},
        dst_mac_{},
        src_ip_v4{},
        src_ip_v6{} {
    // Find the IPv4/v6 gateway.
    Tins::HWAddress<6> gateway_mac{"00:00:00:00:00:00"};
    try {
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
    auto if_name = interface.name();
    std::copy(if_name.begin(), if_name.end(), if_.snd_name);
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
    src_ip_v4.sin_family = AF_INET;
    inet_pton(AF_INET,
              Utilities::source_ipv4_for(interface).to_string().c_str(),
              &src_ip_v4.sin_addr);

    // Set the source IPv6 address.
    src_ip_v6.sin6_family = AF_INET6;
    inet_pton(AF_INET6,
              Utilities::source_ipv6_for(interface).to_string().c_str(),
              &src_ip_v6.sin6_addr);

    spdlog::info("dst_mac={:02x}", fmt::join(dst_mac_, ":"));
    spdlog::info("src_ip_v4={} src_ip_v6={}", src_ip_v4.sin_addr,
                 src_ip_v6.sin6_addr);
  }

  void send(const Probe &probe) {
    const bool is_v4 = probe.v4();
    const uint8_t l3_protocol = is_v4 ? IPPROTO_IP : IPPROTO_IPV6;
    // We reserve two bytes in the payload to tweak the checksum.
    const uint16_t payload_length = probe.ttl + PAYLOAD_TWEAK_BYTES;
    const uint64_t timestamp = to_timestamp<tenth_ms>(system_clock::now());
    const uint16_t timestamp_enc = encode_timestamp(timestamp);
    const Packet packet{buffer_, l3_protocol, l4_protocol_, payload_length};

    std::fill(packet.begin(), packet.end(), std::byte{0});

    if (is_v4) {
      Builder::Ethernet::init(packet, ETHERTYPE_IP, src_mac_, dst_mac_);
      Builder::IP::init(packet, l4_protocol_, src_ip_v4.sin_addr,
                        probe.sockaddr4().sin_addr, probe.ttl);
    } else {
      Builder::Ethernet::init(packet, ETHERTYPE_IPV6, src_mac_, dst_mac_);
      Builder::IP::init(packet, l4_protocol_, src_ip_v6.sin6_addr,
                        probe.sockaddr6().sin6_addr, probe.ttl);
    }

    switch (l4_protocol_) {
      case IPPROTO_ICMP:
        Builder::ICMP::init(packet, probe.src_port, timestamp_enc);
        break;

      case IPPROTO_TCP:
        Builder::TCP::init(packet);
        Builder::TCP::set_ports(packet, probe.src_port, probe.dst_port);
        Builder::TCP::set_sequence(packet, timestamp_enc, probe.ttl);
        Builder::TCP::set_checksum(packet);
        break;

      case IPPROTO_UDP:
        Builder::UDP::set_ports(packet, probe.src_port, probe.dst_port);
        Builder::UDP::set_length(packet);
        Builder::UDP::set_checksum(packet, timestamp_enc);
        break;

      default:
        break;
    }

    socket_.sendto(packet.l2(), packet.l2_size(), 0, &if_);
  }

 private:
  std::array<std::byte, 65536> buffer_;
  uint8_t l4_protocol_;
  Socket socket_;
#ifdef __APPLE__
  sockaddr_ndrv if_;
#elif __linux__
  sockaddr_ll if_;
#endif
  std::array<uint8_t, ETHER_ADDR_LEN> src_mac_;
  std::array<uint8_t, ETHER_ADDR_LEN> dst_mac_;
  sockaddr_in src_ip_v4;
  sockaddr_in6 src_ip_v6;
};
}  // namespace dminer
