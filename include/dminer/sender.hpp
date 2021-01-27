#pragma once

#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <tins/tins.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <map>
#include <string>

#include "builder.hpp"
#include "logging.hpp"
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
        socket_{AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)},
        dst_mac_v4_{},
        dst_mac_v6_{},
        src_ip_v4{},
        src_ip_v6{} {
    // Find the IPv4/v6 gateway.
    Tins::HWAddress<6> gateway_mac{"00:00:00:00:00:00"};
    try {
      gateway_mac =
          Utilities::gateway_mac_for(interface, Tins::IPv4Address("8.8.8.8"));
    } catch (const std::runtime_error &e) {
      LOG(warning,
          "Unable to resolve the gateway MAC address (this is expected on "
          "a loopback or tunnel interface): "
              << e.what())
    }

    // Set the IPv4 destination MAC address.
    std::copy(gateway_mac.begin(), gateway_mac.end(), dst_mac_v4_.sll_addr);
    dst_mac_v4_.sll_family = AF_PACKET;
    dst_mac_v4_.sll_halen = ETHER_ADDR_LEN;
    dst_mac_v4_.sll_ifindex = interface.id();
    dst_mac_v4_.sll_protocol = htons(ETH_P_IP);

    // Set the IPv6 destination MAC address.
    std::copy(gateway_mac.begin(), gateway_mac.end(), dst_mac_v6_.sll_addr);
    dst_mac_v6_.sll_family = AF_PACKET;
    dst_mac_v6_.sll_halen = ETHER_ADDR_LEN;
    dst_mac_v6_.sll_ifindex = interface.id();
    dst_mac_v6_.sll_protocol = htons(ETH_P_IPV6);

    // Set the IPv4 source IP address.
    src_ip_v4.sin_family = AF_INET;
    inet_pton(AF_INET,
              Utilities::source_ipv4_for(interface).to_string().c_str(),
              &src_ip_v4.sin_addr);

    // Set the IPv6 source IP address.
    src_ip_v6.sin6_family = AF_INET6;
    inet_pton(AF_INET6,
              Utilities::source_ipv6_for(interface).to_string().c_str(),
              &src_ip_v6.sin6_addr);

    LOG(info, "dst_mac_v4=" << dst_mac_v4_ << " dst_mac_v6=" << dst_mac_v6_);
    LOG(info, "src_ip_v4=" << src_ip_v4.sin_addr
                           << " src_ip_v6=" << src_ip_v6.sin6_addr);
  }

  void send(const Probe &probe) {
    const bool is_v4 = probe.v4();
    const uint8_t l3_protocol = is_v4 ? IPPROTO_IP : IPPROTO_IPV6;
    // We reserve two bytes in the payload to tweak the checksum.
    const uint16_t payload_length = probe.ttl + 2;
    const uint64_t timestamp = to_timestamp<tenth_ms>(system_clock::now());
    const uint16_t timestamp_enc = encode_timestamp(timestamp);
    const Packet packet{buffer_, l3_protocol, l4_protocol_, payload_length};

    std::fill(packet.begin(), packet.end(), std::byte{0});

    if (is_v4) {
      Builder::IP::init(packet, l4_protocol_, src_ip_v4.sin_addr,
                        probe.sockaddr4().sin_addr, probe.ttl);
    } else {
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

    socket_.sendto(packet.l3(), packet.l3_size(), 0,
                   is_v4 ? &dst_mac_v4_ : &dst_mac_v6_);
  }

 private:
  std::array<std::byte, 65536> buffer_;
  uint8_t l4_protocol_;
  Socket socket_;
  sockaddr_ll dst_mac_v4_;
  sockaddr_ll dst_mac_v6_;
  sockaddr_in src_ip_v4;
  sockaddr_in6 src_ip_v6;
};
}  // namespace dminer
