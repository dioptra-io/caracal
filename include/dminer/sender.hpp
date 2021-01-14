#pragma once

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <tins/tins.h>

#include <array>
#include <boost/log/trivial.hpp>
#include <chrono>
#include <string>

#include "builder.hpp"
#include "pretty.hpp"
#include "probe.hpp"
#include "socket.hpp"
#include "timestamp.hpp"

using std::byte;
using std::chrono::system_clock;

namespace dminer {
class Sender {
 public:
  Sender(const Tins::NetworkInterface &interface, const std::string &protocol)
      : buffer_{}, socket_{AF_INET, SOCK_RAW, IPPROTO_RAW} {
    if (protocol == "icmp") {
      protocol_ = IPPROTO_ICMP;
    } else if (protocol == "tcp") {
      protocol_ = IPPROTO_TCP;
    } else if (protocol == "udp") {
      protocol_ = IPPROTO_UDP;
    } else {
      throw std::invalid_argument("protocol must be one of (icmp, tcp, udp).");
    }

    src_addr_.sin_addr.s_addr = uint32_t(interface.ipv4_address());
    src_addr_.sin_family = AF_INET;  // TODO: IPv6
    src_addr_.sin_port = 0;

    socket_.set(IPPROTO_IP, IP_HDRINCL, true);
    socket_.set(SOL_SOCKET, SO_REUSEADDR, true);
    try {
      socket_.set(SOL_SOCKET, SO_SNDBUF, 8388608);
    } catch (const std::system_error &e) {
      BOOST_LOG_TRIVIAL(warning)
          << "Cannot increase send buffer size: " << e.what();
    }

    socket_.bind(&src_addr_);
  }

  void send(const Probe &probe) {
    sockaddr_in dst_addr = probe.sockaddr();
    Builder::Packet packet;

    // We reserve two bytes in the payload to tweak the checksum.
    uint16_t payload_length = probe.ttl + 2;
    uint64_t timestamp = to_timestamp<tenth_ms>(system_clock::now());
    uint16_t timestamp_enc = encode_timestamp(timestamp);

    switch (protocol_) {
      case IPPROTO_ICMP:
        packet = Builder::Packet{buffer_.begin(),
                                 sizeof(ip) + sizeof(icmphdr) + payload_length};
        std::fill(packet.begin(), packet.end(), byte{0});
        Builder::IPv4::init(packet, protocol_, src_addr_.sin_addr,
                            dst_addr.sin_addr, probe.ttl);
        Builder::ICMP::init(packet, probe.src_port, timestamp_enc);
        break;

      case IPPROTO_TCP:
        packet = Builder::Packet{buffer_.begin(),
                                 sizeof(ip) + sizeof(tcphdr) + payload_length};
        std::fill(packet.begin(), packet.end(), byte{0});
        Builder::IPv4::init(packet, protocol_, src_addr_.sin_addr,
                            dst_addr.sin_addr, probe.ttl);
        Builder::TCP::init(packet);
        Builder::TCP::set_ports(packet, probe.src_port, probe.dst_port);
        Builder::TCP::set_sequence(packet, timestamp_enc, probe.ttl);
        Builder::TCP::set_checksum(packet);
        break;

      case IPPROTO_UDP:
        packet = Builder::Packet{buffer_.begin(),
                                 sizeof(ip) + sizeof(udphdr) + payload_length};
        std::fill(packet.begin(), packet.end(), byte{0});
        Builder::IPv4::init(packet, protocol_, src_addr_.sin_addr,
                            dst_addr.sin_addr, probe.ttl);
        Builder::UDP::set_ports(packet, probe.src_port, probe.dst_port);
        Builder::UDP::set_length(packet);
        Builder::UDP::set_checksum(packet, timestamp_enc);
        break;

      default:
        break;
    }

    socket_.sendto(packet.data(), packet.size(), 0, &dst_addr);
  }

 private:
  std::array<byte, 65536> buffer_;
  uint8_t protocol_;
  Socket socket_;
  sockaddr_in src_addr_;
};
}  // namespace dminer
