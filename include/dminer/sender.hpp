#pragma once

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <tins/tins.h>

#include <boost/log/trivial.hpp>
#include <chrono>
#include <string>

#include "packets_utils.hpp"
#include "pretty.hpp"
#include "probe.hpp"
#include "socket.hpp"
#include "timestamp.hpp"

using packets_utils::add_tcp_ports;
using packets_utils::add_tcp_timestamp;
using packets_utils::add_transport_checksum;
using packets_utils::add_udp_length;
using packets_utils::add_udp_ports;
using packets_utils::add_udp_timestamp;
using packets_utils::complete_icmp_header;
using packets_utils::complete_ip_header;
using packets_utils::fill_payload;
using packets_utils::init_ip_header;
using packets_utils::init_tcp_header;
using std::array;
using std::invalid_argument;
using std::string;
using std::system_error;
using std::chrono::system_clock;
using Tins::NetworkInterface;

namespace dminer {
// TODO: IPv6
class Sender {
 public:
  Sender(const NetworkInterface &interface, const string &protocol)
      : buffer_{0}, socket_{AF_INET, SOCK_RAW, IPPROTO_RAW} {
    if (protocol == "icmp") {
      protocol_ = IPPROTO_ICMP;
    } else if (protocol == "tcp") {
      protocol_ = IPPROTO_TCP;
    } else if (protocol == "udp") {
      protocol_ = IPPROTO_UDP;
    } else {
      throw invalid_argument("protocol must be one of (icmp, tcp, udp).");
    }

    src_addr_.sin_addr.s_addr = uint32_t(interface.ipv4_address());
    src_addr_.sin_family = AF_INET;  // TODO: IPv6
    src_addr_.sin_port = 0;

    socket_.set(IPPROTO_IP, IP_HDRINCL, true);
    socket_.set(SOL_SOCKET, SO_REUSEADDR, true);
    try {
      socket_.set(SOL_SOCKET, SO_SNDBUF, 8388608);
    } catch (const system_error &e) {
      BOOST_LOG_TRIVIAL(warning)
          << "Cannot increase send buffer size: " << e.what();
    }

    socket_.bind(&src_addr_);
  }

  void send(const Probe &probe) {
    sockaddr_in dst_addr = probe.sockaddr();

    uint8_t *ip_buffer = buffer_.data();
    uint8_t *transport_buffer = buffer_.data() + sizeof(ip);

    uint16_t buf_size = 0;
    // The payload len is the ttl + 2, the +2 is to be able to fully
    // tweak the checksum for the timestamp
    uint16_t payload_length = probe.ttl + 2;
    uint64_t timestamp = to_timestamp<tenth_ms>(system_clock::now());

    init_ip_header(ip_buffer, protocol_, src_addr_.sin_addr);
    complete_ip_header(ip_buffer, dst_addr.sin_addr, probe.ttl, protocol_,
                       probe.ttl + 2);

    switch (protocol_) {
      case IPPROTO_ICMP:
        buf_size = sizeof(ip) + sizeof(icmphdr) + payload_length;
        fill_payload(transport_buffer, sizeof(icmphdr), payload_length, 0);
        complete_icmp_header(transport_buffer, probe.src_port, timestamp);
        break;

      case IPPROTO_TCP:
        buf_size = sizeof(ip) + sizeof(tcphdr) + payload_length;
        fill_payload(transport_buffer, sizeof(tcphdr), payload_length, 0);
        init_tcp_header(transport_buffer);
        add_tcp_ports(transport_buffer, probe.src_port, probe.dst_port);
        add_tcp_timestamp(transport_buffer, timestamp, probe.ttl);
        add_transport_checksum(ip_buffer, protocol_, payload_length);
        break;

      case IPPROTO_UDP:
        buf_size = sizeof(ip) + sizeof(udphdr) + payload_length;
        fill_payload(transport_buffer, sizeof(udphdr), payload_length, 0);
        add_udp_ports(transport_buffer, probe.src_port, probe.dst_port);
        add_udp_length(transport_buffer, payload_length);
        add_udp_timestamp(ip_buffer, transport_buffer, payload_length,
                          timestamp);
        break;
    }

    socket_.sendto(buffer_.data(), buf_size, 0, &dst_addr);
  }

 private:
  array<uint8_t, 65536> buffer_;
  uint8_t protocol_;
  Socket socket_;
  sockaddr_in src_addr_;

  // TODO: Remove filter-min-ip/filter-max-ip (makes no sense for IPv6).
  // TODO: Sender buffer size CLI option.
};
}  // namespace dminer
