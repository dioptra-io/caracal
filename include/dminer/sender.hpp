#pragma once

#include <arpa/inet.h>
#include <sys/time.h>
#include <tins/tins.h>

#include <boost/log/trivial.hpp>
#include <chrono>
#include <string>

#include "network_utils_t.hpp"
#include "packets_utils.hpp"
#include "pretty.hpp"
#include "probe.hpp"
#include "socket.hpp"
#include "timestamp.hpp"

using std::array;
using std::invalid_argument;
using std::string;
using std::system_error;
using std::chrono::system_clock;
using Tins::NetworkInterface;
using utils::compact_ip_hdr;
using utils::tcphdr;
using utils::udphdr;

// TODO: IPv6
class Sender {
 public:
  Sender(const NetworkInterface &interface, const string &protocol)
      : buffer_{0}, payload_{"AA"}, socket_{AF_INET, SOCK_RAW, IPPROTO_RAW} {
    if (protocol == "tcp") {
      protocol_ = IPPROTO_TCP;
    } else if (protocol == "udp") {
      protocol_ = IPPROTO_UDP;
    } else {
      throw invalid_argument("protocol must be tcp or udp.");
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
    sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;  // TODO: IPv6
    dst_addr.sin_addr = probe.dst_addr;
    dst_addr.sin_port = htons(probe.dst_port);

    // The payload len is the ttl + 2, the +2 is to be able to fully
    // tweak the checksum for the timestamp
    packets_utils::init_ip_header(buffer_.data(), protocol_,
                                  src_addr_.sin_addr.s_addr);
    packets_utils::complete_ip_header(buffer_.data(), dst_addr.sin_addr.s_addr,
                                      probe.ttl, protocol_, probe.ttl + 2);

    uint64_t timestamp = to_timestamp<tenth_ms>(system_clock::now());

    uint16_t buf_size = 0;
    if (protocol_ == IPPROTO_UDP) {
      uint16_t payload_length = probe.ttl + 2;
      uint16_t udp_length = sizeof(udphdr) + payload_length;

      packets_utils::add_udp_ports(buffer_.data() + sizeof(ip), probe.src_port,
                                   probe.dst_port);
      packets_utils::add_udp_length(buffer_.data() + sizeof(ip),
                                    payload_length);
      packets_utils::add_udp_timestamp(buffer_.data() + sizeof(ip), timestamp);
      buf_size = sizeof(compact_ip_hdr) + udp_length;
    } else if (protocol_ == IPPROTO_TCP) {
      packets_utils::init_tcp_header(buffer_.data() + sizeof(compact_ip_hdr));
      packets_utils::add_tcp_ports(buffer_.data() + sizeof(ip), probe.src_port,
                                   probe.dst_port);
      packets_utils::add_tcp_timestamp(buffer_.data() + sizeof(ip), timestamp,
                                       probe.ttl);
      packets_utils::add_transport_checksum(
          buffer_.data() + sizeof(ip), buffer_.data(), protocol_,
          const_cast<char *>(payload_.c_str()),
          static_cast<uint16_t>(payload_.size()));
      buf_size = sizeof(compact_ip_hdr) + sizeof(tcphdr) + payload_.size();
    }

    socket_.sendto(buffer_.data(), buf_size, 0, &dst_addr);

    // Reset the checksum for future computation.
    compact_ip_hdr *ip_header =
        reinterpret_cast<compact_ip_hdr *>(buffer_.data());
    ip_header->ip_sum = 0;
  }

 private:
  array<uint8_t, 65536> buffer_;
  string payload_;
  uint8_t protocol_;
  Socket socket_;
  sockaddr_in src_addr_;
};
