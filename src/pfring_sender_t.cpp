#include "pfring_sender_t.hpp"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include <boost/log/trivial.hpp>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <optional>

#include "network_utils_t.hpp"
#include "packets_utils.hpp"
#include "parameters_utils_t.hpp"
#include "probe.hpp"
#include "timestamp.hpp"

namespace fs = std::filesystem;

using std::chrono::system_clock;
using utils::compact_ip_hdr;
using utils::tcphdr;
using utils::udphdr;

pf_ring_sender_t::pf_ring_sender_t(const int family,
                                   const std::string &protocol,
                                   const Tins::NetworkInterface iface,
                                   const uint32_t pps)
    : m_family{family}, m_payload("fr"), m_rl(pps) {
  m_proto = -1;
  if (protocol == "udp") {
    m_proto = IPPROTO_UDP;
  } else if (protocol == "tcp") {
    m_proto = IPPROTO_TCP;
  } else {
    throw std::invalid_argument("Invalid protocol!");
  }

  // TODO: Improve this + log. discovered gateway.
  Tins::IPv4Address gateway_ip;
  Tins::Utils::gateway_from_ip("8.8.8.8", gateway_ip);
  Tins::PacketSender resolve_gateway_sender{iface};
  auto hw_source = iface.hw_address();
  auto hw_gateway =
      Tins::Utils::resolve_hwaddr(gateway_ip, resolve_gateway_sender);

  m_pf_ring = pfring_open(iface.name().c_str(), 1500, 0 /* PF_RING_PROMISC */);
  if (m_pf_ring == NULL) {
    printf(
        "pfring_open error [%s] (pf_ring not loaded or interface %s is down "
        "?)\n",
        strerror(errno), iface.name().c_str());
  } else {
    u_int32_t version;

    char name[] = "pfsend";
    pfring_set_application_name(m_pf_ring, name);
    pfring_version(m_pf_ring, &version);

    printf("Using PF_RING v%d.%d.%d\n", (version & 0xFFFF0000) >> 16,
           (version & 0x0000FF00) >> 8, version & 0x000000FF);
  }

  pfring_set_socket_mode(m_pf_ring, send_only_mode);

  if (pfring_enable_ring(m_pf_ring) != 0) {
    pfring_close(m_pf_ring);
    throw std::runtime_error("Unable to enable PF_RING");
  }

  uint32_t uint_src_addr = 0;
  int error = inet_pton(AF_INET, iface.ipv4_address().to_string().c_str(),
                        &uint_src_addr);
  if (error != 1) {
    perror("inet_pton");
  }

  // Check that the PDU is well formed.

  //    Tins::EthernetII test (m_buffer, sizeof(ether_header) + sizeof(ip) +
  //    sizeof(udphdr) + m_payload.size()); std::cout << test.dst_addr() << ", "
  //    << test.src_addr() << "\n"; auto ip_pdu = test.find_pdu<IP>(); std::cout
  //    << ip_pdu->dst_addr() << ", " << ip_pdu->src_addr() << "\n";

  // Raw packet stuff
  std::size_t transport_header_size = 0;
  if (m_proto == IPPROTO_UDP) {
    transport_header_size = sizeof(udphdr);
  } else if (m_proto == IPPROTO_TCP) {
    transport_header_size = sizeof(tcphdr);
  }
  // Buffer size is size of the IP header + size of transport + size of maximum
  // payload We will only send the number of needed bytes for payload.
  uint32_t buffer_size = sizeof(ether_header) + sizeof(compact_ip_hdr) +
                         transport_header_size + utils::max_ttl + 2;
  m_buffer = new uint8_t[buffer_size];
  memset(m_buffer, 0, buffer_size);
  packets_utils::init_ethernet_header(m_buffer, family, hw_source, hw_gateway);
  packets_utils::init_ip_header(m_buffer + sizeof(ether_header), m_proto,
                                uint_src_addr);

  // Raw packet stuff
  if (m_proto == IPPROTO_UDP) {
    //        packets_utils::init_udp_header(m_buffer + sizeof(ether_header) +
    //        sizeof(compact_ip_hdr),
    //                                       static_cast<uint16_t>(m_payload.size()));
  } else if (m_proto == IPPROTO_TCP) {
    packets_utils::init_tcp_header(m_buffer + sizeof(ether_header) +
                                   sizeof(compact_ip_hdr));
  }
}

void pf_ring_sender_t::send(const Probe &probe, int n_packets) {
  // TEMP
  in_addr destination = probe.dst_addr;
  uint8_t ttl = probe.ttl;
  uint16_t sport = probe.src_port;
  uint16_t dport = probe.dst_port;

  //    uint32_t monitoring_interval = 1;
  //    uint32_t packets_per_second_threshold = 100000;
  //    sockaddr_in m_dst_addr;
  //
  //    m_dst_addr.sin_family = m_family;
  //    m_dst_addr.sin_addr.s_addr = destination;
  //    m_dst_addr.sin_port = htons (dport);

  //    m_ip_template.dst_addr(IPv4Address(destination));
  //    m_ip_template.ttl(ttl);
  //    m_ip_template.id(ttl);
  //    static_cast<UDP*> (m_ip_template.inner_pdu())->dport(flow_id);

  packets_utils::complete_ip_header(m_buffer + sizeof(ether_header),
                                    destination.s_addr, ttl, m_proto, ttl + 2);

  uint64_t timestamp = to_timestamp<tenth_ms>(system_clock::now());

  uint16_t buf_size = 0;
  if (m_proto == IPPROTO_UDP) {
    uint16_t payload_length = ttl + 2;
    uint16_t udp_length = sizeof(udphdr) + payload_length;

    packets_utils::add_udp_ports(m_buffer + sizeof(ether_header) + sizeof(ip),
                                 sport, dport);
    packets_utils::add_udp_length(m_buffer + sizeof(ether_header) + sizeof(ip),
                                  payload_length);
    packets_utils::add_udp_timestamp(
        m_buffer + sizeof(ether_header) + sizeof(ip), timestamp);
    buf_size = sizeof(ether_header) + sizeof(compact_ip_hdr) + udp_length;
  } else if (m_proto == IPPROTO_TCP) {
    packets_utils::add_tcp_ports(m_buffer + sizeof(ether_header) + sizeof(ip),
                                 sport, dport);
    packets_utils::add_tcp_timestamp(
        m_buffer + sizeof(ether_header) + sizeof(ip), timestamp, ttl);
    packets_utils::add_transport_checksum(
        m_buffer + sizeof(ether_header) + sizeof(ip),
        m_buffer + sizeof(ether_header), m_proto,
        const_cast<char *>(m_payload.c_str()),
        static_cast<uint16_t>(m_payload.size()));

    buf_size = sizeof(ether_header) + sizeof(compact_ip_hdr) + sizeof(tcphdr) +
               m_payload.size();
  }

  //    Tins::EthernetII test (m_buffer, sizeof(ether_header) + sizeof(ip) +
  //    sizeof(udphdr) + m_payload.size()); std::cout << test.dst_addr() << ", "
  //    << test.src_addr() << "\n"; auto ip_pdu = test.find_pdu<IP>(); std::cout
  //    << ip_pdu->dst_addr() << ", " << ip_pdu->src_addr() << "\n";

  //    PacketSender sender (NetworkInterface::default_interface());
  //    sender.send(test);

  // Send n_packets so that we can spot the eventual per packet LB and
  // anomalies.
  for (int i = 0; i < n_packets; ++i) {
    auto rc = 0;
    while (rc <= 0) {
      rc = pfring_send(m_pf_ring, reinterpret_cast<char *>(m_buffer), buf_size,
                       0);
      if (rc <= 0) {
        // Buffer full, retry
        //                in_addr ip_addr;
        //                ip_addr.s_addr = ip_header->ip_dst;
        std::cerr << "Could not send packet, error code: " << strerror(errno)
                  << "\n";
        //                std::cerr << "The IP destination address is " <<
        //                inet_ntoa(ip_addr) << "\n";
      } else {
        // Control the probing rate with active waiting to be precise
        m_rl.wait();
      }
    }

    if (rc == PF_RING_ERROR_INVALID_ARGUMENT) {
      printf("Attempting to send invalid packet [len: %u][MTU: %u]\n",
             static_cast<unsigned int>(buf_size), m_pf_ring->mtu);
    }
  }

  //    if (unlikely(verbose))
  //        printf("[%d] pfring_send(%d) returned %d\n", i, tosend->len, rc);

  // Reset the checksum for future computation.
  compact_ip_hdr *ip_header =
      reinterpret_cast<compact_ip_hdr *>(m_buffer + sizeof(ether_header));
  ip_header->ip_sum = 0;
}

double pf_ring_sender_t::current_rate() const { return m_rl.current_rate(); }

pf_ring_sender_t::~pf_ring_sender_t() {
  delete[] m_buffer;
  pfring_close(m_pf_ring);
}
