#include "classic_sender_t.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#include <boost/log/trivial.hpp>
#include <cerrno>
#include <cmath>
#include <iostream>
// #include <netinet/udp.h> // udphdr
#include <netinet/ip.h>  // ip
// #include <netinet/tcp.h> // tcphdr
#include <sys/time.h>
#include <tins/tins.h>

#include <filesystem>
#include <optional>

#include "network_utils_t.hpp"
#include "packets_utils.hpp"
#include "parameters_utils_t.hpp"
#include "pretty.hpp"
#include "probe.hpp"

namespace fs = std::filesystem;

using utils::compact_ip_hdr;
using utils::tcphdr;
using utils::udphdr;

classic_sender_t::classic_sender_t(uint8_t family, const std::string &protocol,
                                   const Tins::NetworkInterface interface,
                                   const int pps,
                                   const std::optional<fs::path> ofile)
    : m_socket(socket(family, SOCK_RAW, IPPROTO_RAW)),
      m_family(family),
      m_payload("AA"),
      m_rl(pps) {
  m_proto = -1;
  if (protocol == "udp") {
    m_proto = IPPROTO_UDP;
  } else if (protocol == "tcp") {
    m_proto = IPPROTO_TCP;
  } else {
    throw std::invalid_argument("Invalid protocol!");
  }

  const int on = 1;
  if (setsockopt(m_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) != 0) {
    BOOST_LOG_TRIVIAL(fatal)
        << "Error while calling setsockopt, try to run as root";
    throw std::system_error(errno, std::generic_category(), "setsockopt");
  }

  if (setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) ==
      -1) {
    BOOST_LOG_TRIVIAL(fatal)
        << "Error while calling setsockopt, try to run as root";
    throw std::system_error(errno, std::generic_category(),
                            "setsockopt(SO_REUSEADDR)");
  }

  socklen_t optlen;
  int res, sendbuff;
  optlen = sizeof(sendbuff);
  res = getsockopt(m_socket, SOL_SOCKET, SO_SNDBUF, &sendbuff, &optlen);

  if (res == -1) {
    std::cout << "Error getsockopt one\n";
  } else {
    BOOST_LOG_TRIVIAL(info) << "send buffer size is " << sendbuff;
  }

  // Set buffer size
  sendbuff *= 64;

  res =
      setsockopt(m_socket, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));

  if (res == -1) {
    std::cout << "Error setsockopt \n";
  } else {
    BOOST_LOG_TRIVIAL(info) << "send buffer size setted to " << sendbuff;
  }

  uint32_t uint_src_addr = 0;
  int error = inet_pton(AF_INET, interface.ipv4_address().to_string().c_str(),
                        &uint_src_addr);
  if (error != 1) {
    perror("inet_pton");
  }

  // Socket stuff

  m_src_addr.sin_family = family;
  m_src_addr.sin_addr.s_addr = uint_src_addr;

  if (bind(m_socket, (struct sockaddr *)&m_src_addr, sizeof(m_src_addr)) < 0) {
    perror("bind");
    exit(1);
  }

  // Raw packet stuff
  std::size_t transport_header_size = 0;
  if (m_proto == IPPROTO_UDP) {
    transport_header_size = sizeof(udphdr);
  } else if (m_proto == IPPROTO_TCP) {
    transport_header_size = sizeof(tcphdr);
  }
  // Buffer size is size of the IP header + size of transport + size of maximum
  // payload We will only send the number of needed bytes for payload.
  uint32_t buffer_size =
      sizeof(compact_ip_hdr) + transport_header_size + utils::max_ttl + 2;
  m_buffer = reinterpret_cast<uint8_t *>(malloc(buffer_size));
  memset(m_buffer, 0, buffer_size);
  packets_utils::init_ip_header(m_buffer, m_proto, uint_src_addr);
  if (m_proto == IPPROTO_UDP) {
    // The length depending on the ttl, sets it later
    //        packets_utils::init_udp_header(m_buffer + sizeof(compact_ip_hdr),
    //        static_cast<uint16_t>(m_payload.size()));
  } else if (m_proto == IPPROTO_TCP) {
    packets_utils::init_tcp_header(m_buffer + sizeof(compact_ip_hdr));
  }

  // Set the payload later
  //    char * data = nullptr;
  //    data = reinterpret_cast<char *>(m_buffer + sizeof(compact_ip_hdr) +
  //    transport_header_size); std::cout << m_payload << std::endl;
  //    std::strncpy(data , m_payload.c_str(), m_payload.size());

  if (ofile) {
    m_start_time_log_file.open(ofile.value());
    m_start_time_log_file.precision(17);
    std::cout.precision(17);
  }
}

void classic_sender_t::send(const Probe &probe, int n_packets) {
  uint32_t time_interval = 5;

  // Temp
  in_addr destination = probe.dst_addr;
  uint8_t ttl = probe.ttl;
  uint16_t sport = probe.src_port;
  uint16_t dport = probe.dst_port;

  sockaddr_in m_dst_addr;

  m_dst_addr.sin_family = m_family;
  m_dst_addr.sin_addr = destination;
  m_dst_addr.sin_port = htons(dport);

  //    m_ip_template.dst_addr(IPv4Address(destination));
  //    m_ip_template.ttl(ttl);
  //    m_ip_template.id(ttl);
  //    static_cast<UDP*> (m_ip_template.inner_pdu())->dport(flow_id);

  // TODO: Dump ref. time.
  dump_reference_time();

  // Reset the timestamp if m_now is passed a certain window
  if ((m_now.tv_sec - m_start.tv_sec) >= time_interval) {
    // TODO: Dump ref. time.
    dump_reference_time();
  }

  // The payload len is the ttl + 2, the +2 is to be able to fully
  // tweak the checksum for the timestamp
  packets_utils::complete_ip_header(m_buffer, destination.s_addr, ttl, m_proto,
                                    ttl + 2);

  // Compute payload len to

  uint16_t buf_size = 0;
  if (m_proto == IPPROTO_UDP) {
    uint16_t payload_length = ttl + 2;
    uint16_t udp_length = sizeof(udphdr) + payload_length;

    packets_utils::add_udp_ports(m_buffer + sizeof(ip), sport, dport);
    packets_utils::add_udp_length(m_buffer + sizeof(ip), payload_length);
    packets_utils::add_udp_timestamp(m_buffer + sizeof(ip), m_buffer,
                                     payload_length, m_start, m_now);
    //        packets_utils::add_transport_checksum(m_buffer + sizeof(ip),
    //        m_buffer, m_proto,
    //                                              const_cast<char
    //                                              *>(m_payload.c_str()),
    //                                              static_cast<uint16_t>(m_payload.size()));
    buf_size = sizeof(compact_ip_hdr) + udp_length;

  } else if (m_proto == IPPROTO_TCP) {
    packets_utils::add_tcp_ports(m_buffer + sizeof(ip), sport, dport);
    packets_utils::add_tcp_timestamp(m_buffer + sizeof(ip), m_start, m_now,
                                     ttl);
    packets_utils::add_transport_checksum(
        m_buffer + sizeof(ip), m_buffer, m_proto,
        const_cast<char *>(m_payload.c_str()),
        static_cast<uint16_t>(m_payload.size()));

    buf_size = sizeof(compact_ip_hdr) + sizeof(tcphdr) + m_payload.size();
  }

  //    Tins::EthernetII test (m_buffer, sizeof(ether_header) + sizeof(ip) +
  //    sizeof(udphdr) + m_payload.size()); std::cout << test.dst_addr() << ", "
  //    << test.src_addr() << "\n"; auto ip_pdu = test.find_pdu<IP>(); std::cout
  //    << ip_pdu->dst_addr() << ", " << ip_pdu->src_addr() << "\n";

  //    PacketSender sender (NetworkInterface::default_interface());
  //    sender.send(test);

  // Send two packets so that we can spot the eventual per packet LB and
  // anomalies.
  for (int i = 0; i < n_packets; ++i) {
    BOOST_LOG_TRIVIAL(trace)
        << "Sending packet #" << i + 1 << " to " << m_dst_addr;

    int rc = sendto(m_socket, m_buffer, buf_size, 0,
                    (const sockaddr *)&m_dst_addr, sizeof(m_dst_addr));
    if (rc < 0) {
      BOOST_LOG_TRIVIAL(error) << "Could not send packet to " << m_dst_addr
                               << ": " << strerror(errno);
    }
    // Control the probing rate with active waiting to be precise
    m_rl.wait();
  }

  // Reset the checksum for future computation.
  compact_ip_hdr *ip_header = reinterpret_cast<compact_ip_hdr *>(m_buffer);
  ip_header->ip_sum = 0;
}

classic_sender_t::~classic_sender_t() {
  m_start_time_log_file.close();
  delete m_buffer;
}

void classic_sender_t::dump_reference_time() {
  gettimeofday(&m_start, NULL);
  double seconds_since_epoch =
      m_start.tv_sec + static_cast<double>(m_start.tv_usec) / 1000000;

  // BOOST_LOG_TRIVIAL(debug) << std::fixed
  //                          << "Start time set to: " << seconds_since_epoch
  //                          << " seconds since epoch.";
  m_start_time_log_file << std::fixed << seconds_since_epoch << std::endl;
}
