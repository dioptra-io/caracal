//
// Created by System Administrator on 2019-01-31.
//

#include "classic_sender_t.hpp"

#include <arpa/inet.h>
#include <unistd.h>
#include <utils/network_utils_t.hpp>
#include <errno.h>
#include <iostream>
#include <cmath>

#include <tins/tins.h>
#include <fcntl.h>
#include <utils/timing_utils.hpp>
//#include <netinet/udp.h> // udphdr
#include <netinet/ip.h> // ip
//#include <netinet/tcp.h> //tcphdr



#include <utils/packets_utils.hpp>
#include <utils/parameters_utils_t.hpp>

using namespace Tins;
using namespace utils;


classic_sender_t::classic_sender_t(
        uint8_t family,
        int type,
        uint8_t proto,
        const std::string &src_addr,
        const uint32_t pps):
m_socket(socket(family, SOCK_RAW, IPPROTO_RAW)),
m_family(family),
m_proto(proto),
m_payload("AA"),
m_n_packets_sent(0)
{


    const int on = 1;
    if (setsockopt(m_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) != 0) {
        perror("setsockopt");
    }

    if (setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) == -1) {
        perror("setsockopt(SO_REUSEADDR)");
        exit(1);
    }
    socklen_t optlen;
    int res, sendbuff;
    optlen = sizeof(sendbuff);
    res = getsockopt(m_socket, SOL_SOCKET, SO_SNDBUF, &sendbuff, &optlen);

    if(res == -1){
        std::cout << "Error getsockopt one\n";
    }

    else {
        std::cout << "send buffer size = " << sendbuff << "\n";
    }

    // Set buffer size
    sendbuff *= 64;

    res = setsockopt(m_socket, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));

    if(res == -1){
        std::cout << "Error setsockopt \n";
    } else {
        std::cout << "sets the send buffer to " <<  sendbuff << "\n";
    }


    uint32_t uint_src_addr = 0;
    int error = inet_pton(AF_INET, src_addr.c_str(), &uint_src_addr);
    if (error != 1){
        perror("inet_pton");
    }

    // Socket stuff

    m_src_addr.sin_family = family;
    m_src_addr.sin_addr.s_addr = uint_src_addr;

    if (bind(m_socket, (struct sockaddr *) &m_src_addr, sizeof(m_src_addr)) < 0) {
        perror("bind");
        exit(1);
    }

    // Raw packet stuff
    std::size_t transport_header_size = 0;
    if (proto == IPPROTO_UDP){
        transport_header_size = sizeof(udphdr);
    } else if (proto == IPPROTO_TCP){
        transport_header_size = sizeof(tcphdr);
    }
    // Buffer size is size of the IP header + size of transport + size of maximum payload
    // We will only send the number of needed bytes for payload.
    uint32_t buffer_size = sizeof(compact_ip_hdr) + transport_header_size + utils::max_ttl + 2;
    m_buffer = reinterpret_cast<uint8_t *>(malloc(buffer_size));
    memset(m_buffer, 0, buffer_size);
    packets_utils::init_ip_header(m_buffer, proto, uint_src_addr);
    if (proto == IPPROTO_UDP){
        // The length depending on the ttl, sets it later
//        packets_utils::init_udp_header(m_buffer + sizeof(compact_ip_hdr), static_cast<uint16_t>(m_payload.size()));
    } else if (proto == IPPROTO_TCP){
        packets_utils::init_tcp_header(m_buffer + sizeof(compact_ip_hdr));
    }


    // Set the payload later
//    char * data = nullptr;
//    data = reinterpret_cast<char *>(m_buffer + sizeof(compact_ip_hdr) + transport_header_size);
//    std::cout << m_payload << std::endl;
//    std::strncpy(data , m_payload.c_str(), m_payload.size());



    /**
     * Ticking for probing rate
     */

#if !(defined(__arm__) || defined(__mips__))
    /* computing usleep delay */
    bool is_valid_frequence = false;
    unsigned long hz = 0;
    for (auto i = 0; i < 10; ++i){

        hz = set_frequence();
        decltype(hz) maximum_frequency = 10000000000; // 10 GHz
        if (hz <= maximum_frequency){
            is_valid_frequence = true;
            break;
        }
    }

    if (!is_valid_frequence){
        std::cerr << "Exiting because of impossible frequency: " << hz << "\n";
        exit(1);
    }
    std::cout << "Estimated CPU freq: "<< (long unsigned int) hz <<  " hz\n";

    auto td = static_cast<double> (hz) / pps;
    std::cout << "1 packet every "<< td <<  " ticks."<< "\n";
    m_tick_delta = static_cast<ticks> (td);
    std::cout << "Rate set to "<<  pps <<  " pps."<< "\n";
    std::cout << "1 packet every "<< m_tick_delta <<  " ticks."<< "\n";
    std::cout << "1 packet every "<< 1.0/m_tick_delta <<  " s."<< "\n";


#endif
}

unsigned long classic_sender_t::set_frequence(){
    auto tick_start = getticks();
    usleep(1);
    auto tick_delta = getticks() - tick_start;

    /* computing CPU freq */
    tick_start = getticks();
    usleep(1001);
    auto hz = (getticks() - tick_start - tick_delta) * 1000; /*kHz -> Hz*/
    return hz;
}

void classic_sender_t::send(int n_packets, uint32_t destination, uint8_t ttl, uint16_t  sport, uint16_t dport) {
    uint32_t time_interval = 5;

    sockaddr_in m_dst_addr;

    m_dst_addr.sin_family = m_family;
    m_dst_addr.sin_addr.s_addr = destination;
    m_dst_addr.sin_port = htons (dport);



//    m_ip_template.dst_addr(IPv4Address(destination));
//    m_ip_template.ttl(ttl);
//    m_ip_template.id(ttl);
//    static_cast<UDP*> (m_ip_template.inner_pdu())->dport(flow_id);

    if (m_n_packets_sent == 0){
        m_tick_start = getticks();
        gettimeofday(&m_now, NULL);
        dump_reference_time();
    }

    // Reset the timestamp if m_now is passed a certain window
    if ((m_now.tv_sec - m_start.tv_sec) >= time_interval){
        dump_reference_time();
    }

    std::size_t transport_header_size = 0;
    if (m_proto == IPPROTO_UDP){
        transport_header_size = sizeof(udphdr);
    } else if (m_proto == IPPROTO_TCP){
        transport_header_size = sizeof(tcphdr);
    }

    // The payload len is the ttl + 2, the +2 is to be able to fully
    // tweak the checksum for the timestamp
    packets_utils::complete_ip_header(m_buffer, destination, ttl, m_proto, ttl + 2);


    // Compute payload len to

    uint16_t buf_size = 0;
    if (m_proto == IPPROTO_UDP){
        uint16_t payload_length = ttl + 2;
        uint16_t udp_length = sizeof(udphdr) + payload_length;

        packets_utils::add_udp_ports(m_buffer + sizeof(ip), sport, dport);
        packets_utils::add_udp_length(m_buffer + sizeof(ip), payload_length);
        packets_utils::add_udp_timestamp(m_buffer + sizeof(ip), m_buffer, payload_length, m_start, m_now);
//        packets_utils::add_transport_checksum(m_buffer + sizeof(ip), m_buffer, m_proto,
//                                              const_cast<char *>(m_payload.c_str()),
//                                              static_cast<uint16_t>(m_payload.size()));
        buf_size = sizeof(compact_ip_hdr) + udp_length;

    }
    else if (m_proto == IPPROTO_TCP){
        packets_utils::add_tcp_ports(m_buffer + sizeof(ip), sport, dport);
        packets_utils::add_tcp_timestamp(m_buffer + sizeof(ip), m_start, m_now, ttl);
        packets_utils::add_transport_checksum(m_buffer + sizeof(ip), m_buffer, m_proto,
                const_cast<char *>(m_payload.c_str()),
                static_cast<uint16_t>(m_payload.size()));

        buf_size = sizeof(compact_ip_hdr) + sizeof(tcphdr) + m_payload.size();
    }

//    Tins::EthernetII test (m_buffer, sizeof(ether_header) + sizeof(ip) + sizeof(udphdr) + m_payload.size());
//    std::cout << test.dst_addr() << ", " << test.src_addr() << "\n";
//    auto ip_pdu = test.find_pdu<IP>();
//    std::cout << ip_pdu->dst_addr() << ", " << ip_pdu->src_addr() << "\n";

//    PacketSender sender (NetworkInterface::default_interface());
//    sender.send(test);

    // Send two packets so that we can spot the eventual per packet LB and anomalies.
    for (int i = 0; i < n_packets; ++i){
        auto tries = 0;
        auto rc = 0;
        while (rc <= 0) {
            if (tries == 10000){
                break;
            }
            rc = sendto(m_socket, m_buffer, buf_size, 0, (const sockaddr*) &m_dst_addr, sizeof(m_dst_addr));
            if (rc <= 0){
                // Buffer full, retry
                ++tries;
//                in_addr ip_addr;
//                ip_addr.s_addr = ip_header->ip_dst;
//                std::cout << "Could not send packet, error code: " << strerror(errno) <<  "\n";
//                std::cout << "The IP destination address is " << inet_ntoa(m_dst_addr.sin_addr) << "\n";
            } else {
                // Control the probing rate with active waiting to be precise
                ++m_n_packets_sent;
                while((getticks() - m_tick_start) < (m_n_packets_sent * m_tick_delta)){
                    // Active wait
                }
            }
            if (m_n_packets_sent >= 100000000){
                // Reset the m_tick_start to avoid the uint64_t multiplication overflow.
                m_n_packets_sent = 0;
                m_tick_start = getticks();
            }
        }

    }

    // Reset the checksum for future computation.
    compact_ip_hdr *ip_header = reinterpret_cast<compact_ip_hdr*>(m_buffer);
    ip_header->ip_sum = 0;

}

void classic_sender_t::set_start_time_log_file(const std::string & ofile) {
    m_start_time_log_file.open(ofile);
    m_start_time_log_file.precision(17);
    std::cout.precision(17);

}

classic_sender_t::~classic_sender_t() {
    m_start_time_log_file.close();
    delete m_buffer;
}

void classic_sender_t::dump_reference_time() {
    gettimeofday(&m_start, NULL);
    double seconds_since_epoch = m_start.tv_sec + static_cast<double>(m_start.tv_usec) / 1000000;

    std::cout << std::fixed << "Start time set to: " << seconds_since_epoch << " seconds since epoch." << std::endl;
    m_start_time_log_file << std::fixed << seconds_since_epoch << std::endl;
}
