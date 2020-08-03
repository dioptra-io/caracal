//
// Created by System Administrator on 2019-03-18.
//

#include <sys/socket.h>
#include <arpa/inet.h>
#include <utils/timing_utils.hpp>
#include <utils/packets_utils.hpp>
#include <utils/network_utils_t.hpp>

#include <pfring_sender_t.hpp>
#include <cerrno>
#include <iostream>

//#include <netinet/udp.h> // udphdr
#include <netinet/ip.h> // ip
#include <utils/parameters_utils_t.hpp>
//#include <netinet/tcp.h> //tcph

using namespace utils;

using namespace Tins;
using namespace utils;

pf_ring_sender_t::pf_ring_sender_t(int family, int type, uint8_t proto,
        const NetworkInterface & iface,
        const HWAddress<6> & hw_source,
        const HWAddress<6> & hw_gateway,
        const uint32_t pps):
m_family{family},
m_proto{proto},
m_payload("fr"),
m_n_packets_sent{0}
//, m_payload("kevin.vermeulen@sorbonne-universite.fr")
{

    /**
     * Open pfring
     */


    m_pf_ring = pfring_open(iface.name().c_str(), 1500, 0 /* PF_RING_PROMISC */);
    if(m_pf_ring == NULL) {
        printf("pfring_open error [%s] (pf_ring not loaded or interface %s is down ?)\n",
               strerror(errno), iface.name().c_str());
    } else {
        u_int32_t version;

        pfring_set_application_name(m_pf_ring, "pfsend");
        pfring_version(m_pf_ring, &version);

        printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16,
               (version & 0x0000FF00) >> 8, version & 0x000000FF);
    }

    pfring_set_socket_mode(m_pf_ring, send_only_mode);

    if(pfring_enable_ring(m_pf_ring) != 0) {
        printf("Unable to enable ring :-(\n");
        pfring_close(m_pf_ring);
    }

    uint32_t uint_src_addr = 0;
    int error = inet_pton(AF_INET, iface.ipv4_address().to_string().c_str(), &uint_src_addr);
    if (error != 1){
        perror("inet_pton");
    }

    // Check that the PDU is well formed.

//    Tins::EthernetII test (m_buffer, sizeof(ether_header) + sizeof(ip) + sizeof(udphdr) + m_payload.size());
//    std::cout << test.dst_addr() << ", " << test.src_addr() << "\n";
//    auto ip_pdu = test.find_pdu<IP>();
//    std::cout << ip_pdu->dst_addr() << ", " << ip_pdu->src_addr() << "\n";

// Raw packet stuff
    std::size_t transport_header_size = 0;
    if (proto == IPPROTO_UDP){
        transport_header_size = sizeof(udphdr);
    } else if (proto == IPPROTO_TCP){
        transport_header_size = sizeof(tcphdr);
    }
    // Buffer size is size of the IP header + size of transport + size of maximum payload
    // We will only send the number of needed bytes for payload.
    uint32_t buffer_size = sizeof(ether_header) + sizeof(compact_ip_hdr) + transport_header_size + utils::max_ttl + 2;
    m_buffer = reinterpret_cast<uint8_t *>(malloc(buffer_size));
    memset(m_buffer, 0, buffer_size);
    packets_utils::init_ethernet_header(m_buffer, family, hw_source, hw_gateway);
    packets_utils::init_ip_header(m_buffer + sizeof(ether_header), proto, uint_src_addr);




    // Raw packet stuff
    if (proto == IPPROTO_UDP){
//        packets_utils::init_udp_header(m_buffer + sizeof(ether_header) + sizeof(compact_ip_hdr),
//                                       static_cast<uint16_t>(m_payload.size()));
    } else if (proto == IPPROTO_TCP){
        packets_utils::init_tcp_header(m_buffer + sizeof(ether_header) + sizeof(compact_ip_hdr));
    }

    // Compute the tickdelta to control the probing rate.


#if !(defined(__arm__) || defined(__mips__))
    /* computing usleep delay */
    auto tick_start = getticks();
    usleep(1);
    auto tick_delta = getticks() - tick_start;

    /* computing CPU freq */
    tick_start = getticks();
    usleep(1001);
    auto hz = (getticks() - tick_start - tick_delta) * 1000 /*kHz -> Hz*/;
    std::cout << "Estimated CPU freq: "<< (long unsigned int)hz << "\n";



    auto td = static_cast<double> (hz) / pps;
    m_tick_delta = static_cast<ticks> (td);
    std::cout << "Delta ticks set to "<<  m_tick_delta << " ticks \n";
    std::cout << "Rate set to "<<  pps <<  " pps."<< "\n";


#endif
}



void pf_ring_sender_t::send(int n_packets, uint32_t destination, uint8_t ttl, uint16_t sport, uint16_t dport) {
    static uint32_t n_interval = 0;
    uint32_t time_interval = 5;
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

    if (m_n_packets_sent == 0){
        m_tick_start = getticks();
        gettimeofday(&m_start, NULL);
        //std::cout << "Start time set to: " << m_start.tv_sec << "." << m_start.tv_usec << " seconds since epoch." << "\n";
        m_start_time_log_file << m_start.tv_sec << "." << m_start.tv_usec << std::endl;
    }

    if ((m_now.tv_sec - m_start.tv_sec) >= time_interval){
//        if (m_n_packets_sent > n_interval * time_interval * packets_per_second_threshold){
//            std::cout << "Error rate is above the limit" << std::endl;
//            std::cout << m_n_packets_sent << " packets sent." <<  std::endl;
//            std::cout << n_interval * time_interval * packets_per_second_threshold << " theoretical packets sent." <<  std::endl;
//            if (m_n_packets_sent > 1.5 * n_interval * time_interval * packets_per_second_threshold){
//                exit(1);
//            }
//        }
//        std::cout << m_n_packets_sent << std::endl;
//        std::cout << getticks() << " ticks." << std::endl;
//        std::cout << m_n_packets_sent << " packets sent." <<  std::endl;
//        std::cout << n_interval * time_interval * packets_per_second_threshold << " theoretical packets sent." <<  std::endl;
//        ++n_interval;
        dump_reference_time();
    }

    std::size_t transport_header_size = 0;
    if (m_proto == IPPROTO_UDP){
        transport_header_size = sizeof(udphdr);
    } else if (m_proto == IPPROTO_TCP){
        transport_header_size = sizeof(tcphdr);
    }

    packets_utils::complete_ip_header(m_buffer + sizeof(ether_header), destination, ttl, m_proto, ttl + 2);


    uint16_t buf_size = 0;
    if (m_proto == IPPROTO_UDP){

        uint16_t payload_length = ttl + 2;
        uint16_t udp_length = sizeof(udphdr) + payload_length;

        packets_utils::add_udp_ports(m_buffer + sizeof(ether_header) +  sizeof(ip), sport, dport);
        packets_utils::add_udp_length(m_buffer + sizeof(ether_header) + sizeof(ip), payload_length);
        packets_utils::add_udp_timestamp(m_buffer + sizeof(ether_header) + sizeof(ip),
                m_buffer  + sizeof(ether_header),
                payload_length,
                m_start, m_now);
//        packets_utils::add_transport_checksum(m_buffer + sizeof(ip), m_buffer, m_proto,
//                                              const_cast<char *>(m_payload.c_str()),
//                                              static_cast<uint16_t>(m_payload.size()));
        buf_size = sizeof (ether_header) + sizeof(compact_ip_hdr) + udp_length;
    }
    else if (m_proto == IPPROTO_TCP){
        packets_utils::add_tcp_ports(m_buffer + sizeof(ether_header) + sizeof(ip), sport, dport);
        packets_utils::add_tcp_timestamp(m_buffer + sizeof(ether_header) + sizeof(ip), m_start, m_now, ttl);
        packets_utils::add_transport_checksum(m_buffer + sizeof(ether_header) + sizeof(ip), m_buffer + sizeof(ether_header), m_proto,
                                              const_cast<char *>(m_payload.c_str()),
                                              static_cast<uint16_t>(m_payload.size()));

        buf_size = sizeof(ether_header) + sizeof(compact_ip_hdr) + sizeof(tcphdr) + m_payload.size();
    }



//    Tins::EthernetII test (m_buffer, sizeof(ether_header) + sizeof(ip) + sizeof(udphdr) + m_payload.size());
//    std::cout << test.dst_addr() << ", " << test.src_addr() << "\n";
//    auto ip_pdu = test.find_pdu<IP>();
//    std::cout << ip_pdu->dst_addr() << ", " << ip_pdu->src_addr() << "\n";

//    PacketSender sender (NetworkInterface::default_interface());
//    sender.send(test);

    // Send n_packets so that we can spot the eventual per packet LB and anomalies.
    for (int i = 0; i < n_packets; ++i){
        auto rc = 0;
        while (rc <= 0) {
            rc = pfring_send(m_pf_ring, (char *) m_buffer, buf_size, 0);
            if (rc <= 0){
                // Buffer full, retry
//                in_addr ip_addr;
//                ip_addr.s_addr = ip_header->ip_dst;
                std::cerr << "Could not send packet, error code: " << strerror(errno) <<  "\n";
//                std::cerr << "The IP destination address is " << inet_ntoa(ip_addr) << "\n";
            } else {
                // Control the probing rate with active waiting to be precise
                ++m_n_packets_sent;
                while((getticks() - m_tick_start) < (m_n_packets_sent * m_tick_delta)){
                    // Active wait
                }
            }
        }

        if (m_n_packets_sent >= 100000000){
            // Reset the m_tick_start to avoid the uint64_t multiplication overflow.
            m_n_packets_sent = 0;
            m_tick_start = getticks();
        }

        if (rc == PF_RING_ERROR_INVALID_ARGUMENT) {
            printf("Attempting to send invalid packet [len: %u][MTU: %u]\n",
                   static_cast<unsigned int>(buf_size), m_pf_ring->mtu);
        }
    }


//    if (unlikely(verbose))
//        printf("[%d] pfring_send(%d) returned %d\n", i, tosend->len, rc);

    // Reset the checksum for future computation.
    compact_ip_hdr *ip_header = (compact_ip_hdr *) (m_buffer + sizeof(ether_header));
    ip_header->ip_sum = 0;


}

void pf_ring_sender_t::set_start_time_log_file(const std::string &ofile) {
    m_start_time_log_file.open(ofile);
    m_start_time_log_file.precision(17);
    std::cout.precision(17);
}

pf_ring_sender_t::~pf_ring_sender_t() {
    delete m_buffer;
    pfring_close(m_pf_ring);
}

void pf_ring_sender_t::dump_reference_time() {
    gettimeofday(&m_start, NULL);
    double seconds_since_epoch = m_start.tv_sec + static_cast<double>(m_start.tv_usec) / 1000000;

    std::cout << std::fixed << "Start time set to: " << seconds_since_epoch << " seconds since epoch." << std::endl;
    m_start_time_log_file << std::fixed << seconds_since_epoch << std::endl;
}
