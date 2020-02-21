//
// Created by System Administrator on 2019-11-04.
//

#include "packets_utils.hpp"
#include "bits_utils_t.hpp"


#include <cstdlib> // malloc
#include <cstring> // memset
#include <cmath> // pow
#include <netinet/ip.h> //ip
//#include <netinet/udp.h> // udphdr
//#include <netinet/tcp.h> //tcphdr
#include <utils/network_utils_t.hpp>
#include <utils/timing_utils.hpp>
#include <net/ethernet.h>

#include <iostream>
#include <chrono>
#include <assert.h>

using namespace Tins;
using namespace utils;

void packets_utils::init_ethernet_header(uint8_t * buffer, int family, const HWAddress<6> & hw_source,
                                         const HWAddress<6> & hw_gateway) {
    auto l2_len = sizeof(ether_header);
    ether_header* ethernet_header = (ether_header *) buffer;

    for (std::size_t i = 0; i < hw_gateway.size(); ++i){
        ethernet_header->ether_dhost[i] = hw_gateway[i];
        ethernet_header->ether_shost[i] = hw_source[i];
    }


    std::cout << "Mac source set to " << hw_source << "\n";
    std::cout << "Mac destination set to " << hw_gateway << "\n";

    if (family == AF_INET6){
        buffer[l2_len-2] = 0x86;
        buffer[l2_len - 1] = 0xDD;
    } else if (family == AF_INET){
        buffer[l2_len-2] = 0x08;
        buffer[l2_len-1] = 0x00;
    }
}

void packets_utils::init_ip_header(uint8_t *buffer, uint8_t ip_proto,
                                   uint32_t uint_src_addr) {
    compact_ip_hdr * ip_header = (compact_ip_hdr * ) (buffer);
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;

//    ip_header->ip_off = htons(0);
//    m_ip_hdr.ip_id = htons(54321);
//    m_ip_hdr.ip_ttl = 64; // hops
    ip_header->ip_p = ip_proto; // Transport protocol

    ip_header->ip_src = uint_src_addr;
}

void packets_utils::init_udp_header(uint8_t *transport_buffer, uint16_t payload_len) {
     udphdr *udp_header = reinterpret_cast<udphdr *> (transport_buffer);
    // Source and destination ports number filled later
    // m_udp_hdr.udph_destport = htons(atoi(argv[4]));
     udp_header->uh_ulen = htons(sizeof(udphdr) + payload_len);
}

void packets_utils::init_tcp_header(uint8_t * transport_buffer) {
    tcphdr * tcp_header = reinterpret_cast<tcphdr *> (transport_buffer);

    tcp_header->th_ack = 0;
    tcp_header->th_off = 5;
    // Do not send TCP SYN because of SYN Flood, do not put any TCP flags
//    tcp_header->th_flags |= TH_SYN;
//    tcp_header->th_flags |= TH_ACK;
    tcp_header->th_x2 = 0;
    tcp_header->th_flags = 0;
    tcp_header->th_win = htons(50);
//    tcp_header->th_chksum = 0; // Fill later
    tcp_header->th_urp = 0;
}

void packets_utils::complete_ip_header(uint8_t *ip_buffer, uint32_t destination, uint8_t ttl, uint8_t proto, uint16_t payload_len) {
    compact_ip_hdr *ip_header = reinterpret_cast<compact_ip_hdr *>(ip_buffer);
    ip_header->ip_dst = destination;
    ip_header->ip_ttl = ttl;
    ip_header->ip_id = htons(ttl);

    // Encode 16 last bits of the IP address in IP checksum to avoid NATs
//    uint16_t lsb_16_destination = n_last_bits(ntohl(destination), 16);
//    ip_header->ip_sum = lsb_16_destination;
//    adjust_payload_len(ip_buffer, lsb_16_destination, proto);

    // Compute the payload length so that it has the good checksum.
        if (proto == IPPROTO_UDP) {
#ifdef __APPLE__

        ip_header->ip_len = sizeof(ip) + sizeof(udphdr) + payload_len;
#else
        ip_header->ip_len = htons(sizeof(ip) + sizeof(udphdr) + payload_len);
#endif
        }
        else if (proto == IPPROTO_TCP) {
#ifdef __APPLE__

        ip_header->ip_len = sizeof(ip) + sizeof(tcphdr) + payload_len;
#else
        ip_header->ip_len = htons(sizeof(ip) + sizeof(tcphdr) + payload_len);
#endif
    }

    // Reset the checksum before computation
    ip_header->ip_sum = 0;

    // Value of the checksum in big endian
    ip_header->ip_sum = wrapsum(in_cksum((unsigned char *) ip_header, sizeof(*ip_header), 0));
}

void packets_utils::adjust_payload_len(uint8_t *ip_buffer, uint16_t checksum, uint8_t proto) {
    uint32_t target_checksum_little_endian = ~ntohs(checksum) & 0xFFFF;
    // Deconstruct the checksum
    // Little endian checksum
    uint32_t wrong_checksum = in_cksum(ip_buffer, sizeof(compact_ip_hdr), 0);

    uint16_t payload_len = 0;
    std::size_t transport_size_header = 0;
    uint32_t c = target_checksum_little_endian;
    if (c < wrong_checksum){
        c += 0xFFFF;
    }
    if (proto == IPPROTO_UDP){
        payload_len = c - wrong_checksum;
        transport_size_header = sizeof(udphdr);
    } else if (proto == IPPROTO_TCP){
        payload_len = c - wrong_checksum;
        transport_size_header = sizeof(tcphdr);
    }

    compact_ip_hdr *ip_header = reinterpret_cast<compact_ip_hdr *>(ip_buffer);
    ip_header->ip_len = htons(payload_len);

    uint16_t new_checksum = wrapsum(in_cksum(ip_buffer, sizeof(compact_ip_hdr), 0));
    assert(checksum == new_checksum);

//    uint8_t * data = ip_buffer + sizeof(compact_ip_hdr) + transport_size_header;
//    payload_len = payload_len - (sizeof(compact_ip_hdr) + transport_size_header);
//    char payload[payload_len];
//    memset(payload, 'A', payload_len);
//    memcpy(data, payload, payload_len);
}

void packets_utils::add_udp_ports(uint8_t *transport_buffer, uint16_t sport, uint16_t dport) {
    udphdr * udp_header = reinterpret_cast<udphdr *> (transport_buffer);

    udp_header->uh_sport = htons(sport);
    udp_header->uh_dport = htons(dport);
}



void packets_utils::add_transport_checksum(uint8_t *transport_buffer, uint8_t *ip_buffer, uint8_t proto, char * payload, uint16_t payload_len) {
    compact_ip_hdr * ip_header = reinterpret_cast<compact_ip_hdr *>(ip_buffer);
    // Calculate the checksum for integrity
    //Now the UDP checksum using the pseudo header
    pseudo_header psh;
    psh.source_address = ip_header->ip_src;
    psh.dest_address = ip_header->ip_dst;
    psh.placeholder = 0;
    psh.protocol = proto;

    if (proto == IPPROTO_UDP){
        udphdr *udp_header = reinterpret_cast<udphdr *> (transport_buffer);
        // Set this field later
        udp_header->uh_sum = 0;
        psh.transport_length = htons(sizeof(struct udphdr) + payload_len);
        // Implementation to avoid memcpy system call
        uint32_t pseudo_header_sum_16 = sum(reinterpret_cast<uint16_t *>(&psh), sizeof(pseudo_header));
        uint32_t udp_header_sum_16 = sum(reinterpret_cast<uint16_t *>(udp_header), sizeof(udphdr));
        uint32_t payload_sum_16 = sum(reinterpret_cast<uint16_t *>(payload), payload_len);
//    udp_header->uh_sum = csum(reinterpret_cast<uint16_t *>(pseudogram) , psize);
        udp_header->uh_sum = one_s_complement_bits32_sum_to_16(pseudo_header_sum_16 + udp_header_sum_16 + payload_sum_16);

        if (udp_header->uh_sum == 0){
            udp_header->uh_sum = 0xFFFF;
        }

    } else if (proto == IPPROTO_TCP){
        tcphdr * tcp_header = reinterpret_cast<tcphdr *> (transport_buffer);
        tcp_header->th_sum = 0;
        psh.transport_length = htons(sizeof(struct tcphdr) + payload_len);
        // Implementation to avoid memcpy system call
        uint32_t pseudo_header_sum_16 = sum(reinterpret_cast<uint16_t *>(&psh), sizeof(pseudo_header));
        uint32_t tcp_header_sum_16 = sum(reinterpret_cast<uint16_t *>(tcp_header), sizeof(tcphdr));
        uint32_t payload_sum_16 = sum(reinterpret_cast<uint16_t *>(payload), payload_len);
//    udp_header->uh_sum = csum(reinterpret_cast<uint16_t *>(pseudogram) , psize);
        tcp_header->th_sum = one_s_complement_bits32_sum_to_16(pseudo_header_sum_16 + tcp_header_sum_16 + payload_sum_16);
    }


//    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + m_payload.size();
//    char pseudogram[psize];
//
//    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
//    memcpy(pseudogram + sizeof(struct pseudo_header) , udp_header , sizeof(struct udphdr) + m_payload.size());



}

void packets_utils::add_tcp_ports(uint8_t *transport_buffer, uint16_t sport, uint16_t dport) {

    tcphdr * tcp_header = reinterpret_cast<tcphdr *> (transport_buffer);
    tcp_header->th_sport = htons(sport);
    tcp_header->th_dport = htons(dport);

}

void packets_utils::add_tcp_timestamp(uint8_t *transport_buffer, timeval &start, timeval &now, uint8_t ttl) {
    tcphdr * tcp_header = reinterpret_cast<tcphdr *> (transport_buffer);

    // Encode the send time in the seq number
    uint32_t time_diff = elapsed(&now, &start);

    // The sequence number is 27 bits of diff time + 5 bits of ttl
    uint32_t msb_ttl = static_cast<uint32_t >(ttl) << 27;

    uint32_t seq_no = time_diff + msb_ttl;

//    if (time_diff < 500){
//        std::cout << "Reset start time: " << start.tv_sec << "." << start.tv_usec << " seconds since epoch." << std::endl;
//        std::cout << time_diff << " " << seq_no << std::endl;
//    }

    tcp_header->th_seq = htonl(seq_no);
}

void packets_utils::add_udp_timestamp(uint8_t *transport_buffer, uint8_t *ip_buffer, timeval &start, timeval &now) {
    std::size_t payload_len = 2;

    udphdr *udp_header = reinterpret_cast<udphdr *> (transport_buffer);

    compact_ip_hdr * ip_header = reinterpret_cast<compact_ip_hdr *>(ip_buffer);
    pseudo_header_udp psh;
    psh.source_address = ip_header->ip_src;
    psh.dest_address = ip_header->ip_dst;
    psh.placeholder = 0;
    psh.transport_length = htons(sizeof(struct udphdr) + payload_len);
    psh.protocol = IPPROTO_UDP;
    psh.uh_sport = udp_header->uh_sport;
    psh.uh_dport = udp_header->uh_dport;
    psh.uh_ulen  = udp_header->uh_ulen;
    psh.uh_sum   = 0;
//    psh.payload  = 0;
    // Encode the send time in the checksum
    uint32_t time_diff = elapsed(&now, &start);
    // Time must be less than 600 s
//    assert(time_diff < std::pow(2, 16) -1);

    uint32_t pseudo_header_sum_16 = in_cksum(reinterpret_cast<uint8_t *>(&psh), sizeof(pseudo_header_udp), 0);

    uint16_t target_checksum = static_cast<uint16_t>(time_diff);
    if (target_checksum == 0){
        udp_header->uh_sum = 0;
        uint16_t * data = reinterpret_cast<uint16_t *>(transport_buffer + sizeof(udphdr));
        *data = 0;
        return;
    }

    uint32_t target_checksum_little_endian = ~ntohs(target_checksum) & 0xFFFF;
    // Deconstruct the checksum
    // Little endian checksum
    uint32_t wrong_checksum = pseudo_header_sum_16;

    uint16_t payload = 0;
    uint32_t c = target_checksum_little_endian;
    if (c < wrong_checksum){
        c += 0xFFFF;
    }

    payload = c - wrong_checksum;

    uint16_t * data = reinterpret_cast<uint16_t *>(transport_buffer + sizeof(udphdr));
    *data = htons(payload);

//    psh.payload = htons(payload);
//
    uint32_t new_checksum = in_cksum(reinterpret_cast<uint8_t *>(&psh), sizeof(pseudo_header_udp), 0);
    new_checksum += payload;
    if (new_checksum > 0xFFFF){
        new_checksum -= 0xFFFF;
    }
    new_checksum = ~new_checksum & 0xFFFF;

    assert(target_checksum == htons(new_checksum));
    udp_header->uh_sum = target_checksum;

}







