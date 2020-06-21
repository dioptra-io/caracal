//
// Created by System Administrator on 2019-11-04.
//

#ifndef HEARTBEAT_PACKETS_UTILS_HPP
#define HEARTBEAT_PACKETS_UTILS_HPP

#include <cstdint>
#include <cstddef> // std::size_t
#include <string>
#include <tins/hw_address.h>

class packets_utils {

public:

    /*
     * Ethernet functions
     */
    static void init_ethernet_header(uint8_t * buffer, int family, const Tins::HWAddress<6> & hw_source,
                                     const Tins::HWAddress<6> & hw_gateway);
    /*
     * IP functions
     */
    static void init_ip_header(uint8_t *buffer, uint8_t ip_proto,
                               uint32_t uint_src_addr);
    static void complete_ip_header(uint8_t *ip_buffer, uint32_t destination, uint8_t ttl, uint8_t proto, uint16_t payload_len);
    static void adjust_payload_len(uint8_t * ip_buffer, uint16_t checksum, uint8_t proto);

    /*
     * UDP functions
     */
    static void init_udp_header(uint8_t *transport_buffer, uint16_t payload_len);
    static void add_udp_length(uint8_t *transport_buffer, uint16_t payload_length);
    static void add_udp_ports(uint8_t *transport_buffer, uint16_t sport, uint16_t dport);

    static void add_transport_checksum(uint8_t *transport_buffer, uint8_t *ip_buffer, uint8_t  proto,
            char * payload,
            uint16_t payload_len);

    static void add_udp_timestamp(uint8_t * transport_buffer, uint8_t *ip_buffer, std::size_t payload_len, timeval & start, timeval & now);

    /*
     * TCP functions
     */
    static void init_tcp_header(uint8_t *transport_buffer);
    static void add_tcp_ports(uint8_t *transport_buffer, uint16_t sport, uint16_t dport);
    static void add_tcp_timestamp(uint8_t * transport_buffer, timeval & start, timeval & now, uint8_t ttl);
};


#endif //HEARTBEAT_PACKETS_UTILS_HPP
