#pragma once

#include <string>
#include <tins/tins.h>
#include <pfring.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <fstream>

class pf_ring_sender_t {
public:
    pf_ring_sender_t(int family, int type, uint8_t proto,
                     const Tins::NetworkInterface & iface,
                     const Tins::HWAddress<6> & hw_source,
                     const Tins::HWAddress<6> & hw_addr_gateway,
                     const uint32_t pps);

    void send(int n_packets, uint32_t destination, uint8_t ttl, uint16_t  sport, uint16_t dport);


    void set_start_time_log_file(const std::string &ofile);
    ~pf_ring_sender_t();

private:
    unsigned long set_frequence();
    void dump_reference_time();

    pfring * m_pf_ring;
    int m_family;
    uint8_t m_proto;
    std::string m_payload;
    uint8_t* m_buffer;
    uint64_t m_n_packets_sent;

    uint64_t m_tick_delta;
    uint64_t m_tick_start;

    timeval     m_start;
    timeval     m_now;

    std::ofstream m_start_time_log_file;
};