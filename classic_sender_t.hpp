//
// Created by System Administrator on 2019-01-31.
//

#ifndef HEARTBEAT_CLASSIC_SENDER_T_HPP
#define HEARTBEAT_CLASSIC_SENDER_T_HPP

#include <netinet/in.h>
#include <sys/socket.h>
#include <string>
#include <tins/tins.h>
#include <vector>
#include <fstream>

class classic_sender_t {

public:

    classic_sender_t(uint8_t family, int type, uint8_t proto, const std::string & src_addr, const uint32_t pps);
    void send(int n_packets, uint32_t destination, uint8_t ttl, uint16_t sport, uint16_t dport);

    void set_start_time_log_file(const std::string &ofile);

    ~classic_sender_t();

private:
    void dump_reference_time();

    int         m_socket;
    uint8_t     m_family;
    uint8_t     m_proto;
    sockaddr_in m_src_addr;
    sockaddr_in m_dst_addr;
    uint8_t *   m_buffer;
    std::string m_payload;
    uint64_t    m_n_packets_sent;
    uint64_t    m_tick_delta;
    uint64_t    m_tick_start;

    timeval     m_start;
    timeval     m_now;

    std::ofstream m_start_time_log_file;

};


#endif //HEARTBEAT_SENDER_T_HPP
