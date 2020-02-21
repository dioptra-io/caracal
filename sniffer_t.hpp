//
// Created by System Administrator on 2019-02-04.
//

#ifndef HEARTBEAT_SNIFFER_T_HPP
#define HEARTBEAT_SNIFFER_T_HPP
#include <tins/tins.h>
#include <string>
#include <thread>
#include <probing_options_t.hpp>

class sniffer_t {
public:
    sniffer_t (const std::string & interface, const probing_options_t & options, const std::string & ofile);
    void start();
    void stop();
private:
    Tins::Sniffer m_sniffer;
    Tins::PacketWriter m_packet_writer;
    std::thread m_thread;
    probing_options_t m_options;
};


#endif //HEARTBEAT_SNIFFER_T_HPP
