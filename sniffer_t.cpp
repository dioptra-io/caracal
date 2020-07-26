//
// Created by System Administrator on 2019-02-04.
//

#include <thread>
#include <iostream>
#include "sniffer_t.hpp"
#include "parameters_utils_t.hpp"

using namespace Tins;
using namespace utils;
void sniffer_t::start() {
    std::cout << "Starting sniffer...\n";
    auto handler = [this](Packet & p){
//        timeval t;
//        gettimeofday(&t, NULL);
////        std::cout << "Receive time: " << t.tv_sec << "." << t.tv_usec << " seconds since epoch." << "\n";
//
//        auto us = std::chrono::microseconds(p.timestamp()).count();
//        std::cout.precision(17);
//        std::cout << std::fixed << static_cast<double>(us) << " us\n";
        m_packet_writer.write(p);
        return true;
    };
    m_thread = std::thread ([this, handler](){
        m_sniffer.sniff_loop(handler);
    });
}

sniffer_t::sniffer_t(const std::string &interface, const probing_options_t & options, const std::string &ofile) :
m_sniffer{interface},
m_packet_writer{ofile, DataLinkType<EthernetII>()},
m_options{options}
{
    SnifferConfiguration config;
    config.set_immediate_mode(true);
    // 2 Gb buffer size tcpdump like
    config.set_buffer_size(options.buffer_sniffer_size  * 1024);

    

#ifdef NDEBUG
    std::string filter = "icmp or (src port " + std::to_string(m_options.dport) + " )";
    std::cout << "Setting filter: " << filter << std::endl;
    config.set_filter(filter);
#else
    std::string filter = "icmp or port " + std::to_string(m_options.dport);
    std::cout << "Setting filter: " << filter << std::endl;
    config.set_filter(filter);
#endif

    // As sniffer does not have set_configuration, we copy...
    m_sniffer = Sniffer(interface, config);

    m_sniffer.set_extract_raw_pdus(true);
}

void sniffer_t::stop() {
    m_sniffer.stop_sniff();
    m_thread.join();
}
