#include "sniffer_t.hpp"

#include <boost/log/trivial.hpp>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

namespace fs = std::filesystem;

using Tins::DataLinkType;
using Tins::EthernetII;
using Tins::Packet;
using Tins::Sniffer;
using Tins::SnifferConfiguration;

void sniffer_t::start() {
  BOOST_LOG_TRIVIAL(info) << "Starting sniffer...";
  auto handler = [this](Packet &p) {
    BOOST_LOG_TRIVIAL(trace)
        << "Received packet with timestamp "
        << std::chrono::microseconds{p.timestamp()}.count();
    m_received_count++;
    m_packet_writer.write(p);
    return true;
  };
  m_thread = std::thread([this, handler]() { m_sniffer.sniff_loop(handler); });
}

sniffer_t::sniffer_t(const Tins::NetworkInterface interface,
                     const fs::path ofile, const int buffer_size,
                     const uint16_t destination_port)
    : m_sniffer{interface.name()},
      m_packet_writer{ofile.string(), DataLinkType<EthernetII>()},
      m_received_count{0} {
  std::string filter =
      "icmp or (src port " + std::to_string(destination_port) + ")";
  BOOST_LOG_TRIVIAL(info) << "Sniffer filter: " << filter;

  SnifferConfiguration config;
  config.set_buffer_size(buffer_size * 1024);
  config.set_filter(filter);
  config.set_immediate_mode(true);

  // As sniffer does not have set_configuration, we copy...
  m_sniffer = Sniffer(interface.name(), config);
  m_sniffer.set_extract_raw_pdus(true);
}

void sniffer_t::stop() {
  BOOST_LOG_TRIVIAL(info) << "Stopping the sniffer..." << std::endl;
  m_sniffer.stop_sniff();
  m_thread.join();
}

int sniffer_t::received_count() const { return m_received_count; }
