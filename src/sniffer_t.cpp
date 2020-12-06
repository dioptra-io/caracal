#include "sniffer_t.hpp"

#include <boost/log/trivial.hpp>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

namespace fs = std::filesystem;

using Tins::DataLinkType;
using Tins::EthernetII;
using Tins::ICMP;
using Tins::IP;
using Tins::Packet;
using Tins::PDU;
using Tins::Sniffer;
using Tins::SnifferConfiguration;

void sniffer_t::start() {
  BOOST_LOG_TRIVIAL(info) << "Starting sniffer...";
  auto handler = [this](Packet& packet) {
    // TODO: Full packet parsing/CSV here (performance?)
    try {
      PDU* pdu = packet.pdu();
      if (pdu) {
        const IP& ip = pdu->rfind_pdu<IP>();
        const ICMP& icmp = pdu->rfind_pdu<ICMP>();
        if (icmp.type() == ICMP::TIME_EXCEEDED ||
            icmp.type() == ICMP::DEST_UNREACHABLE) {
          auto src_addr = ip.src_addr();
          BOOST_LOG_TRIVIAL(trace) << "Received ICMP message from " << src_addr;
          m_statistics.icmp_messages.insert(uint32_t(src_addr));
        }
      }
    } catch (const Tins::pdu_not_found& e) {
      BOOST_LOG_TRIVIAL(trace) << "PDU not found: " << e.what();
    }

    m_statistics.received_count++;
    m_packet_writer.write(packet);
    return true;
  };
  m_thread = std::thread([this, handler]() { m_sniffer.sniff_loop(handler); });
}

sniffer_t::sniffer_t(const Tins::NetworkInterface interface,
                     const fs::path ofile, const int buffer_size,
                     const uint16_t destination_port)
    : m_sniffer{interface.name()},
      m_packet_writer{ofile.string(), DataLinkType<EthernetII>()},
      m_statistics{} {
  std::string filter =
      "icmp or (src port " + std::to_string(destination_port) + ")";
  BOOST_LOG_TRIVIAL(info) << "Sniffer filter: " << filter;

  SnifferConfiguration config;
  config.set_buffer_size(buffer_size * 1024);
  config.set_filter(filter);
  config.set_immediate_mode(true);

  // As sniffer does not have set_configuration, we copy...
  m_sniffer = Sniffer(interface.name(), config);
  // m_sniffer.set_extract_raw_pdus(true);
}

void sniffer_t::stop() {
  BOOST_LOG_TRIVIAL(info) << "Stopping the sniffer..." << std::endl;
  m_sniffer.stop_sniff();
  m_thread.join();
}

int sniffer_t::received_count() const { return m_statistics.received_count; }
int sniffer_t::icmp_distinct_count() const {
  return m_statistics.icmp_messages.size();
}
