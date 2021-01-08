#pragma once

#include <boost/log/trivial.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "packet_parser.hpp"
#include "statistics.hpp"

namespace fs = std::filesystem;

using Tins::DataLinkType;
using Tins::EthernetII;
using Tins::Packet;
using Tins::PacketWriter;
using Tins::SnifferConfiguration;

class Sniffer {
 public:
  Sniffer(const Tins::NetworkInterface interface,
          const optional<fs::path> output_file_csv,
          const optional<fs::path> output_file_pcap, const uint64_t buffer_size,
          const optional<std::string> meta_round,
          const uint16_t destination_port)
      : m_sniffer{interface.name()}, m_meta_round{meta_round}, m_statistics{} {
    std::string filter =
        "icmp or (src port " + std::to_string(destination_port) + ")";
    BOOST_LOG_TRIVIAL(info) << "Sniffer filter: " << filter;

    SnifferConfiguration config;
    config.set_buffer_size(buffer_size * 1024);
    config.set_filter(filter);
    config.set_immediate_mode(true);

    // As sniffer does not have set_configuration, we copy...
    m_sniffer = Tins::Sniffer(interface.name(), config);
    // m_sniffer.set_extract_raw_pdus(true);

    if (output_file_csv) {
      m_output_csv.open(output_file_csv.value());
    }

    if (output_file_pcap) {
      m_output_pcap = Tins::PacketWriter{output_file_pcap.value(),
                                         DataLinkType<EthernetII>()};
    }
  }

  ~Sniffer() {
    // Cleanup resources in case the sniffer was not properly stopped.
    // For example if an exception was raised on the main thread.
    stop();
  }

  void start() {
    BOOST_LOG_TRIVIAL(info) << "Starting sniffer...";
    // TODO: Benchmark utility of batching/batch size.

    auto handler = [this](Packet& packet) {
      auto reply = parse(packet);

      if (reply) {
        auto reply_ = reply.value();
        BOOST_LOG_TRIVIAL(trace)
            << "Received ICMP message from " << reply_.src_ip;
        m_statistics.icmp_messages_all.insert(reply_.src_ip);
        if (reply_.src_ip != reply_.inner_dst_ip) {
          m_statistics.icmp_messages_path.insert(reply_.src_ip);
        }
        m_output_csv << reply_.to_csv();
        m_output_csv << "," << m_meta_round.value_or("1");
        m_output_csv << ",1"
                     << "\n";
      }

      if (m_output_pcap) {
        m_output_pcap.value().write(packet);
      }

      m_statistics.received_count++;
      return true;
    };

    m_thread =
        std::thread([this, handler]() { m_sniffer.sniff_loop(handler); });
  }

  void stop() noexcept {
    if (m_thread.joinable()) {
      m_sniffer.stop_sniff();
      m_thread.join();
    }
  }

  const SnifferStatistics& statistics() const { return m_statistics; }

 private:
  Tins::Sniffer m_sniffer;
  std::ofstream m_output_csv;
  std::optional<std::string> m_meta_round;
  std::optional<Tins::PacketWriter> m_output_pcap;
  std::thread m_thread;
  SnifferStatistics m_statistics;
};
