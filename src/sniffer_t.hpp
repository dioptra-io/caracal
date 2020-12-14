#pragma once

#include <tins/tins.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>
#include <unordered_set>

namespace fs = std::filesystem;

using std::optional;

struct SnifferStatistics {
  uint64_t received_count;
  std::unordered_set<uint32_t> icmp_messages;
};

class sniffer_t {
 public:
  sniffer_t(const Tins::NetworkInterface interface,
            const optional<fs::path> output_file_csv,
            const optional<fs::path> output_file_pcap, const int buffer_size,
            const optional<std::string> meta_round,
            const uint16_t destination_port);
  void start();
  void stop();
  const SnifferStatistics& statistics() const;

 private:
  Tins::Sniffer m_sniffer;
  std::ofstream m_output_csv;
  std::optional<std::string> m_meta_round;
  std::optional<Tins::PacketWriter> m_output_pcap;
  std::thread m_thread;
  SnifferStatistics m_statistics;
};
