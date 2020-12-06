#pragma once

#include <tins/tins.h>

#include <atomic>
#include <filesystem>
#include <string>
#include <thread>
#include <unordered_set>

namespace fs = std::filesystem;

struct SnifferStatistics {
  std::unordered_set<uint32_t> icmp_messages;
  unsigned long long int received_count;
};

class sniffer_t {
 public:
  sniffer_t(const Tins::NetworkInterface interface, const fs::path ofile,
            const int buffer_size, const uint16_t destination_port);
  void start();
  void stop();
  int received_count() const;
  int icmp_distinct_count() const;

 private:
  Tins::Sniffer m_sniffer;
  Tins::PacketWriter m_packet_writer;
  std::thread m_thread;
  SnifferStatistics m_statistics;
};
