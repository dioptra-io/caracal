#pragma once

#include <tins/tins.h>

#include <atomic>
#include <filesystem>
#include <string>
#include <thread>

namespace fs = std::filesystem;

class sniffer_t {
 public:
  sniffer_t(const Tins::NetworkInterface interface, const fs::path ofile,
            const int buffer_size, const uint16_t destination_port);
  void start();
  void stop();
  int received_count() const;

 private:
  Tins::Sniffer m_sniffer;
  Tins::PacketWriter m_packet_writer;
  std::thread m_thread;
  std::atomic<int> m_received_count;
};
