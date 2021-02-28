#pragma once

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>

#include "statistics.hpp"

namespace fs = std::filesystem;

namespace dminer {

class Sniffer {
 public:
  Sniffer(const Tins::NetworkInterface &interface,
          const std::optional<fs::path> &output_file_csv,
          const std::optional<fs::path> &output_file_pcap, uint64_t buffer_size,
          const std::optional<std::string> &meta_round,
          uint16_t destination_port);

  ~Sniffer();

  void start() noexcept;

  void stop() noexcept;

  [[nodiscard]] const Statistics::Sniffer &statistics() const noexcept;

 private:
  Tins::Sniffer sniffer_;
  std::ofstream output_csv_;
  std::optional<std::string> meta_round_;
  std::optional<Tins::PacketWriter> output_pcap_;
  std::thread thread_;
  Statistics::Sniffer statistics_;
};

}  // namespace dminer
