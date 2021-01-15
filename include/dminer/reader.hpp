#pragma once

#include <tins/tins.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "logging.hpp"
#include "parser.hpp"
#include "statistics.hpp"

namespace fs = std::filesystem;

/// Read and convert PCAP files.
namespace dminer::Reader {

Statistics::Sniffer read(const fs::path &input_file,
                         const fs::path &output_file,
                         const std::string &round) {
  std::ofstream output_csv{output_file};
  Statistics::Sniffer statistics{};
  Tins::FileSniffer sniffer{input_file};

  auto handler = [&output_csv, &round, &statistics](Tins::Packet &packet) {
    auto reply = Parser::parse(packet);

    if (statistics.received_count % 1'000'000 == 0) {
      LOG(info, statistics);
    }

    if (reply) {
      auto reply_ = reply.value();
      statistics.icmp_messages_all.insert(reply_.src_ip);
      if (reply_.src_ip != reply_.inner_dst_ip) {
        statistics.icmp_messages_path.insert(reply_.src_ip);
      }
      output_csv << reply_.to_csv() << "," << round << ",1"
                 << "\n";
    }

    statistics.received_count++;
    return true;
  };

  sniffer.sniff_loop(handler);
  LOG(info, statistics);
  return statistics;
}

}  // namespace dminer::Reader
