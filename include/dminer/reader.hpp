#pragma once

#include <tins/tins.h>

#include <boost/log/trivial.hpp>
#include <filesystem>
#include <fstream>
#include <string>

#include "parser.hpp"
#include "statistics.hpp"

using Tins::DataLinkType;
using Tins::EthernetII;
using Tins::Packet;

namespace fs = std::filesystem;

namespace dminer {

SnifferStatistics read_packets(const fs::path &input_file,
                               const fs::path &output_file,
                               const std::string &round) {
  std::ofstream output_csv{output_file};
  SnifferStatistics statistics{};
  Tins::FileSniffer sniffer{input_file};

  auto handler = [&output_csv, &round, &statistics](Packet &packet) {
    auto reply = Parser::parse(packet);

    if (statistics.received_count % 1'000'000 == 0) {
      BOOST_LOG_TRIVIAL(info) << statistics;
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
  BOOST_LOG_TRIVIAL(info) << statistics;
  return statistics;
}

}  // namespace dminer
