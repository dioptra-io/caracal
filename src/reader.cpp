#include <spdlog/fmt/fmt.h>
#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>
#include <tins/tins.h>

#include <caracal/parser.hpp>
#include <caracal/reader.hpp>
#include <caracal/statistics.hpp>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

namespace caracal::Reader {

Statistics::Sniffer read(const fs::path& input_file,
                         const fs::path& output_file, const std::string& round,
                         const uint16_t caracal_id,
                         const bool integrity_check) {
  std::ofstream output_csv{output_file};
  Statistics::Sniffer statistics{};
  Tins::FileSniffer sniffer{input_file};

  auto handler = [&](Tins::Packet& packet) {
    auto reply = Parser::parse(packet);

    if (statistics.received_count % 1'000'000 == 0) {
      spdlog::info(statistics);
    }

    if (reply && (!integrity_check || reply->is_valid(caracal_id))) {
      statistics.icmp_messages_all.insert(reply->reply_src_addr);
      if (reply->is_icmp_time_exceeded()) {
        statistics.icmp_messages_path.insert(reply->reply_src_addr);
      }
      output_csv << fmt::format("{},{}\n", reply->to_csv(), round);
    }

    statistics.received_count++;
    return true;
  };

  sniffer.sniff_loop(handler);
  spdlog::info(statistics);
  return statistics;
}

}  // namespace caracal::Reader
