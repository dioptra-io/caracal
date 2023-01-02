#include <spdlog/fmt/fmt.h>
#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>
#include <tins/tins.h>

#include <bxzstr/bxzstr.hpp>
#include <caracal/parser.hpp>
#include <caracal/sniffer.hpp>
#include <caracal/statistics.hpp>
#include <caracal/utilities.hpp>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <optional>
#include <thread>

namespace fs = std::filesystem;

namespace caracal {

Sniffer::Sniffer(const std::string &interface_name,
                 const std::optional<fs::path> &output_file_csv,
                 const std::optional<fs::path> &output_file_pcap,
                 const std::optional<std::string> &meta_round,
                 const uint16_t caracal_id, const bool integrity_check)
    : sniffer_{interface_name},
      meta_round_{meta_round},
      statistics_{},
      caracal_id_{caracal_id},
      integrity_check_{integrity_check} {
  Tins::NetworkInterface interface { interface_name };

  auto filter =
      "(ip and icmp and ("
      "icmp[icmptype] = icmp-echoreply or "
      "icmp[icmptype] = icmp-timxceed or "
      "icmp[icmptype] = icmp-unreach))"
      " or "
      "(ip6 and icmp6 and ("
      "icmp6[icmp6type] = icmp6-echoreply or "
      "icmp6[icmp6type] = icmp6-timeexceeded or "
      "icmp6[icmp6type] = icmp6-destinationunreach))";
  spdlog::info("sniffer_filter={}", filter);

  Tins::SnifferConfiguration config;
  // A buffer of 64M is enough to store ~1M ICMPv6 Time Exceeded replies.
  // We probably don't need as much but this lets us handle burst of incoming
  // packets.
  config.set_buffer_size(64 * 1024 * 1024);
  // Filter as much as possible at the kernel level.
  // We're only interested in incoming ICMP packets.
  config.set_direction(PCAP_D_IN);
  config.set_filter(filter);
  // `timeout` has two uses here:
  // 1. Batch deliveries from pcap to reduce syscall overhead
  //    See "packet buffer timeout" in PCAP(3PCAP) man page.
  //    See also section 26.2 "BSD Packet Filter" in "Unix Network Programming
  //    vol. 1".
  // 2. Allow us to break the capture loop through the `stopped` variable.
  // This has no impact of RTT computation as packets are timestamped as soon as
  // they are captured by pcap.
  config.set_timeout(100);
  sniffer_ = Tins::Sniffer(interface_name, config);

  if (output_file_csv) {
    if (output_file_csv->extension() == ".zst") {
      output_csv_ = std::make_unique<bxz::ofstream>(*output_file_csv,
                                                    bxz::Compression::zstd, 1);
    } else {
      output_csv_ = std::make_unique<std::ofstream>(*output_file_csv);
    }
  } else {
    output_csv_ = std::make_unique<std::ostream>(std::cout.rdbuf());
  }

  if (output_file_pcap) {
    output_pcap_ = Tins::PacketWriter{*output_file_pcap,
                                      Tins::DataLinkType<Tins::EthernetII>()};
  }
}

Sniffer::~Sniffer() {
  // Cleanup resources in case the sniffer was not properly stopped.
  // For example if an exception was raised on the main thread.
  stop();
}

void Sniffer::start() noexcept {
  *output_csv_ << Reply::csv_header() << "\n";
  auto handler = [this](Tins::Packet &packet) {
    auto reply = Parser::parse(packet);

    if (reply && (!integrity_check_ || reply->is_valid(caracal_id_))) {
      spdlog::trace(reply.value());
      statistics_.icmp_messages_all.insert(reply->reply_src_addr);
      if (reply->is_time_exceeded()) {
        statistics_.icmp_messages_path.insert(reply->reply_src_addr);
      }
      *output_csv_ << reply->to_csv(meta_round_.value_or("1")) << "\n";
    } else {
      auto data = packet.pdu()->serialize();
      spdlog::trace("invalid_packet_hex={:02x}", fmt::join(data, ""));
      statistics_.received_invalid_count++;
    }

    if (output_pcap_) {
      output_pcap_->write(packet);
    }

    statistics_.received_count++;
    return true;
  };

  thread_ = std::thread([this, handler]() { sniffer_.sniff_loop(handler); });
}

void Sniffer::stop() noexcept {
  if (thread_.joinable()) {
    sniffer_.stop_sniff();
    thread_.join();
  }
}

const Statistics::Sniffer &Sniffer::statistics() const noexcept {
  return statistics_;
}

pcap_stat Sniffer::pcap_statistics() noexcept {
  pcap_stat ps{};
  pcap_stats(sniffer_.get_pcap_handle(), &ps);
  return ps;
}

}  // namespace caracal
