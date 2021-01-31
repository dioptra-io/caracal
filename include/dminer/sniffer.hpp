#pragma once

#include <spdlog/fmt/fmt.h>
#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "parser.hpp"
#include "statistics.hpp"

namespace fs = std::filesystem;

namespace dminer {

class Sniffer {
 public:
  Sniffer(const Tins::NetworkInterface &interface,
          const optional<fs::path> &output_file_csv,
          const optional<fs::path> &output_file_pcap,
          const uint64_t buffer_size, const optional<std::string> &meta_round,
          const uint16_t destination_port)
      : sniffer_{interface.name()}, meta_round_{meta_round}, statistics_{} {
    auto filter = fmt::format(
        "(dst {} or dst {}) and ((icmp and icmp[icmptype] != icmp-echo) or "
        "(icmp6 and icmp6[icmptype] != icmp-echo) or "
        "(src port {}))",
        Utilities::source_ipv4_for(interface).to_string(),
        Utilities::source_ipv6_for(interface).to_string(), destination_port);
    spdlog::info("sniffer_filter={}", filter);

    Tins::SnifferConfiguration config;
    config.set_buffer_size(buffer_size);
    config.set_filter(filter);
    config.set_immediate_mode(true);

    // As sniffer does not have set_configuration, we copy...
    sniffer_ = Tins::Sniffer(interface.name(), config);

    if (output_file_csv) {
      output_csv_.open(*output_file_csv);
    }

    if (output_file_pcap) {
      output_pcap_ = Tins::PacketWriter{*output_file_pcap,
                                        Tins::DataLinkType<Tins::EthernetII>()};
    }
  }

  ~Sniffer() {
    // Cleanup resources in case the sniffer was not properly stopped.
    // For example if an exception was raised on the main thread.
    stop();
  }

  void start() noexcept {
    auto handler = [this](Tins::Packet &packet) {
      auto reply = Parser::parse(packet);

      if (reply) {
        spdlog::trace("reply_from={} rtt={}", reply->src_ip, reply->rtt);
        statistics_.icmp_messages_all.insert(reply->src_ip);
        if (reply->src_ip != reply->inner_dst_ip) {
          statistics_.icmp_messages_path.insert(reply->src_ip);
        }
        output_csv_ << fmt::format("{},{},{}\n", reply->to_csv(),
                                   meta_round_.value_or("1"), "1");
      } else {
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

  void stop() noexcept {
    if (thread_.joinable()) {
      sniffer_.stop_sniff();
      thread_.join();
    }
  }

  [[nodiscard]] const Statistics::Sniffer &statistics() const {
    return statistics_;
  }

 private:
  Tins::Sniffer sniffer_;
  std::ofstream output_csv_;
  std::optional<std::string> meta_round_;
  std::optional<Tins::PacketWriter> output_pcap_;
  std::thread thread_;
  Statistics::Sniffer statistics_;
};

}  // namespace dminer
