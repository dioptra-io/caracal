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
    std::string filter =
        "(icmp and icmp[icmptype] != icmp-echo) or (src port " +
        std::to_string(destination_port) + ")";
    BOOST_LOG_TRIVIAL(info) << "sniffer_filter=" << filter;

    Tins::SnifferConfiguration config;
    config.set_buffer_size(buffer_size * 1024);
    config.set_filter(filter);
    config.set_immediate_mode(true);

    // As sniffer does not have set_configuration, we copy...
    sniffer_ = Tins::Sniffer(interface.name(), config);

    if (output_file_csv) {
      output_csv_.open(output_file_csv.value());
    }

    if (output_file_pcap) {
      output_pcap_ = Tins::PacketWriter{output_file_pcap.value(),
                                        Tins::DataLinkType<Tins::EthernetII>()};
    }
  }

  ~Sniffer() {
    // Cleanup resources in case the sniffer was not properly stopped.
    // For example if an exception was raised on the main thread.
    stop();
  }

  void start() {
    auto handler = [this](Tins::Packet &packet) {
      auto reply = Parser::parse(packet);

      if (reply) {
        auto reply_ = reply.value();
        BOOST_LOG_TRIVIAL(trace)
            << "reply_from=" << reply_.src_ip << " rtt=" << reply_.rtt;
        statistics_.icmp_messages_all.insert(reply_.src_ip);
        if (reply_.src_ip != reply_.inner_dst_ip) {
          statistics_.icmp_messages_path.insert(reply_.src_ip);
        }
        output_csv_ << reply_.to_csv();
        output_csv_ << "," << meta_round_.value_or("1");
        output_csv_ << ",1"
                    << "\n";
      } else {
        statistics_.received_invalid_count++;
      }

      if (output_pcap_) {
        output_pcap_.value().write(packet);
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

  const SnifferStatistics &statistics() const { return statistics_; }

 private:
  Tins::Sniffer sniffer_;
  std::ofstream output_csv_;
  std::optional<std::string> meta_round_;
  std::optional<Tins::PacketWriter> output_pcap_;
  std::thread thread_;
  SnifferStatistics statistics_;
};

}  // namespace dminer
