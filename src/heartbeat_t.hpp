#pragma once
#include <arpa/inet.h>

#include <boost/log/trivial.hpp>
#include <chrono>
#include <patricia.hpp>
#include <range/v3/all.hpp>

#include "classic_sender_t.hpp"
#include "heartbeat_config.hpp"
#include "probe.hpp"
#include "sniffer_t.hpp"

#ifdef WITH_PF_RING
#include "pfring_sender_t.hpp"
#endif

using std::chrono::duration_cast;
using std::chrono::microseconds;
using std::chrono::milliseconds;
using std::chrono::steady_clock;

void send_heartbeat(const HeartbeatConfig config) {
  BOOST_LOG_TRIVIAL(info) << config;

  // Filter tries, only v4 at the moment.
  Patricia prefix_filter_trie{32};
  Patricia bgp_filter_trie{32};

  if (config.prefix_filter_file) {
    BOOST_LOG_TRIVIAL(info) << "Loading excluded prefixes...";
    prefix_filter_trie.populateBlock(AF_INET,
                                     config.prefix_filter_file.value().c_str());
  }

  if (config.bgp_filter_file) {
    BOOST_LOG_TRIVIAL(info) << "Loading routing informations...";
    bgp_filter_trie.populate(config.bgp_filter_file.value().c_str());
  }

  // Sniffer
  sniffer_t sniffer{config.interface, config.output_file,
                    config.sniffer_buffer_size, 33434};
  sniffer.start();

#ifdef WITH_PF_RING
  pf_ring_sender_t sender{AF_INET, config.protocol, config.interface,
                          config.probing_rate, config.start_time_log_file};
#else
  classic_sender_t sender{AF_INET, config.protocol, config.interface,
                          config.probing_rate, config.start_time_log_file};
#endif

  auto probes_sent = 0;
  auto start_time = steady_clock::now();

  auto log_stats = [&] {
    auto now = steady_clock::now();
    auto delta = duration_cast<microseconds>(now - start_time);
    BOOST_LOG_TRIVIAL(info) << "Sent " << probes_sent << " probes ("
                            << probes_sent * config.n_packets << " packets) in "
                            << delta.count() / (1000.0 * 1000.0) << " seconds ("
                            << (probes_sent * config.n_packets) /
                                   (delta.count() / (1000.0 * 1000.0))
                            << " packets/s)";

    BOOST_LOG_TRIVIAL(info)
        << "Received " << sniffer.received_count() << " packets";
  };

  std::ifstream input_file;
  std::istream& is = config.input_file ? input_file : std::cin;

  if (config.input_file) {
    input_file.open(config.input_file.value());
  } else {
    BOOST_LOG_TRIVIAL(info) << "Reading from stdin, press CTRL+D to stop...";
    std::ios::sync_with_stdio(false);
  }

  // TODO: Cleanup
  // TODO: min/max IP/TTL
  // TODO: Log when filtered (custom filter view)?
  // BOOST_LOG_TRIVIAL(trace) << "Filtered probe " << probe;
  // clang-format off
  auto probes = ranges::getlines(is)
    | ranges::views::transform(Probe::from_csv)
    | ranges::views::take(config.max_probes.value_or(10000000))
    | ranges::views::filter([&](const Probe& p) {
        // Temporary safeguard, until we cleanup packets_utils.
        // "TTL > 32 are not supported, the probe will not be sent: "
        return p.ttl <= 32;
      })
    | ranges::views::filter([&](const Probe& p) {
        // Do not send probes to specified prefixes.
        return prefix_filter_trie.get(p.dst_addr.s_addr) == nullptr;
      })
    | ranges::views::filter([&](const Probe& p) {
        // Do not send probes to un-routed destinations.
        if (config.bgp_filter_file && (bgp_filter_trie.get(p.dst_addr.s_addr) == nullptr)) {
          return false;
        }
        return true;
      });
  // clang-format on

  for (auto probe : probes) {
    BOOST_LOG_TRIVIAL(trace) << "Sending probe " << probe;
    sender.send(probe, config.n_packets);
    probes_sent++;
  }

  // Log preliminary statistics
  log_stats();

  BOOST_LOG_TRIVIAL(info) << "Waiting 5s to allow the sniffer to get the last "
                             "flying responses... Press CTRL+C to exit now.";
  std::this_thread::sleep_for(std::chrono::milliseconds(5000));
  sniffer.stop();

  // Log final statistics
  log_stats();
}
