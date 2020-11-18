#pragma once
#include <arpa/inet.h>

#include <boost/log/trivial.hpp>
#include <chrono>
#include <patricia.hpp>

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

template <typename T>
void send(const HeartbeatConfig config, T probes) {
  BOOST_LOG_TRIVIAL(info) << config;

  // Only v4 at the moment.
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

  auto filter = [&](const Probe& probe) {
    // Do not send probes to specified prefixes.
    if (prefix_filter_trie.get(probe.dst_addr.s_addr) != nullptr) {
      return false;
    }
    // Do not send probes to un-routed destinations.
    if (config.bgp_filter_file &&
        (bgp_filter_trie.get(probe.dst_addr.s_addr) == nullptr)) {
      return false;
    }
    return true;
  };

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

  for (auto probe : probes) {
    if (config.max_probes && (probes_sent >= config.max_probes)) {
      BOOST_LOG_TRIVIAL(info) << "max_probes reached, stopping probing...";
      break;
    }

    if (!filter(probe)) {
      BOOST_LOG_TRIVIAL(trace) << "Filtered probe " << probe;
      continue;
    }

    BOOST_LOG_TRIVIAL(trace) << "Sending probe " << probe;
    sender.send(config.n_packets, probe.dst_addr, probe.ttl, probe.src_port,
                probe.dst_port);

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
