#pragma once

#include <boost/log/trivial.hpp>
#include <chrono>
#include <memory>
#include <patricia.hpp>
#include <string>
#include <tuple>

#include "probe.hpp"
#include "prober_config.hpp"
#include "rate_limiter.hpp"
#include "sender.hpp"
#include "sniffer.hpp"
#include "statistics.hpp"

/// Build and send probes.
namespace dminer::Prober {

typedef std::tuple<ProberStatistics, SnifferStatistics> Statistics;

inline Statistics probe(const Config& config) {
  BOOST_LOG_TRIVIAL(info) << config;

  // Test the rate limiter
  BOOST_LOG_TRIVIAL(info)
      << "Testing the rate limiter, this should take ~1s... If it takes too "
         "long try to reduce the probing rate.";
  if (!RateLimiter::test(config.probing_rate)) {
    BOOST_LOG_TRIVIAL(warning)
        << "Unable to achieve the target probing rate, either the system clock "
           "resolution is insufficient, or the probing rate is too high for "
           "the system.";
  }

  // Filter tries, only v4 at the moment
  Patricia prefix_excl_trie{32};
  Patricia prefix_incl_trie{32};

  if (config.prefix_excl_file) {
    BOOST_LOG_TRIVIAL(info) << "Loading excluded prefixes...";
    prefix_excl_trie.populateBlock(AF_INET,
                                   config.prefix_excl_file.value().c_str());
  }

  if (config.prefix_incl_file) {
    BOOST_LOG_TRIVIAL(info) << "Loading included prefixes...";
    prefix_incl_trie.populateBlock(AF_INET,
                                   config.prefix_incl_file.value().c_str());
  }

  // Sniffer
  Sniffer sniffer{config.interface,        config.output_file_csv,
                  config.output_file_pcap, config.sniffer_buffer_size,
                  config.meta_round,       33434};
  sniffer.start();

  // Sender
  Sender sender{config.interface, config.protocol};

  // Rate limiter
  RateLimiter rl{config.probing_rate};

  // Statistics
  ProberStatistics stats;
  auto log_stats = [&] {
    BOOST_LOG_TRIVIAL(info) << "packets_rate=" << rl.current_rate();
    BOOST_LOG_TRIVIAL(info) << stats;
    BOOST_LOG_TRIVIAL(info) << sniffer.statistics();
  };

  // Input
  std::ifstream input_file;
  std::istream& is = config.input_file ? input_file : std::cin;

  if (config.input_file) {
    input_file.open(config.input_file.value());
  } else {
    BOOST_LOG_TRIVIAL(info) << "Reading from stdin, press CTRL+D to stop...";
    std::ios::sync_with_stdio(false);
  }

  // Loop
  std::string line;
  Probe p{};

  while (std::getline(is, line)) {
    try {
      p = Probe::from_csv(line);
    } catch (const std::exception& e) {
      BOOST_LOG_TRIVIAL(warning) << e.what();
      continue;
    }
    stats.read++;

    // TTL filter
    if (config.filter_min_ttl && (p.ttl < config.filter_min_ttl.value())) {
      BOOST_LOG_TRIVIAL(trace) << "Filtered probe " << p << " (TTL too low)";
      stats.filtered_lo_ttl++;
      continue;
    }
    if (config.filter_max_ttl && (p.ttl > config.filter_max_ttl.value())) {
      BOOST_LOG_TRIVIAL(trace) << "Filtered probe " << p << " (TTL too high)";
      stats.filtered_hi_ttl++;
      continue;
    }

    // Prefix filter
    // Do not send probes to excluded prefixes (deny list).
    // TODO: IPv6
    if (config.prefix_excl_file &&
        (prefix_excl_trie.get(p.dst_addr.s6_addr32[3]) != nullptr)) {
      BOOST_LOG_TRIVIAL(trace)
          << "Filtered probe " << p << " (excluded prefix)";
      stats.filtered_prefix_excl++;
      continue;
    }
    // Do not send probes to *not* included prefixes.
    // i.e. send probes only to included prefixes (allow list).
    // TODO: IPv6
    if (config.prefix_incl_file &&
        (prefix_incl_trie.get(p.dst_addr.s6_addr32[3]) == nullptr)) {
      BOOST_LOG_TRIVIAL(trace)
          << "Filtered probe " << p << " (not included prefix)";
      stats.filtered_prefix_not_incl++;
      continue;
    }

    for (uint64_t i = 0; i < config.n_packets; i++) {
      BOOST_LOG_TRIVIAL(trace) << "probe=" << p << " packet=" << i + 1;
      try {
        sender.send(p);
        stats.sent++;
      } catch (const std::system_error& e) {
        BOOST_LOG_TRIVIAL(error) << "probe=" << p << " error=" << e.what();
        stats.failed++;
      }
      rl.wait();
    }

    // Log every ~5 seconds.
    auto rate = uint64_t(rl.current_rate());
    if ((rate > 0) && (stats.sent % (5 * rate) == 0)) {
      log_stats();
    }

    if (config.max_probes && (stats.sent >= config.max_probes.value())) {
      BOOST_LOG_TRIVIAL(trace) << "max_probes reached, exiting...";
      break;
    }
  }

  log_stats();

  BOOST_LOG_TRIVIAL(info) << "Waiting " << config.sniffer_wait_time
                          << "s to allow the sniffer to get the last "
                             "flying responses...";
  std::this_thread::sleep_for(std::chrono::seconds(config.sniffer_wait_time));
  sniffer.stop();

  return {stats, sniffer.statistics()};
}

}  // namespace dminer::Prober
