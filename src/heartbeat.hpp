#pragma once
#include <arpa/inet.h>

#include <boost/log/trivial.hpp>
#include <chrono>
#include <memory>
#include <patricia.hpp>
#include <range/v3/all.hpp>
#include <tuple>

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
using std::chrono::seconds;
using std::chrono::steady_clock;

inline std::tuple<int, int> send_heartbeat(const HeartbeatConfig& config) {
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
  Patricia bgp_filter_trie{32};

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

  if (config.bgp_filter_file) {
    BOOST_LOG_TRIVIAL(info) << "Loading routing informations...";
    bgp_filter_trie.populate(config.bgp_filter_file.value().c_str());
  }

  // Sniffer
  sniffer_t sniffer{config.interface, config.output_file,
                    config.sniffer_buffer_size, 33434};
  sniffer.start();

  // Sender
  std::unique_ptr<Sender> sender;
#ifdef WITH_PF_RING
  try {
    sender = std::make_unique<pf_ring_sender_t>(
        AF_INET, config.protocol, config.interface, config.probing_rate,
        config.start_time_log_file);
  } catch (const std::runtime_error& e) {
    BOOST_LOG_TRIVIAL(warning) << e.what();
  }
#endif
  if (!sender) {
    BOOST_LOG_TRIVIAL(info)
        << "PF_RING not available, using classical sender...";
    sender = std::make_unique<classic_sender_t>(
        AF_INET, config.protocol, config.interface, config.probing_rate,
        config.start_time_log_file);
  }

  unsigned long long int probes_sent = 0;
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

  // clang-format off
  auto probes = ranges::getlines(is)
    | ranges::views::transform(Probe::from_csv)
    | ranges::views::take(config.max_probes.value_or(100000000000)) // TODO: More than 100B?
    | ranges::views::filter([&](const Probe& p) {
        // Temporary safeguard, until we cleanup packets_utils.
        // "TTL >= 32 are not supported, the probe will not be sent: "
        if (p.ttl >= 32) {
            BOOST_LOG_TRIVIAL(trace) << "Filtered probe " << p << " (TTL >= 32 are not supported)";
            return false;
        }
        return true;
      })
    | ranges::views::filter([&](const Probe& p) {
        if (config.filter_min_ttl && (p.ttl < config.filter_min_ttl.value())) {
          BOOST_LOG_TRIVIAL(trace) << "Filtered probe " << p << " (TTL too low)";
          return false;
        }
        if (config.filter_max_ttl && (p.ttl > config.filter_max_ttl.value())) {
          BOOST_LOG_TRIVIAL(trace) << "Filtered probe " << p << " (TTL too high)";
          return false;
        }
        // TODO: Cleanup this.
        if (config.filter_min_ip && (p.dst_addr.s_addr < uint32_t(config.filter_min_ip.value()))) {
          BOOST_LOG_TRIVIAL(trace) << "Filtered probe " << p << " (destination address too low)";
          return false;
        }
        if (config.filter_max_ip && (p.dst_addr.s_addr > uint32_t(config.filter_max_ip.value()))) {
          BOOST_LOG_TRIVIAL(trace) << "Filtered probe " << p << " (destination address too high)";
          return false;
        }
        // Do not send probes to excluded prefixes (deny list).
        if (config.prefix_excl_file && (prefix_excl_trie.get(p.dst_addr.s_addr) != nullptr)) {
          BOOST_LOG_TRIVIAL(trace) << "Filtered probe " << p << " (excluded prefix)";
          return false;
        }
        // Do not send probes to *not* included prefixes.
        // i.e. send probes only to included prefixes (allow list).
        if (config.prefix_incl_file && (prefix_incl_trie.get(p.dst_addr.s_addr) == nullptr)) {
          BOOST_LOG_TRIVIAL(trace) << "Filtered probe " << p << " (not included prefix)";
          return false;
        }
        // Do not send probes to un-routed destinations.
        if (config.bgp_filter_file && (bgp_filter_trie.get(p.dst_addr.s_addr) == nullptr)) {
          BOOST_LOG_TRIVIAL(trace) << "Filtered probe " << p << " (not routable prefix)";
          return false;
        }
        return true;
      });
  // clang-format on

  for (auto probe : probes) {
    BOOST_LOG_TRIVIAL(trace) << "Sending probe " << probe;
    sender->send(probe, config.n_packets);
    probes_sent++;
    // Log every ~15 seconds.
    if ((probes_sent % (15 * config.probing_rate)) == 0) {
      log_stats();
    }
  }

  log_stats();

  BOOST_LOG_TRIVIAL(info) << "Waiting 5s to allow the sniffer to get the last "
                             "flying responses... Press CTRL+C to exit now.";
  std::this_thread::sleep_for(std::chrono::milliseconds(5000));
  sniffer.stop();

  return {probes_sent, sniffer.received_count()};
}
