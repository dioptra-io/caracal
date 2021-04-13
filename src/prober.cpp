#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>

#include <caracal/lpm.hpp>
#include <caracal/probe.hpp>
#include <caracal/prober.hpp>
#include <caracal/prober_config.hpp>
#include <caracal/rate_limiter.hpp>
#include <caracal/sender.hpp>
#include <caracal/sniffer.hpp>
#include <caracal/statistics.hpp>
#include <chrono>
#include <iostream>
#include <tuple>

namespace caracal::Prober {

// NOTE: Should we expose this as a parameter?
const uint64_t batch_size = 128;

std::tuple<Statistics::Prober, Statistics::Sniffer> probe(
    const Config& config) {
  spdlog::info(config);

  LPM prefix_excl;
  LPM prefix_incl;

  if (config.prefix_excl_file) {
    spdlog::info("Loading excluded prefixes...");
    prefix_excl.insert_file(*config.prefix_excl_file);
  }

  if (config.prefix_incl_file) {
    spdlog::info("Loading included prefixes...");
    prefix_incl.insert_file(*config.prefix_incl_file);
  }

  // Sniffer
  Sniffer sniffer{config.interface, config.output_file_csv,
                  config.output_file_pcap, config.meta_round, 33434};
  sniffer.start();

  // Sender
  Sender sender{config.interface, config.protocol};

  // Rate limiter
  RateLimiter rl{config.probing_rate, batch_size, config.rate_limiting_method};

  // Statistics
  Statistics::Prober stats;
  auto log_stats = [&] {
    spdlog::info(rl.statistics());
    spdlog::info(stats);
    spdlog::info(sniffer.statistics());
  };

  // Input
  std::ifstream input_file;
  std::istream& is = config.input_file ? input_file : std::cin;

  if (config.input_file) {
    input_file.open(*config.input_file);
  } else {
    spdlog::info("Reading from stdin, press CTRL+D to stop...");
    std::ios::sync_with_stdio(false);
  }

  // Loop
  std::string line;
  Probe p{};

  while (std::getline(is, line)) {
    try {
      p = Probe::from_csv(line);
    } catch (const std::exception& e) {
      spdlog::warn("line={} error={}", line, e.what());
      continue;
    }
    stats.read++;

    // TTL filter
    if (config.filter_min_ttl && (p.ttl < *config.filter_min_ttl)) {
      spdlog::trace("probe={} filter=ttl_too_low", p);
      stats.filtered_lo_ttl++;
      continue;
    }
    if (config.filter_max_ttl && (p.ttl > *config.filter_max_ttl)) {
      spdlog::trace("probe={} filter=ttl_too_high", p);
      stats.filtered_hi_ttl++;
      continue;
    }

    // Prefix filter
    // Do not send probes to excluded prefixes (deny list).
    if (config.prefix_excl_file && prefix_excl.lookup(p.dst_addr)) {
      spdlog::trace("probe={} filter=prefix_excluded", p);
      stats.filtered_prefix_excl++;
      continue;
    }
    // Do not send probes to *not* included prefixes.
    // i.e. send probes only to included prefixes (allow list).
    if (config.prefix_incl_file && !prefix_incl.lookup(p.dst_addr)) {
      spdlog::trace("probe={} filter=prefix_not_included", p);
      stats.filtered_prefix_not_incl++;
      continue;
    }

    for (uint64_t i = 0; i < config.n_packets; i++) {
      spdlog::trace("probe={} packet={}", p, i + 1);
      try {
        sender.send(p);
        stats.sent++;
      } catch (const std::system_error& e) {
        spdlog::error("probe={} error={}", p, e.what());
        stats.failed++;
      }
      // Rate limit every `batch_size` packets sent.
      if ((stats.sent + stats.failed) % batch_size == 0) {
        rl.wait();
      }
    }

    // Log every ~5 seconds.
    auto rate = static_cast<uint64_t>(rl.statistics().average_rate());
    if ((rate > 0) && (stats.sent % (5 * rate) == 0)) {
      log_stats();
    }

    if (config.max_probes && (stats.sent >= *config.max_probes)) {
      spdlog::trace("max_probes reached, exiting...");
      break;
    }
  }

  log_stats();

  spdlog::info(
      "Waiting {}s to allow the sniffer to get the last flying responses...",
      config.sniffer_wait_time);
  std::this_thread::sleep_for(std::chrono::seconds(config.sniffer_wait_time));
  sniffer.stop();

  log_stats();
  return {stats, sniffer.statistics()};
}

}  // namespace caracal::Prober
