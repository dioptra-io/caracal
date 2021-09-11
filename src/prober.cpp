#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>

#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/filter/zstd.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <caracal/lpm.hpp>
#include <caracal/pretty.hpp>
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

namespace io = boost::iostreams;
using std::chrono::milliseconds;

// NOTE: Should we expose this as a parameter?
/// Number of probes to send before calling the rate limiter.
const uint64_t batch_size = 128;

ProbingStatistics probe(const Config& config, Iterator& it) {
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
  Sniffer sniffer{config.interface,        config.output_file_csv,
                  config.output_file_pcap, config.meta_round,
                  config.caracal_id,       config.integrity_check};
  sniffer.start();

  // Sender
  Sender sender{config.interface, config.caracal_id};

  // Rate limiter
  RateLimiter rl{config.probing_rate, batch_size, config.rate_limiting_method};

  // Statistics
  Statistics::Prober stats;
  auto log_stats = [&] {
    spdlog::info(rl.statistics());
    spdlog::info(stats);
    spdlog::info(sniffer.statistics());
    spdlog::info(sniffer.pcap_statistics());
  };

  // Log statistics every 5 seconds
  auto stop_stats_thread = false;
  std::thread stats_thread{[&] {
    milliseconds elapsed{0};
    const milliseconds refresh{100};
    const milliseconds interval{5000};
    while (!stop_stats_thread) {
      std::this_thread::sleep_for(refresh);
      elapsed += refresh;
      if (elapsed >= interval) {
        log_stats();
        elapsed = milliseconds{0};
      }
    }
  }};

  // Loop
  Probe p{};

  while (it(p)) {
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
      spdlog::trace("probe={} id={} packet={}", p,
                    p.checksum(config.caracal_id), i + 1);
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

    if (config.max_probes && (stats.sent >= *config.max_probes)) {
      spdlog::trace("max_probes reached, exiting...");
      break;
    }
  }

  spdlog::info(
      "Waiting {}s to allow the sniffer to get the last flying responses...",
      config.sniffer_wait_time);
  std::this_thread::sleep_for(std::chrono::seconds(config.sniffer_wait_time));
  sniffer.stop();

  // Stop logger thread and print statistics one last time.
  stop_stats_thread = true;
  stats_thread.join();
  log_stats();

  return {stats, sniffer.statistics(), sniffer.pcap_statistics()};
}

ProbingStatistics probe(const Config& config, std::istream& is) {
  std::string line;
  Iterator iterator = [&](Probe& p) {
    bool valid = false;
    // Iterate until we find the next valid probe, or we reach EOF.
    while (!valid && std::getline(is, line)) {
      try {
        p = Probe::from_csv(line);
        valid = true;
      } catch (const std::exception& e) {
        spdlog::warn("line={} error={}", line, e.what());
      }
    }
    return valid;
  };
  return probe(config, iterator);
}

ProbingStatistics probe(const Config& config, const fs::path& p) {
  if (!fs::exists(p)) {
    throw std::invalid_argument(p.string() + " does not exists");
  }
  io::filtering_stream<io::input> inp;
  if (p.extension() == ".zst") {
    inp.push(io::zstd_decompressor());
  }
  std::ifstream ifs{p};
  inp.push(ifs);
  return probe(config, inp);
}

}  // namespace caracal::Prober
