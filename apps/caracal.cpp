#include <caracal-config.h>
#include <spdlog/cfg/helpers.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <caracal/prober.hpp>
#include <caracal/prober_config.hpp>
#include <caracal/utilities.hpp>
#include <cxxopts.hpp>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

using std::string;

int main(int argc, char** argv) {
  std::cerr << "caracal"
            << " v" << CARACAL_VERSION << " (" << CARACAL_BUILD_TYPE
            << " build)";
  std::cerr << std::endl;

  caracal::Prober::Config config;
  cxxopts::Options options("caracal");

  // clang-format off
  options.add_options()
      ("h,help", "Show this message")
      ("r,probing-rate", "Probing rate in packets per second", cxxopts::value<int>()->default_value(std::to_string(config.probing_rate)))
      ("z,interface", "Interface from which to send the packets", cxxopts::value<string>()->default_value(config.interface))
      ("B,batch-size", "Number of probes to send before calling the rate limiter", cxxopts::value<int>()->default_value(std::to_string(config.batch_size)))
      ("L,log-level", "Minimum log level (trace, debug, info, warning, error, fatal)", cxxopts::value<string>()->default_value("info"))
      ("N,n-packets", "Number of packets to send per probe", cxxopts::value<int>()->default_value(std::to_string(config.n_packets)))
      ("P,max-probes", "Maximum number of probes to send (unlimited by default)", cxxopts::value<int>())
      ("source-address-v4", "Specify the IPv4 source address to use in the packets (if probing in v4)", cxxopts::value<string>())
      ("source-address-v6", "Specify the IPv6 source address to use in the packets (if probing in v6)", cxxopts::value<string>())
      ("W,sniffer-wait-time", "Time in seconds to wait after sending the probes to stop the sniffer", cxxopts::value<int>()->default_value(std::to_string(config.sniffer_wait_time)))
      ("rate-limiting-method", "Method to use to limit the packets rate (auto, active, sleep, none)", cxxopts::value<string>()->default_value(config.rate_limiting_method))
      ("filter-from-prefix-file-excl", "Do not send probes to prefixes specified in file (deny list)", cxxopts::value<string>())
      ("filter-from-prefix-file-incl", "Do not send probes to prefixes *not* specified in file (allow list)", cxxopts::value<string>())
      ("filter-min-ttl", "Do not send probes with ttl < min_ttl", cxxopts::value<int>())
      ("filter-max-ttl", "Do not send probes with ttl > max_ttl", cxxopts::value<int>())
      ("caracal-id", "Identifier encoded in the probes (random by default)", cxxopts::value<int>())
      ("meta-round", "Value of the round column in the CSV output", cxxopts::value<string>())
      ("no-integrity-check", "Do not check that replies match valid probes", cxxopts::value<bool>()->default_value("false"));
  // clang-format on

  auto result = options.parse(argc, argv);

  if (result.count("help")) {
    std::cout << options.help() << std::endl;
    return 0;
  }

  try {
    if (result.count("probing-rate")) {
      config.set_probing_rate(result["probing-rate"].as<int>());
    }

    if (result.count("interface")) {
      config.set_interface(result["interface"].as<string>());
    }

    if (result.count("batch-size")) {
      config.set_batch_size(result["batch-size"].as<int>());
    }

    if (result.count("sniffer-wait-time")) {
      config.set_sniffer_wait_time(result["sniffer-wait-time"].as<int>());
    }

    if (result.count("source-address-v4")) {
      config.set_ip_version(4);
      config.set_source_ipv4(result["source-address"].as<std::string>());
    }

    if (result.count("source-address-v6")) {
      config.set_ip_version(6);
      config.set_source_ipv6(result["source-address"].as<std::string>());
    }


    if (result.count("max-probes")) {
      config.set_max_probes(result["max-probes"].as<int>());
    }

    if (result.count("n-packets")) {
      config.set_n_packets(result["n-packets"].as<int>());
    }

    if (result.count("rate-limiting-method")) {
      config.set_rate_limiting_method(
          result["rate-limiting-method"].as<string>());
    }

    if (result.count("filter-from-prefix-file-excl")) {
      fs::path path{result["filter-from-prefix-file-excl"].as<string>()};
      config.set_prefix_excl_file(path);
    }

    if (result.count("filter-from-prefix-file-incl")) {
      fs::path path{result["filter-from-prefix-file-incl"].as<string>()};
      config.set_prefix_incl_file(path);
    }

    if (result.count("filter-min-ttl")) {
      config.set_filter_min_ttl(result["filter-min-ttl"].as<int>());
    }

    if (result.count("filter-max-ttl")) {
      config.set_filter_max_ttl(result["filter-max-ttl"].as<int>());
    }

    if (result.count("caracal-id")) {
      config.set_caracal_id(result["caracal-id"].as<int>());
    }

    if (result.count("meta-round")) {
      config.set_meta_round(result["meta-round"].as<string>());
    }

    if (result.count("no-integrity-check")) {
      config.set_integrity_check(false);
    }

    spdlog::cfg::helpers::load_levels(result["log-level"].as<string>());
    // See
    // https://github.com/gabime/spdlog/wiki/0.-FAQ#switch-the-default-logger-to-stderr
    // for why we need to create a dummy logger.
    spdlog::set_default_logger(spdlog::stderr_color_st("dummy"));
    spdlog::set_default_logger(spdlog::stderr_color_st(""));

    spdlog::info("Reading from stdin, press CTRL+D to stop...");
    caracal::Prober::probe(config, std::cin);
  } catch (const std::exception& e) {
    auto type = caracal::Utilities::demangle(typeid(e).name());
    std::cerr << "Exception of type " << type << ": " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
