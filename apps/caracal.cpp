#include <caracal-config.h>
#include <spdlog/cfg/helpers.h>
#include <spdlog/spdlog.h>

#include <boost/core/demangle.hpp>
#include <boost/program_options.hpp>
#include <caracal/prober.hpp>
#include <caracal/prober_config.hpp>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;
namespace po = boost::program_options;

using std::string;

int main(int argc, char** argv) {
  std::cout << "caracal"
            << " v" << CARACAL_SEMVER << " (" << CARACAL_BUILD_TYPE
            << " build)";
  std::cout << std::endl;

  caracal::Prober::Config config;
  po::options_description general("General options");
  po::options_description filters("Filters");
  po::options_description meta("Metadata");

  // clang-format off
  general.add_options()
    ("help,h", "Show this message")
    ("input-file,i", po::value<string>()->value_name("file"), "File containing the probes to send")
    ("output-file-csv,o", po::value<string>()->value_name("file"), "File to which the captured replies will be written")
    ("output-file-pcap", po::value<string>()->value_name("file"), "File to which the captured replies will be written")
    ("probing-rate,r", po::value<int>()->value_name("pps")->default_value(config.probing_rate), "Probing rate in packets per second")
    ("interface,z", po::value<string>()->value_name("interface")->default_value(config.interface.name()), "Interface from which to send the packets")
    ("sniffer-wait-time,W", po::value<int>()->value_name("seconds")->default_value(config.sniffer_wait_time), "Time in seconds to wait after sending the probes to stop the sniffer")
    ("log-level,L", po::value<string>()->value_name("level")->default_value("info"), "Minimum log level (trace, debug, info, warning, error, fatal)")
    ("max-probes,P", po::value<int>()->value_name("count"), "Maximum number of probes to send (unlimited by default)")
    ("n-packets,N", po::value<int>()->value_name("count")->default_value(config.n_packets), "Number of packets to send per probe")
    ("rate-limiting-method", po::value<string>()->value_name("method")->default_value(config.rate_limiting_method), "Method to use to limit the packets rate (auto, active, sleep, none)");

  filters.add_options()
    ("filter-from-prefix-file-excl", po::value<string>()->value_name("file"), "Do not send probes to prefixes specified in file (deny list)")
    ("filter-from-prefix-file-incl", po::value<string>()->value_name("file"), "Do not send probes to prefixes *not* specified in file (allow list)")
    ("filter-min-ttl", po::value<int>()->value_name("min_ttl"), "Do not send probes with ttl < min_ttl")
    ("filter-max-ttl", po::value<int>()->value_name("max_ttl"), "Do not send probes with ttl > max_ttl");

  meta.add_options()
      ("meta-round", po::value<string>()->value_name("value"), "Value of the round column in the CSV output");
  // clang-format on

  po::options_description all;
  all.add(general).add(filters).add(meta);

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, all), vm);
  po::notify(vm);

  if (vm.count("help")) {
    std::cout << all << std::endl;
    return 0;
  }

  try {
    if (vm.count("output-file-csv")) {
      fs::path path{vm["output-file-csv"].as<string>()};
      config.set_output_file_csv(path);
    }

    if (vm.count("output-file-pcap")) {
      fs::path path{vm["output-file-pcap"].as<string>()};
      config.set_output_file_pcap(path);
    }

    if (vm.count("probing-rate")) {
      config.set_probing_rate(vm["probing-rate"].as<int>());
    }

    if (vm.count("interface")) {
      config.set_interface(vm["interface"].as<string>());
    }

    if (vm.count("sniffer-wait-time")) {
      config.set_sniffer_wait_time(vm["sniffer-wait-time"].as<int>());
    }

    if (vm.count("max-probes")) {
      config.set_max_probes(vm["max-probes"].as<int>());
    }

    if (vm.count("n-packets")) {
      config.set_n_packets(vm["n-packets"].as<int>());
    }

    if (vm.count("rate-limiting-method")) {
      config.set_rate_limiting_method(vm["rate-limiting-method"].as<string>());
    }

    if (vm.count("filter-from-prefix-file-excl")) {
      fs::path path{vm["filter-from-prefix-file-excl"].as<string>()};
      config.set_prefix_excl_file(path);
    }

    if (vm.count("filter-from-prefix-file-incl")) {
      fs::path path{vm["filter-from-prefix-file-incl"].as<string>()};
      config.set_prefix_incl_file(path);
    }

    if (vm.count("filter-min-ttl")) {
      config.set_filter_min_ttl(vm["filter-min-ttl"].as<int>());
    }

    if (vm.count("filter-max-ttl")) {
      config.set_filter_max_ttl(vm["filter-max-ttl"].as<int>());
    }

    if (vm.count("meta-round")) {
      config.set_meta_round(vm["meta-round"].as<string>());
    }

    spdlog::cfg::helpers::load_levels(vm["log-level"].as<string>());

    if (vm.count("input-file")) {
      fs::path path{vm["input-file"].as<string>()};
      caracal::Prober::probe(config, path);
    } else {
      spdlog::info("Reading from stdin, press CTRL+D to stop...");
      std::ios::sync_with_stdio(false);
      caracal::Prober::probe(config, std::cin);
    }
  } catch (const std::exception& e) {
    auto type = boost::core::demangle(typeid(e).name());
    std::cerr << "Exception of type " << type << ": " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
