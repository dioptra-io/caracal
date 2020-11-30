#include <dminer_config.h>

#include <boost/program_options.hpp>
#include <filesystem>
#include <iostream>

#include "heartbeat.hpp"
#include "heartbeat_config.hpp"
#include "logging.hpp"

namespace fs = std::filesystem;
namespace po = boost::program_options;

using std::string;

int main(int argc, char** argv) {
  std::cout << "diamond-miner-prober"
            << " v" << DMINER_VERSION_MAJOR << "." << DMINER_VERSION_MINOR
            << "." << DMINER_VERSION_PATCH;
#ifdef WITH_PF_RING
  std::cout << " (WITH_PF_RING=ON)";
#else
  std::cout << " (WITH_PF_RING=OFF)";
#endif
  std::cout << std::endl;

  po::options_description general("General options");
  po::options_description filters("Filters");

  // clang-format off
  general.add_options()
    ("help,h", "Show this message")
    ("input-file,i", po::value<string>()->value_name("file"), "File containing the probes to send")
    ("output-file,o", po::value<string>()->value_name("file"), "File to which the captured replies will be written")
    ("protocol,p", po::value<string>()->value_name("protocol")->default_value("udp"), "Protocol to use for probing (udp, tcp)")
    ("probing-rate,r", po::value<int>()->value_name("pps")->default_value(100), "Probing rate in packets per second")
    ("interface,z", po::value<string>()->value_name("interface"), "Interface from which to send the packets")
    ("sniffer-buffer-size,B", po::value<int>()->value_name("bytes")->default_value(2000000), "Size of the sniffer buffer (equivalent of -B option in tcpdump)")
    ("log-level,L", po::value<string>()->value_name("level")->default_value("info"), "Minimum log level (trace, debug, info, warning, error, fatal)")
    ("max-probes,P", po::value<int>()->value_name("count"), "Maximum number of probes to send (unlimited by default)")
    ("n-packets,N", po::value<int>()->value_name("count")->default_value(1), "Number of packets to send per probe")
    ("start-time-log-file,S", po::value<string>()->value_name("file"), "Logging file to record the starting time of the tool. Needed if record-timestamp is set.");

  filters.add_options()
    ("filter-from-bgp-file", po::value<string>()->value_name("file"), "Do not send probes to un-routed destinations")
    ("filter-from-prefix-file-excl", po::value<string>()->value_name("file"), "Do not send probes to prefixes specified in file (blacklist)")
    ("filter-from-prefix-file-incl", po::value<string>()->value_name("file"), "Do not send probes to prefixes *not* specified in file (whitelist)")
    ("filter-min-ip", po::value<string>()->value_name("min_ip"), "Do not send probes with dest_ip < min_ip")
    ("filter-max-ip", po::value<string>()->value_name("max_ip"), "Do not send probes with dest_ip > max_ip")
    ("filter-min-ttl", po::value<int>()->value_name("min_ttl"), "Do not send probes with ttl < min_ttl")
    ("filter-max-ttl", po::value<int>()->value_name("max_ttl"), "Do not send probes with ttl > max_ttl");
  // clang-format on

  po::options_description all;
  all.add(general).add(filters);

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, all), vm);
  po::notify(vm);

  if (vm.count("help")) {
    std::cout << all << std::endl;
    return 0;
  }

  try {
    HeartbeatConfigBuilder builder;

    if (vm.count("input-file")) {
      fs::path path{vm["input-file"].as<string>()};
      builder.set_input_file(path);
    }

    if (vm.count("output-file")) {
      fs::path path{vm["output-file"].as<string>()};
      builder.set_output_file(path);
    }

    if (vm.count("protocol")) {
      builder.set_protocol(vm["protocol"].as<string>());
    }

    if (vm.count("probing-rate")) {
      builder.set_probing_rate(vm["probing-rate"].as<int>());
    }

    if (vm.count("interface")) {
      builder.set_interface(vm["interface"].as<string>());
    }

    if (vm.count("sniffer-buffer-size")) {
      builder.set_sniffer_buffer_size(vm["sniffer-buffer-size"].as<int>());
    }

    if (vm.count("max-probes")) {
      builder.set_max_probes(vm["max-probes"].as<int>());
    }

    if (vm.count("n-packets")) {
      builder.set_n_packets(vm["n-packets"].as<int>());
    }

    if (vm.count("start-time-log-file")) {
      fs::path path{vm["start-time-log-file"].as<string>()};
      builder.set_start_time_log_file(path);
    }

    if (vm.count("filter-from-bgp-file")) {
      fs::path path{vm["filter-from-bgp-file"].as<string>()};
      builder.set_bgp_filter_file(path);
    }

    if (vm.count("filter-from-prefix-file-excl")) {
      fs::path path{vm["filter-from-prefix-file-excl"].as<string>()};
      builder.set_prefix_excl_file(path);
    }

    if (vm.count("filter-from-prefix-file-incl")) {
      fs::path path{vm["filter-from-prefix-file-incl"].as<string>()};
      builder.set_prefix_incl_file(path);
    }

    if (vm.count("filter-min-ip")) {
      builder.set_filter_min_ip(vm["filter-min-ip"].as<string>());
    }

    if (vm.count("filter-max-ip")) {
      builder.set_filter_max_ip(vm["filter-max-ip"].as<string>());
    }

    if (vm.count("filter-min-ttl")) {
      builder.set_filter_min_ttl(vm["filter-min-ttl"].as<int>());
    }

    if (vm.count("filter-max-ttl")) {
      builder.set_filter_min_ttl(vm["filter-max-ttl"].as<int>());
    }

    configure_logging(vm["log-level"].as<string>());
    HeartbeatConfig config = builder.build();
    send_heartbeat(config);
  } catch (const std::invalid_argument& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
