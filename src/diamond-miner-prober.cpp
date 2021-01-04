#include <diamond-miner-config.h>

#include <boost/program_options.hpp>
#include <dminer/heartbeat.hpp>
#include <dminer/heartbeat_config.hpp>
#include <dminer/logging.hpp>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;
namespace po = boost::program_options;

using std::string;

int main(int argc, char** argv) {
  std::cout << "diamond-miner-prober"
            << " v" << DMINER_VERSION_MAJOR << "." << DMINER_VERSION_MINOR
            << "." << DMINER_VERSION_PATCH;
  std::cout << std::endl;

  HeartbeatConfig config;
  po::options_description general("General options");
  po::options_description filters("Filters");
  po::options_description meta("Metadata");

  // clang-format off
  general.add_options()
    ("help,h", "Show this message")
    ("input-file,i", po::value<string>()->value_name("file"), "File containing the probes to send")
    ("output-file-csv,o", po::value<string>()->value_name("file"), "File to which the captured replies will be written")
    ("output-file-pcap", po::value<string>()->value_name("file"), "File to which the captured replies will be written")
    ("protocol,p", po::value<string>()->value_name("protocol")->default_value(config.protocol), "Protocol to use for probing (udp, tcp)")
    ("probing-rate,r", po::value<int>()->value_name("pps")->default_value(config.probing_rate), "Probing rate in packets per second")
    ("interface,z", po::value<string>()->value_name("interface")->default_value(config.interface.name()), "Interface from which to send the packets")
    ("sniffer-buffer-size,B", po::value<int>()->value_name("bytes")->default_value(config.sniffer_buffer_size), "Size of the sniffer buffer (equivalent of -B option in tcpdump)")
    ("sniffer-wait-time,W", po::value<int>()->value_name("seconds")->default_value(config.sniffer_wait_time), "Time in seconds to wait after sending the probes to stop the sniffer")
    ("log-level,L", po::value<string>()->value_name("level")->default_value("info"), "Minimum log level (trace, debug, info, warning, error, fatal)")
    ("max-probes,P", po::value<int>()->value_name("count"), "Maximum number of probes to send (unlimited by default)")
    ("n-packets,N", po::value<int>()->value_name("count")->default_value(config.n_packets), "Number of packets to send per probe");

  filters.add_options()
    ("filter-from-bgp-file", po::value<string>()->value_name("file"), "Do not send probes to un-routed destinations")
    ("filter-from-prefix-file-excl", po::value<string>()->value_name("file"), "Do not send probes to prefixes specified in file (deny list)")
    ("filter-from-prefix-file-incl", po::value<string>()->value_name("file"), "Do not send probes to prefixes *not* specified in file (allow list)")
    ("filter-min-ip", po::value<string>()->value_name("min_ip"), "Do not send probes with dest_ip < min_ip")
    ("filter-max-ip", po::value<string>()->value_name("max_ip"), "Do not send probes with dest_ip > max_ip")
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
    if (vm.count("input-file")) {
      fs::path path{vm["input-file"].as<string>()};
      config.set_input_file(path);
    }

    if (vm.count("output-file-csv")) {
      fs::path path{vm["output-file-csv"].as<string>()};
      config.set_output_file_csv(path);
    }

    if (vm.count("output-file-pcap")) {
      fs::path path{vm["output-file-pcap"].as<string>()};
      config.set_output_file_pcap(path);
    }

    if (vm.count("protocol")) {
      config.set_protocol(vm["protocol"].as<string>());
    }

    if (vm.count("probing-rate")) {
      config.set_probing_rate(vm["probing-rate"].as<int>());
    }

    if (vm.count("interface")) {
      config.set_interface(vm["interface"].as<string>());
    }

    if (vm.count("sniffer-buffer-size")) {
      config.set_sniffer_buffer_size(vm["sniffer-buffer-size"].as<int>());
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

    if (vm.count("filter-from-bgp-file")) {
      fs::path path{vm["filter-from-bgp-file"].as<string>()};
      config.set_bgp_filter_file(path);
    }

    if (vm.count("filter-from-prefix-file-excl")) {
      fs::path path{vm["filter-from-prefix-file-excl"].as<string>()};
      config.set_prefix_excl_file(path);
    }

    if (vm.count("filter-from-prefix-file-incl")) {
      fs::path path{vm["filter-from-prefix-file-incl"].as<string>()};
      config.set_prefix_incl_file(path);
    }

    if (vm.count("filter-min-ip")) {
      config.set_filter_min_ip(vm["filter-min-ip"].as<string>());
    }

    if (vm.count("filter-max-ip")) {
      config.set_filter_max_ip(vm["filter-max-ip"].as<string>());
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

    configure_logging(vm["log-level"].as<string>());
    send_heartbeat(config);
  } catch (const std::invalid_argument& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
