#include <iostream>
#include <vector>


#include <tins/tins.h>
#include <heartbeat_t.hpp>
#include <probing_options_t.hpp>

#include <boost/program_options.hpp>

#include <limits>
#include <utils/parameters_utils_t.hpp>

using namespace Tins;
using namespace utils;

int main(int argc, char **argv) {



    namespace po = boost::program_options;

    std::string help_message;

    probing_options_t options;

    std::string output_file;

    // Declare the supported options.
    po::options_description desc("Options");
    desc.add_options()
            ("help,h", help_message.c_str())
            ("interface", po::value<std::string>(), "Interface from which to send the packets")
            ("proto,p", po::value<std::string>(), "Protocol to use for probing (udp (default), tcp, icmp)")
            ("dport", po::value<uint16_t>(), "destination port for probing (default 33434)")
            ("probes-files,f", po::value<std::string>(), "Format is SRC_IP, DST_IP, SRC_PORT, DST_PORT, TTL, ROUND")
            ("send-from-file,F", "Send from a file rather than an exhaustive IPv4 probing.")
            ("output-file,o", po::value<std::string>(), "pcap output file of replies")
            ("probing-rate,r", po::value<uint32_t>(), "Probing rate in pps")
            ("inf-born,i", po::value<uint32_t>(), "inf born of the dst_ip")
            ("sup-born,s", po::value<uint32_t>(), "sup born of the dst_ip")
            ("destinations,d", po::value<uint32_t>(), "Number of destinations per /24")
            ("only-routable", "Send only to routable destinations, need the bgp file argument")
            ("bgp-file", po::value<std::string>(), "BGP file to send only to routable destinations")
            ("record-timestamp", "record the sending time of the packets. Needs to set the start-time-log-file option")
            ("start-time-log-file", po::value<std::string>(), "Logging file to record the starting time of the tool. Needed if record-timestamp is set.")
            ("send-from-targets-file,T", "Send from a target file rather than an exhaustive IPv4 probing.")
            ("targets-file,t", po::value<std::string>(), "File containing targets (< 100000) in string or little endian format. Need to set the send-from-targets");


    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 1;
    }

    if (vm.count("interface")){
        std::string interface = vm["interface"].as<std::string>();
        options.interface = interface;
    }

    if (vm.count("proto")){
        std::string proto = vm["proto"].as<std::string>();
        if (proto == "udp"){
            options.proto = IPPROTO_UDP;
        }
        else if (proto == "tcp") {
            options.proto = IPPROTO_TCP;
        }
    } else {
        std::cerr << "Unknown protocol. Exiting...\n";
        exit(1);
    }

    if (vm.count("dport")){
        options.dport = vm["dport"].as<uint16_t >();
    }

    if (vm.count("output-file")){
        options.output_file = vm["output-file"].as<std::string>();
    } else {
        std::cerr << "Missing an output file. Exiting...\n";
        exit(1);
    }

    if (vm.count("send-from-file")) {
        options.is_send_from_probes_file = true;
        if (vm.count("probes-files")){
            options.probes_file = vm["probes-files"].as<std::string>();
        } else {
            std::cerr << "Missing a probes file. Exiting...\n";
            exit(1);
        }
    } else {
        options.is_send_from_probes_file = false;
    }

    if(vm.count("probing-rate")){
        options.pps = vm["probing-rate"].as<uint32_t>();
    }
    else {
        std::cerr << "Please provide a probing rate. Exiting...\n";
        exit(1);
    }
    if(vm.count("inf-born")){
        options.inf_born = vm["inf-born"].as<uint32_t>();
    } else {
        options.inf_born = std::numeric_limits<uint32_t>::min();
    }
    if(vm.count("sup-born")){
        options.sup_born = vm["sup-born"].as<uint32_t>();
    } else {
        options.sup_born = std::numeric_limits<uint32_t>::max();
    }
    if(vm.count("destinations")){
        options.n_destinations_per_24 = vm["destinations"].as<uint32_t >();
        std::cout << "Destinations per /24:" << options.n_destinations_per_24 << "\n";
    } else {
        options.n_destinations_per_24 = 1;
    }
    if(vm.count("only-routable")){
        options.is_only_routable = true;
        if (vm.count("bgp-file")){
            options.bgp_file = vm["bgp-file"].as<std::string>();
        } else {
            std::cerr << "Missing a bgp file. Exiting...\n";
            exit(1);
        }
    } else {
        options.is_only_routable = false;
    }

    if (vm.count("record-timestamp")){
        options.is_record_timestamp = true;
        if (vm.count("start-time-log-file")){
            options.start_time_log_file = vm["start-time-log-file"].as<std::string>();
        } else {
            std::cerr << "Missing a start-time-log file. Exiting...\n";
            exit(1);
        }
    } else {
        options.is_record_timestamp = false;
    }


    if (vm.count("send-from-targets-file")) {
        options.is_send_from_targets_file = true;
        if (vm.count("targets-file")){
            options.targets_file = vm["targets-file"].as<std::string>();
        } else {
            std::cerr << "Missing a targets file. Exiting...\n";
            exit(1);
        }
    } else {
        options.is_send_from_targets_file = false;
    }


    NetworkInterface default_interface = NetworkInterface::default_interface();
    NetworkInterface interface = default_interface;
    if (!options.interface.empty()){
        interface = NetworkInterface(options.interface);
    }
    std::cout << "Probing interface: " << interface.name() << "\n";
    // Find gateway of the addresses
    IPv4Address gateway_ip;
    Utils::gateway_from_ip("8.8.8.8", gateway_ip);


    PacketSender resolve_gateway_sender {default_interface};
    auto hw_gateway = Utils::resolve_hwaddr(gateway_ip, resolve_gateway_sender);
    std::cout << "Gateway MAC address: " << hw_gateway.to_string() << "\n";


    heartbeat_t heartbeat(interface.name(), hw_gateway.to_string(), options);

    heartbeat.start();

    return 0;
}