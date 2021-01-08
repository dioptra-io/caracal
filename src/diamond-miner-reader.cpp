#include <diamond-miner-config.h>

#include <boost/program_options.hpp>
#include <dminer/logging.hpp>
#include <dminer/reader.hpp>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;
namespace po = boost::program_options;

using std::string;

int main(int argc, char** argv) {
  std::cout << "diamond-miner-reader"
            << " v" << DMINER_VERSION_MAJOR << "." << DMINER_VERSION_MINOR
            << "." << DMINER_VERSION_PATCH;
  std::cout << std::endl;

  po::options_description all("Options");

  // clang-format off
  all.add_options()
    ("help,h", "Show this message")
    ("input-file,i", po::value<string>()->value_name("file")->required(), "PCAP file containing the captured replies")
    ("output-file-csv,o", po::value<string>()->value_name("file")->required(), "File to which the parsed replies will be written as CSV")
    ("log-level,L", po::value<string>()->value_name("level")->default_value("info"), "Minimum log level (trace, debug, info, warning, error, fatal)")
    ("meta-round", po::value<string>()->value_name("value")->default_value("1"), "Value of the round column in the CSV output");
  // clang-format on

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, all), vm);

  if (vm.count("help")) {
    std::cout << all << std::endl;
    return 0;
  }

  try {
    po::notify(vm);

    fs::path input_file{vm["input-file"].as<string>()};
    fs::path output_file{vm["output-file-csv"].as<string>()};
    string round = vm["meta-round"].as<string>();

    configure_logging(vm["log-level"].as<string>());
    read_packets(input_file, output_file, round);
  } catch (const std::exception& e) {
    std::cerr << "Exception: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
