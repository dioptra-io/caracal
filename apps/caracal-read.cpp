#include <caracal-config.h>
#include <spdlog/cfg/helpers.h>

#include <boost/core/demangle.hpp>
#include <boost/program_options.hpp>
#include <caracal/reader.hpp>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;
namespace po = boost::program_options;

using std::string;

int main(int argc, char** argv) {
  std::cout << "caracal-read"
            << " v" << CARACAL_SEMVER << " (" << CARACAL_BUILD_TYPE
            << " build)";
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

    spdlog::cfg::helpers::load_levels(vm["log-level"].as<string>());
    caracal::Reader::read(input_file, output_file, round);
  } catch (const std::exception& e) {
    auto type = boost::core::demangle(typeid(e).name());
    std::cerr << "Exception of type " << type << ": " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
