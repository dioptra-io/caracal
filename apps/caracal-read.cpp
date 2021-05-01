#include <caracal-config.h>
#include <spdlog/cfg/helpers.h>

#include <caracal/reader.hpp>
#include <caracal/utilities.hpp>
#include <cxxopts.hpp>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

using std::string;

int main(int argc, char** argv) {
  std::cout << "caracal-read"
            << " v" << CARACAL_SEMVER << " (" << CARACAL_BUILD_TYPE
            << " build)";
  std::cout << std::endl;

  cxxopts::Options options("caracal");

  // clang-format off
  options.add_options()
    ("h,help", "Show this message")
    ("i,input-file", "PCAP file containing the captured replies (required)", cxxopts::value<string>())
    ("o,output-file-csv", "File to which the parsed replies will be written as CSV (required)", cxxopts::value<string>())
    ("L,log-level", "Minimum log level (trace, debug, info, warning, error, fatal)", cxxopts::value<string>()->default_value("info"))
    ("caracal-id", "Identifier encoded in the probes (random by default)", cxxopts::value<int>())
    ("meta-round", "Value of the round column in the CSV output", cxxopts::value<string>())
    ("no-integrity-check", "Do not check that replies match valid probes", cxxopts::value<bool>()->default_value("false"));
  // clang-format on

  auto result = options.parse(argc, argv);

  if (result.count("help") || result.count("input-file") == 0 ||
      result.count("output-file-csv") == 0) {
    std::cout << options.help() << std::endl;
    return 0;
  }

  try {
    fs::path input_file{result["input-file"].as<string>()};
    fs::path output_file{result["output-file-csv"].as<string>()};
    string round = result["meta-round"].as<string>();
    uint16_t caracal_id = result["caracal-id"].as<int>();
    bool integrity_check = !result.count("no-integrity-check");

    spdlog::cfg::helpers::load_levels(result["log-level"].as<string>());
    caracal::Reader::read(input_file, output_file, round, caracal_id,
                          integrity_check);
  } catch (const std::exception& e) {
    auto type = caracal::Utilities::demangle(typeid(e).name());
    std::cerr << "Exception of type " << type << ": " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
