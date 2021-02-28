#pragma once

#include <filesystem>
#include <string>

#include "statistics.hpp"

namespace fs = std::filesystem;

/// Read and convert PCAP files.
namespace dminer::Reader {

Statistics::Sniffer read(fs::path &input_file, fs::path &output_file,
                         std::string &round);

}  // namespace dminer::Reader
