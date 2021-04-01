#pragma once

#include <filesystem>
#include <string>

#include "statistics.hpp"

namespace fs = std::filesystem;

/// Read and convert PCAP files.
namespace caracal::Reader {

Statistics::Sniffer read(const fs::path& input_file,
                         const fs::path& output_file, const std::string& round);

}  // namespace caracal::Reader
