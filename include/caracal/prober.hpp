#pragma once

#include <pcap.h>

#include <filesystem>
#include <istream>
#include <tuple>

#include "probe.hpp"
#include "prober_config.hpp"
#include "statistics.hpp"

/// Build and send probes.
namespace caracal::Prober {

/// A function that gets the next probe and returns false when there is no more
/// probes.
using Iterator = std::function<bool(Probe&)>;

using ProbingStatistics =
    std::tuple<Statistics::Prober, Statistics::Sniffer, pcap_stat>;

/// Send probes from a function yielding probes.
ProbingStatistics probe(const Config& config, Iterator& it);

/// Send probes from a CSV stream (e.g. stdin).
ProbingStatistics probe(const Config& config, std::istream& is);

/// Send probes from a file.
ProbingStatistics probe(const Config& config, const fs::path& path);

}  // namespace caracal::Prober
