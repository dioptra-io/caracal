#pragma once

#include <tuple>

#include "prober_config.hpp"
#include "statistics.hpp"

/// Build and send probes.
namespace caracal::Prober {

std::tuple<Statistics::Prober, Statistics::Sniffer> probe(const Config& config);

}
