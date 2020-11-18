#include "probe.hpp"

#include <catch2/catch.hpp>
#include <filesystem>
#include <fstream>
#include <vector>

namespace fs = std::filesystem;

template <typename F>
std::vector<Probe> collect(F lambda) {
  std::vector<Probe> values;
  for (auto value : lambda()) {
    values.push_back(value);
  }
  return values;
}

TEST_CASE("CSVProbeReader") {
  fs::path path{"zzz_probes.csv"};
  std::ofstream ofs{path};
  ofs << "192.168.001.001,03242,03231,020\n";
  ofs << "192.168.001.002,03242,03232,001\n";
  ofs.close();

  // TODO: Test data validation (col must not be < 1), ...
  auto values = collect([path]() { return CSVProbeReader{path}; });
  REQUIRE(values.size() == 2);
  REQUIRE(values[0].human_dst_addr() == "192.168.1.1");
  REQUIRE(values[0].src_port == 3242);
  REQUIRE(values[0].dst_port == 3231);
  REQUIRE(values[0].ttl == 20);

  fs::remove(path);
}
