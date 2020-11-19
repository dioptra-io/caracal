#include "csv.hpp"

#include <catch2/catch.hpp>
#include <filesystem>
#include <fstream>
#include <vector>

#include "../probe.hpp"

namespace fs = std::filesystem;

template <typename F>
std::vector<Probe> collect(F lambda) {
  std::vector<Probe> values;
  for (auto value : lambda()) {
    values.push_back(value);
  }
  return values;
}

TEST_CASE("probe_from_csv") {
  Probe probe;

  probe_from_csv("0.0.0.0,1,2,3", probe);
  REQUIRE(probe.human_dst_addr() == "0.0.0.0");
  REQUIRE(probe.dst_addr.s_addr == 0);
  REQUIRE(probe.src_port == 1);
  REQUIRE(probe.dst_port == 2);
  REQUIRE(probe.ttl == 3);

  probe_from_csv("008.008.004.004,0010,1000,050", probe);
  REQUIRE(probe.human_dst_addr() == "8.8.4.4");
  REQUIRE(probe.src_port == 10);
  REQUIRE(probe.dst_port == 1000);
  REQUIRE(probe.ttl == 50);
}

TEST_CASE("CSVProbeReader") {
  fs::path path{"zzz_probes.csv"};
  std::ofstream ofs{path};
  ofs << "192.168.1.001,03242,03231,020\n";
  ofs << "192.168.1.002,03242,03232,001\n";
  ofs.close();

  // TODO: Test data validation (col must not be < 1), ...
  auto values1 = collect([path]() { return CSVProbeReader{path}; });
  REQUIRE(values1.size() == 2);
  REQUIRE(values1[0].human_dst_addr() == "192.168.1.1");
  REQUIRE(values1[0].src_port == 3242);
  REQUIRE(values1[0].dst_port == 3231);
  REQUIRE(values1[0].ttl == 20);

  // Two runs should produce the same sequence.
  auto values2 = collect([path]() { return CSVProbeReader{path}; });
  REQUIRE(values2 == values1);

  fs::remove(path);
}

TEST_CASE("CSVRandomProbeReader") {
  fs::path path{"zzz_probes.csv"};
  std::ofstream ofs{path};
  ofs << "192.168.001.001,03241,03231,020\n";
  ofs << "192.168.001.002,03242,03232,001\n";
  ofs << "192.168.001.003,03243,03233,002\n";
  ofs << "192.168.001.004,03244,03234,003\n";
  ofs << "192.168.001.005,03245,03235,004\n";
  ofs.close();

  // Two subsequent runs should produce different sequences.
  auto values1 = collect([path]() { return CSVRandomProbeReader{path, 32}; });
  auto values2 = collect([path]() { return CSVRandomProbeReader{path, 32}; });

  REQUIRE(values1.size() == 5);
  REQUIRE(values2.size() == 5);
  REQUIRE(values2 != values1);

  fs::remove(path);
}
