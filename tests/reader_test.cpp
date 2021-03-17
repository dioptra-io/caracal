#include <spdlog/cfg/helpers.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <dminer/reader.hpp>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

using dminer::Reader::read;

static auto data = fs::path{__FILE__}.parent_path() / ".." / "data";

inline auto read_lines(const std::string& file) {
  std::ifstream f{file};
  std::string line;
  std::vector<std::string> lines;
  while (std::getline(f, line)) {
    lines.push_back(line);
  }
  return lines;
}

TEST_CASE("Reader::read") {
  spdlog::cfg::helpers::load_levels("trace");
  read(data / "sample_results.pcap", "zzz_output.csv", "1", false);

  auto ref = read_lines(data / "sample_results.csv");
  auto res = read_lines("zzz_output.csv");

  REQUIRE(res.size() == ref.size());
  for (uint64_t i = 0; i < res.size(); i++) {
    REQUIRE(res[i] == ref[i] + ",1");
  }

  fs::remove("zzz_output.csv");
}
