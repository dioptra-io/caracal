#include <tins/tins.h>

#include <catch2/catch.hpp>
#include <dminer/parser.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using dminer::Parser::parse;

namespace fs = std::filesystem;

std::vector<std::string> read_lines(const std::string& file) {
  std::ifstream f{file};
  std::string line;
  std::vector<std::string> lines;
  while (std::getline(f, line)) {
    lines.push_back(line);
  }
  return lines;
}

std::vector<std::string> parse_file(const std::string& file) {
  Tins::FileSniffer sniffer{file};
  std::vector<std::string> res;

  auto handler = [&res](Tins::Packet& packet) {
    auto reply = parse(packet, false);
    if (reply) {
      res.push_back(reply.value().to_csv());
    }
    return true;
  };

  sniffer.sniff_loop(handler);
  return res;
}

TEST_CASE("Parser::parse") {
  // TODO: Test RTT estimation.
  auto data = fs::path{__FILE__}.parent_path() / ".." / "data";
  auto ref = read_lines(data / "sample_results.csv");
  auto res = parse_file(data / "sample_results.pcap");

  REQUIRE(res.size() == ref.size());
  for (uint64_t i = 0; i < res.size(); i++) {
    REQUIRE(res[i] == ref[i]);
  }
}
