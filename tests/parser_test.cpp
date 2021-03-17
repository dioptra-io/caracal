#include <tins/tins.h>

#include <catch2/catch_test_macros.hpp>
#include <dminer/parser.hpp>
#include <dminer/utilities.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using dminer::Parser::parse;
using dminer::Utilities::format_addr;

namespace fs = std::filesystem;

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

inline auto parse_file(const std::string& file) {
  Tins::FileSniffer sniffer{file};
  std::vector<dminer::Reply> res;

  auto handler = [&res](Tins::Packet& packet) {
    auto reply = parse(packet);
    if (reply) {
      res.push_back(reply.value());
    }
    return true;
  };

  sniffer.sniff_loop(handler);
  return res;
}

// Bunch of replies to UDP probes, parsed with the original "reader" code.
TEST_CASE("Parser::parse/sample") {
  auto ref = read_lines(data / "sample_results.csv");
  auto res = parse_file(data / "sample_results.pcap");

  REQUIRE(res.size() == ref.size());
  for (uint64_t i = 0; i < res.size(); i++) {
    REQUIRE(res[i].to_csv(false) == ref[i]);
  }
}

// Replies to ICMP probes.
TEST_CASE("Parser::parse/ICMP") {
  SECTION("ICMP TTL Exceeded") {
    auto res = parse_file(data / "icmp-icmp-ttl-exceeded.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(format_addr(reply.src_ip) == "72.14.204.68");
    REQUIRE(format_addr(reply.dst_ip) == "192.168.1.5");
    REQUIRE(reply.size == 56);
    REQUIRE(reply.ttl == 250);
    REQUIRE(reply.icmp_type == 11);
    REQUIRE(reply.icmp_code == 0);
    REQUIRE(format_addr(reply.inner_dst_ip) == "8.8.8.8");
    REQUIRE(reply.inner_size == 36);
    REQUIRE(reply.inner_ttl == 6);
    REQUIRE(reply.inner_ttl_from_transport == 6);
    REQUIRE(reply.inner_proto == 1);
    REQUIRE(reply.inner_src_port == 24000);
    REQUIRE(reply.inner_dst_port == 0);
    REQUIRE(reply.rtt == 6.6);
  }

  SECTION("ICMP Echo Reply") {
    auto res = parse_file(data / "icmp-icmp-echo-reply.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(format_addr(reply.src_ip) == "8.8.8.8");
    REQUIRE(format_addr(reply.dst_ip) == "192.168.1.5");
    REQUIRE(reply.size == 40);
    REQUIRE(reply.ttl == 117);
    REQUIRE(reply.icmp_type == 0);
    REQUIRE(reply.icmp_code == 0);
    REQUIRE(format_addr(reply.inner_dst_ip) == "::");
    REQUIRE(reply.inner_size == 0);
    REQUIRE(reply.inner_ttl == 0);
    REQUIRE(reply.inner_ttl_from_transport == 10);
    REQUIRE(reply.inner_proto == 1);
    REQUIRE(reply.inner_src_port == 24000);
    REQUIRE(reply.inner_dst_port == 0);
    REQUIRE(reply.rtt == 6.9);
  }
}

TEST_CASE("Parser::parse/ICMPv6") {
  SECTION("ICMPv6 TTL Exceeded") {
    auto res = parse_file(data / "icmp6-icmp6-ttl-exceeded.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(format_addr(reply.src_ip) == "2a04:8ec0:0:a::1:119");
    REQUIRE(format_addr(reply.dst_ip) == "2a04:8ec0:0:164:620c:e59a:daf8:21e9");
    REQUIRE(reply.size == 60);
    REQUIRE(reply.ttl == 63);
    REQUIRE(reply.icmp_type == 3);
    REQUIRE(reply.icmp_code == 0);
    REQUIRE(format_addr(reply.inner_dst_ip) == "2001:4860:4860::8888");
    REQUIRE(reply.inner_size == 12);
    REQUIRE(reply.inner_ttl == 2);
    REQUIRE(reply.inner_ttl_from_transport == 2);
    REQUIRE(reply.inner_proto == 58);
    REQUIRE(reply.inner_src_port == 24000);
    REQUIRE(reply.inner_dst_port == 0);
    REQUIRE(reply.rtt == 0.6);
  }

  SECTION("ICMPv6 Echo Reply") {
    auto res = parse_file(data / "icmp6-icmp6-echo-reply.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(format_addr(reply.src_ip) == "2001:4860:4860::8888");
    REQUIRE(format_addr(reply.dst_ip) == "2a04:8ec0:0:164:620c:e59a:daf8:21e9");
    REQUIRE(reply.size == 18);
    REQUIRE(reply.ttl == 118);
    REQUIRE(reply.icmp_type == 129);
    REQUIRE(reply.icmp_code == 0);
    REQUIRE(format_addr(reply.inner_dst_ip) == "::");
    REQUIRE(reply.inner_size == 0);
    REQUIRE(reply.inner_ttl == 0);
    REQUIRE(reply.inner_ttl_from_transport == 8);
    REQUIRE(reply.inner_proto == 58);
    REQUIRE(reply.inner_src_port == 24000);
    REQUIRE(reply.inner_dst_port == 0);
    REQUIRE(reply.rtt == 1.3);
  }
}

// Replies to UDP probes.
TEST_CASE("Parser::parse/UDP") {
  SECTION("ICMP TTL Exceeded") {
    auto res = parse_file(data / "udp-icmp-ttl-exceeded.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(format_addr(reply.src_ip) == "72.14.204.68");
    REQUIRE(format_addr(reply.dst_ip) == "192.168.1.5");
    REQUIRE(reply.size == 56);
    REQUIRE(reply.ttl == 250);
    REQUIRE(reply.icmp_type == 11);
    REQUIRE(reply.icmp_code == 0);
    REQUIRE(format_addr(reply.inner_dst_ip) == "8.8.8.8");
    REQUIRE(reply.inner_size == 36);
    REQUIRE(reply.inner_ttl == 6);
    REQUIRE(reply.inner_ttl_from_transport == 6);
    REQUIRE(reply.inner_proto == 17);
    REQUIRE(reply.inner_src_port == 24000);
    REQUIRE(reply.inner_dst_port == 33434);
    REQUIRE(reply.rtt == 8.3);
  }

  SECTION("ICMPv6 TTL Exceeded") {
    auto res = parse_file(data / "udp-icmp6-ttl-exceeded.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(format_addr(reply.src_ip) == "2a04:8ec0:0:a::1:119");
    REQUIRE(format_addr(reply.dst_ip) == "2a04:8ec0:0:164:620c:e59a:daf8:21e9");
    REQUIRE(reply.size == 60);
    REQUIRE(reply.ttl == 63);
    REQUIRE(reply.icmp_type == 3);
    REQUIRE(reply.icmp_code == 0);
    REQUIRE(format_addr(reply.inner_dst_ip) == "2001:4860:4860::8888");
    REQUIRE(reply.inner_size == 12);
    REQUIRE(reply.inner_ttl == 2);
    REQUIRE(reply.inner_ttl_from_transport == 2);
    REQUIRE(reply.inner_proto == 17);
    REQUIRE(reply.inner_src_port == 24000);
    REQUIRE(reply.inner_dst_port == 33434);
    REQUIRE(reply.rtt == 0.6);
  }
}
