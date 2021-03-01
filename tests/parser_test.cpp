#include <tins/tins.h>

#include <catch2/catch_test_macros.hpp>
#include <dminer/parser.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using dminer::Parser::parse;

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

// host_addr: address in host order.
inline auto to_string(uint32_t host_addr) {
  in_addr addr{ntohl(host_addr)};
  char buf[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
  return std::string{buf};
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
    REQUIRE(to_string(reply.src_ip) == "72.14.204.68");
    REQUIRE(to_string(reply.dst_ip) == "192.168.1.5");
    REQUIRE(reply.size == 56);
    REQUIRE(reply.ttl == 250);
    REQUIRE(reply.icmp_type == 11);
    REQUIRE(reply.icmp_code == 0);
    REQUIRE(to_string(reply.inner_dst_ip) == "8.8.8.8");
    REQUIRE(reply.inner_size == 36);
    REQUIRE(reply.inner_ttl == 6);
    REQUIRE(reply.inner_proto == 1);
    REQUIRE(reply.inner_src_port == 24000);
    REQUIRE(reply.inner_dst_port == 0);
    REQUIRE(reply.inner_ttl_from_transport == 6);
    REQUIRE(reply.rtt == 6.6);
  }

  SECTION("ICMP Echo Reply") {
    auto res = parse_file(data / "icmp-icmp-echo-reply.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(to_string(reply.src_ip) == "8.8.8.8");
    REQUIRE(to_string(reply.dst_ip) == "192.168.1.5");
    REQUIRE(reply.size == 40);
    REQUIRE(reply.ttl == 117);
    REQUIRE(reply.icmp_type == 0);
    REQUIRE(reply.icmp_code == 0);
    REQUIRE(reply.inner_dst_ip == 0);
    REQUIRE(reply.inner_size == 0);
    REQUIRE(reply.inner_ttl == 0);
    REQUIRE(reply.inner_proto == 1);
    REQUIRE(reply.inner_src_port == 24000);
    REQUIRE(reply.inner_dst_port == 0);
    REQUIRE(reply.inner_ttl_from_transport == 10);
    REQUIRE(reply.rtt == 6.9);
  }
}

// Replies to UDP probes.
TEST_CASE("Parser::parse/UDP") {
  SECTION("ICMP TTL Exceeded") {
    auto res = parse_file(data / "udp-icmp-ttl-exceeded.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(to_string(reply.src_ip) == "72.14.204.68");
    REQUIRE(to_string(reply.dst_ip) == "192.168.1.5");
    REQUIRE(reply.size == 56);
    REQUIRE(reply.ttl == 250);
    REQUIRE(reply.icmp_type == 11);
    REQUIRE(reply.icmp_code == 0);
    REQUIRE(to_string(reply.inner_dst_ip) == "8.8.8.8");
    REQUIRE(reply.inner_size == 36);
    REQUIRE(reply.inner_ttl == 6);
    REQUIRE(reply.inner_proto == 17);
    REQUIRE(reply.inner_src_port == 24000);
    REQUIRE(reply.inner_dst_port == 33434);
    REQUIRE(reply.inner_ttl_from_transport == 6);
    REQUIRE(reply.rtt == 8.3);
  }
}
