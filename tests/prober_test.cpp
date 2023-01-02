#include <spdlog/cfg/helpers.h>

#include <caracal/prober.hpp>
#include <caracal/prober_config.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <cstdlib>
#include <filesystem>
#include <iostream>

#include "./environment.hpp"

namespace fs = std::filesystem;

using caracal::Prober::Config;
using caracal::Prober::probe;

// NOTE: These tests can be "flaky" depending on the host and the network where
// the tests are run. If the number of packets received is lower than expected,
// this is not necessaraily a bug.

TEST_CASE("Prober::probe/v4") {
  auto protocol = GENERATE("icmp", "udp");
  std::ofstream ofs;

  ofs.open("zzz_input.csv");
  ofs << fmt::format("8.8.8.8,24000,33434,1,{}\n", protocol);  // Allowed
  ofs << fmt::format("8.8.8.8,24000,33434,2,{}\n", protocol);  // Allowed
  ofs << fmt::format("8.8.8.8,24000,33434,0,{}\n",
                     protocol);  // Denied (TTL too low)
  ofs << fmt::format("8.8.8.8,24000,33434,8,{}\n",
                     protocol);  // Denied (TTL too high)
  ofs << fmt::format("8.8.9.1,24000,33434,2,{}\n",
                     protocol);  // Denied (prefix excluded)
  ofs << fmt::format("8.3.4.1,24000,33434,2,{}\n",
                     protocol);  // Denied (prefix not included)
  ofs << "a,b,c,d,e,f\n";  // Invalid probe (should not crash, and should not be
                           // included in read stats)
  ofs.close();

  ofs.open("zzz_excl.csv");
  ofs << "8.8.9.0/24\n";
  ofs.close();

  ofs.open("zzz_incl.csv");
  ofs << "8.8.0.0/16\n";
  ofs.close();

  Config config;
  config.set_output_file_csv("zzz_output.csv");
  config.set_output_file_pcap("zzz_output.pcap");
  config.set_prefix_excl_file("zzz_excl.csv");
  config.set_prefix_incl_file("zzz_incl.csv");
  config.set_filter_min_ttl(1);
  config.set_filter_max_ttl(6);
  config.set_batch_size(1);
  config.set_probing_rate(10);
  config.set_sniffer_wait_time(1);
  config.set_n_packets(3);
  config.set_meta_round("1");
  config.set_integrity_check(true);

  spdlog::cfg::helpers::load_levels("trace");

  SECTION("Base case") {
    auto [prober_stats, sniffer_stats, pcap_stats] =
        probe(config, "zzz_input.csv");
    REQUIRE(prober_stats.read == 6);
    REQUIRE(prober_stats.sent == 6);
    REQUIRE(prober_stats.filtered_lo_ttl == 1);
    REQUIRE(prober_stats.filtered_hi_ttl == 1);
    REQUIRE(prober_stats.filtered_prefix_excl == 1);
    REQUIRE(prober_stats.filtered_prefix_not_incl == 1);
    if (!is_github) {
      REQUIRE(sniffer_stats.received_count >= 2);
      REQUIRE(sniffer_stats.received_invalid_count == 0);
      REQUIRE(!sniffer_stats.icmp_messages_all.empty());
      REQUIRE(!sniffer_stats.icmp_messages_path.empty());
    }
  }

  SECTION("Include list with missing new line") {
    // Should not crash and should filter the prefixes not included.
    ofs.open("zzz_incl.csv");
    ofs << "8.8.0.0/16";
    ofs.close();

    auto [prober_stats, sniffer_stats, pcap_stats] =
        probe(config, "zzz_input.csv");
    REQUIRE(prober_stats.sent == 6);
    if (!is_github) {
      REQUIRE(sniffer_stats.received_count == 6);
    }
    REQUIRE(sniffer_stats.received_invalid_count == 0);
  }

  SECTION("Empty exclude list") {
    // Should not crash and should not filter prefixes.
    ofs.open("zzz_excl.csv");
    ofs << "";
    ofs.close();

    auto [prober_stats, sniffer_stats, pcap_stats] =
        probe(config, "zzz_input.csv");
    REQUIRE(prober_stats.sent == 9);
    if (!is_github) {
      REQUIRE(sniffer_stats.received_count == 9);
    }
    REQUIRE(sniffer_stats.received_invalid_count == 0);
  }

  SECTION("Empty include list") {
    // Should not crash and should filter all prefixes.
    ofs.open("zzz_incl.csv");
    ofs << "";
    ofs.close();

    auto [prober_stats, sniffer_stats, pcap_stats] =
        probe(config, "zzz_input.csv");
    REQUIRE(prober_stats.sent == 0);
    REQUIRE(sniffer_stats.received_count == 0);
    REQUIRE(sniffer_stats.received_invalid_count == 0);
  }

  fs::remove("zzz_excl.csv");
  fs::remove("zzz_incl.csv");
  fs::remove("zzz_input.csv");
  fs::remove("zzz_output.csv");
  fs::remove("zzz_output.pcap");
}

TEST_CASE("Prober::probe/v6") {
  auto dst_addr = "2a00:1450:4007:819::200e";  // google.com
  auto protocol = "icmp6";
  uint32_t flow_label = 1;
  std::ofstream ofs;

  ofs.open("zzz_input.csv");
  ofs << fmt::format("{},24000,33434,1,{},{}\n", dst_addr, protocol,
                     flow_label);  // Allowed
  ofs << fmt::format("{},24000,33434,2,{},{}\n", dst_addr, protocol,
                     flow_label);  // Allowed
  ofs << fmt::format("{},24000,33434,0,{},{}\n", dst_addr, protocol,
                     flow_label);  // Denied (TTL too low)
  ofs << fmt::format("{},24000,33434,8,{},{}\n", dst_addr, protocol,
                     flow_label);  // Denied (TTL too high)
  ofs << fmt::format("2b00:1450:4007:819::200e,24000,33434,2,{},{}\n", protocol,
                     flow_label);  // Denied (prefix IPv6 not included)
  ofs << fmt::format("2a00:1450:4007:818::200e,24000,33434,2,{},{}\n", protocol,
                     flow_label);  // Denied (prefix IPv6 excluded)
  ofs.close();

  ofs.open("zzz_excl.csv");
  ofs << "2a00:1450:4007:818::/64\n";
  ofs.close();

  ofs.open("zzz_incl.csv");
  ofs << "2a00::/12\n";
  ofs.close();

  Config config;
  config.set_output_file_csv("zzz_output.csv");
  config.set_output_file_pcap("zzz_output.pcap");
  config.set_prefix_excl_file("zzz_excl.csv");
  config.set_prefix_incl_file("zzz_incl.csv");
  config.set_filter_min_ttl(1);
  config.set_filter_max_ttl(6);
  config.set_batch_size(1);
  config.set_probing_rate(10);
  config.set_sniffer_wait_time(1);
  config.set_n_packets(3);
  config.set_meta_round("1");
  config.set_integrity_check(true);

  spdlog::cfg::helpers::load_levels("trace");

  if (has_ipv6) {
    auto [prober_stats, sniffer_stats, pcap_stats] =
        probe(config, "zzz_input.csv");
    REQUIRE(prober_stats.read == 6);
    REQUIRE(prober_stats.sent == 6);
    REQUIRE(prober_stats.filtered_lo_ttl == 1);
    REQUIRE(prober_stats.filtered_hi_ttl == 1);
    REQUIRE(prober_stats.filtered_prefix_excl == 1);
    REQUIRE(prober_stats.filtered_prefix_not_incl == 1);
    REQUIRE(sniffer_stats.received_count >= 2);
    REQUIRE(sniffer_stats.received_invalid_count == 0);
    REQUIRE(!sniffer_stats.icmp_messages_all.empty());
    REQUIRE(!sniffer_stats.icmp_messages_path.empty());
  }

  fs::remove("zzz_excl.csv");
  fs::remove("zzz_incl.csv");
  fs::remove("zzz_input.csv");
  fs::remove("zzz_output.csv");
  fs::remove("zzz_output.pcap");
}
