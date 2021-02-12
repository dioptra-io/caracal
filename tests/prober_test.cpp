#include <spdlog/cfg/helpers.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <dminer/prober.hpp>
#include <dminer/prober_config.hpp>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

using dminer::Prober::Config;
using dminer::Prober::probe;

TEST_CASE("Prober::probe") {
  auto protocol = GENERATE("icmp", "udp");
  std::ofstream ofs;

  // TODO: IPv6.

  ofs.open("zzz_input.csv");
  ofs << "8.8.8.8,24000,33434,1\n";  // Allowed
  ofs << "8.8.8.8,24000,33434,2\n";  // Allowed
  ofs << "8.8.8.8,24000,33434,0\n";  // Denied (TTL too low)
  ofs << "8.8.8.8,24000,33434,8\n";  // Denied (TTL too high)
  ofs << "8.8.9.1,24000,33434,2\n";  // Denied (prefix excluded)
  ofs << "8.9.8.8,24000,33434,2\n";  // Denied (prefix not included)
  ofs << "a,b,c,d\n";  // Invalid probe (should not crash, and should not be
                       // included in read stats)
  ofs.close();

  ofs.open("zzz_excl.csv");
  ofs << "8.8.9.0/24\n";
  ofs.close();

  ofs.open("zzz_incl.csv");
  ofs << "8.8.0.0/16\n";
  ofs.close();

  Config config;
  config.set_input_file("zzz_input.csv");
  config.set_output_file_csv("zzz_output.csv");
  config.set_output_file_pcap("zzz_output.pcap");
  config.set_prefix_excl_file("zzz_excl.csv");
  config.set_prefix_incl_file("zzz_incl.csv");
  config.set_filter_min_ttl(1);
  config.set_filter_max_ttl(6);
  config.set_probing_rate(100);
  config.set_sniffer_buffer_size(20000);
  config.set_sniffer_wait_time(1);
  config.set_protocol(protocol);
  config.set_n_packets(3);
  config.set_meta_round("1");

  spdlog::cfg::helpers::load_levels("trace");

  SECTION("Base case") {
    auto [prober_stats, sniffer_stats] = probe(config);
    REQUIRE(prober_stats.read == 6);
    REQUIRE(prober_stats.sent == 6);
    REQUIRE(prober_stats.filtered_lo_ttl == 1);
    REQUIRE(prober_stats.filtered_hi_ttl == 1);
    REQUIRE(prober_stats.filtered_prefix_excl == 1);
    REQUIRE(prober_stats.filtered_prefix_not_incl == 1);
    // Some replies are dropped on GitHub CI.
    // REQUIRE(sniffer_stats.received_count == 6);
    REQUIRE(sniffer_stats.received_count >= 2);
    REQUIRE(sniffer_stats.received_invalid_count == 0);
  }

  SECTION("Include list with missing new line") {
    // Should not crash and should filter the prefixes not included.
    ofs.open("zzz_incl.csv");
    ofs << "8.8.0.0/16";
    ofs.close();

    auto [prober_stats, sniffer_stats] = probe(config);
    REQUIRE(prober_stats.sent == 6);
    // Some replies are dropped on GitHub CI.
    // REQUIRE(sniffer_stats.received_count == 6);
    REQUIRE(sniffer_stats.received_count >= 2);
    REQUIRE(sniffer_stats.received_invalid_count == 0);
  }

  SECTION("Empty exclude list") {
    // Should not crash and should not filter prefixes.
    ofs.open("zzz_excl.csv");
    ofs << "";
    ofs.close();

    auto [prober_stats, sniffer_stats] = probe(config);
    REQUIRE(prober_stats.sent == 9);
    // Some replies are dropped on GitHub CI.
    // REQUIRE(sniffer_stats.received_count == 9);
    REQUIRE(sniffer_stats.received_count >= 3);
    REQUIRE(sniffer_stats.received_invalid_count == 0);
  }

  SECTION("Empty include list") {
    // Should not crash and should filter all prefixes.
    ofs.open("zzz_incl.csv");
    ofs << "";
    ofs.close();

    auto [prober_stats, sniffer_stats] = probe(config);
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
