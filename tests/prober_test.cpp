#include <catch2/catch.hpp>
#include <dminer/prober.hpp>
#include <dminer/prober_config.hpp>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

#ifdef __APPLE__
#define LOOPBACK "lo0"
#else
#define LOOPBACK "lo"
#endif

TEST_CASE("send_probes") {
  std::ofstream ofs;

  ofs.open("zzz_input.csv");
  ofs << "127.0.0.1,24000,33434,1\n";  // Allowed
  ofs << "127.0.0.1,24000,33434,2\n";  // Allowed
  ofs << "127.0.0.1,24000,33434,8\n";  // Denied (TTL)
  ofs << "127.0.1.1,24000,33434,2\n";  // Denied (prefix excluded)
  ofs << "127.1.0.0,24000,33434,2\n";  // Denied (prefix not included)
  ofs.close();

  ofs.open("zzz_excl.csv");
  ofs << "127.0.1.0/24\n";
  ofs.close();

  ofs.open("zzz_incl.csv");
  ofs << "127.0.0.0/16\n";
  ofs.close();

  ProberConfig config;
  config.set_interface(LOOPBACK);
  config.set_input_file("zzz_input.csv");
  config.set_output_file_csv("zzz_output.csv");
  config.set_output_file_pcap("zzz_output.pcap");
  config.set_prefix_excl_file("zzz_excl.csv");
  config.set_prefix_incl_file("zzz_incl.csv");
  config.set_filter_min_ip("0.0.0.0");
  config.set_filter_max_ip("255.255.255.255");
  config.set_filter_min_ttl(1);
  config.set_filter_max_ttl(6);
  config.set_probing_rate(100);
  config.set_sniffer_buffer_size(20000);
  config.set_sniffer_wait_time(1);
  config.set_protocol("udp");
  config.set_n_packets(3);
  config.set_meta_round("1");

  SECTION("Base case") {
    // We should receive port unreachable messages.
    auto [prober_stats, sniffer_stats] = send_probes(config);
    REQUIRE(prober_stats.read == 5);
    REQUIRE(prober_stats.sent == 6);
    REQUIRE(prober_stats.filtered_lo_ip == 0);
    REQUIRE(prober_stats.filtered_hi_ip == 0);
    REQUIRE(prober_stats.filtered_lo_ttl == 0);
    REQUIRE(prober_stats.filtered_hi_ttl == 1);
    REQUIRE(prober_stats.filtered_prefix_excl == 1);
    REQUIRE(prober_stats.filtered_prefix_not_incl == 1);
    REQUIRE(prober_stats.filtered_prefix_not_routable == 0);
    REQUIRE(sniffer_stats.received_count == 6);
  }

  SECTION("Include list with missing new line") {
    // Should not crash and should filter the prefixes not included.
    ofs.open("zzz_incl.csv");
    ofs << "127.0.0.0/16";
    ofs.close();

    auto [prober_stats, sniffer_stats] = send_probes(config);
    REQUIRE(prober_stats.sent == 6);
    REQUIRE(sniffer_stats.received_count == 6);
  }

  SECTION("Empty exclude list") {
    // Should not crash and should not filter prefixes.
    ofs.open("zzz_excl.csv");
    ofs << "";
    ofs.close();

    auto [prober_stats, sniffer_stats] = send_probes(config);
    REQUIRE(prober_stats.sent == 9);
    REQUIRE(sniffer_stats.received_count == 9);
  }

  SECTION("Empty include list") {
    // Should not crash and should filter all prefixes.
    ofs.open("zzz_incl.csv");
    ofs << "";
    ofs.close();

    auto [prober_stats, sniffer_stats] = send_probes(config);
    REQUIRE(prober_stats.sent == 0);
    REQUIRE(sniffer_stats.received_count == 0);
  }

  fs::remove("zzz_excl.csv");
  fs::remove("zzz_incl.csv");
  fs::remove("zzz_input.csv");
  fs::remove("zzz_output.csv");
  fs::remove("zzz_output.pcap");
}
