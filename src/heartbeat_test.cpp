#include "heartbeat.hpp"

#include <catch2/catch.hpp>
#include <filesystem>
#include <iostream>

#include "heartbeat_config.hpp"

namespace fs = std::filesystem;

TEST_CASE("send_heartbeat") {
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

  HeartbeatConfigBuilder builder;
  builder.set_interface("lo");
  builder.set_input_file("zzz_input.csv");
  builder.set_output_file("zzz_output.pcap");
  builder.set_prefix_excl_file("zzz_excl.csv");
  builder.set_prefix_incl_file("zzz_incl.csv");
  builder.set_filter_min_ip("0.0.0.0");
  builder.set_filter_max_ip("255.255.255.255");
  builder.set_filter_min_ttl(1);
  builder.set_filter_max_ttl(6);
  builder.set_probing_rate(100);
  builder.set_sniffer_buffer_size(20000);
  builder.set_protocol("udp");
  builder.set_n_packets(3);

  auto [probes_sent, received_count] = send_heartbeat(builder.build());
  REQUIRE(probes_sent == 2);
  // We should received port unreachable messages.
  REQUIRE(received_count == 6);

  fs::remove("zzz_input.csv");
  fs::remove("zzz_output.pcap");
}
