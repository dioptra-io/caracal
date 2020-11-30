#include "heartbeat.hpp"

#include <catch2/catch.hpp>
#include <filesystem>
#include <iostream>

#include "heartbeat_config.hpp"

namespace fs = std::filesystem;

TEST_CASE("send_heartbeat") {
  fs::path path{"zzz_input.csv"};
  std::ofstream ofs{path};
  ofs << "127.0.0.1,03242,03231,020\n";
  ofs << "127.0.0.1,03242,03232,001\n";
  ofs.close();

  HeartbeatConfigBuilder builder;
  builder.set_interface("lo");
  builder.set_input_file("zzz_input.csv");
  builder.set_output_file("zzz_output.pcap");
  builder.set_protocol("udp");
  builder.set_probing_rate(100);
  builder.set_sniffer_buffer_size(20000);
  builder.set_n_packets(3);
  auto config = builder.build();

  auto [probes_sent, received_count] = send_heartbeat(config);
  REQUIRE(probes_sent == 2);
  REQUIRE(received_count == 6);

  fs::remove("zzz_input.csv");
  fs::remove("zzz_output.pcap");
}
