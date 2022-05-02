#pragma once

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

using std::optional;
using std::string;

namespace fs = std::filesystem;

namespace caracal::Prober {

/// Configuration of the prober.
struct Config {
  uint16_t caracal_id = get_default_id();
  uint64_t n_packets = 1;
  uint64_t batch_size = 128;
  uint64_t probing_rate = 100;
  uint64_t sniffer_wait_time = 5;
  bool integrity_check = true;
  std::string interface = get_default_interface();
  string rate_limiting_method = "auto";
  optional<uint64_t> max_probes;
  optional<fs::path> output_file_csv;
  optional<fs::path> output_file_pcap;
  optional<fs::path> prefix_excl_file;
  optional<fs::path> prefix_incl_file;
  optional<int> filter_min_ttl;
  optional<int> filter_max_ttl;
  optional<string> meta_round;

  static uint16_t get_default_id();

  static std::string get_default_interface();

  void set_caracal_id(int id);

  void set_n_packets(int count);

  void set_batch_size(int size);

  void set_probing_rate(int rate);

  void set_sniffer_wait_time(int seconds);

  void set_integrity_check(bool check);

  void set_interface(const string& s);

  void set_rate_limiting_method(const string& s);

  void set_max_probes(uint64_t count);

  void set_output_file_csv(const fs::path& p);

  void set_output_file_pcap(const fs::path& p);

  void set_prefix_excl_file(const fs::path& p);

  void set_prefix_incl_file(const fs::path& p);

  void set_filter_min_ttl(int ttl);

  void set_filter_max_ttl(int ttl);

  void set_meta_round(const string& round);
};

std::ostream& operator<<(std::ostream& os, Config const& v);

}  // namespace caracal::Prober
