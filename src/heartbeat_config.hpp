#pragma once

#include <tins/tins.h>

#include <filesystem>
#include <optional>
#include <string>

using std::optional;
using std::string;

namespace fs = std::filesystem;

struct HeartbeatConfig {
  // const fs::path input_file;
  const fs::path output_file;
  const optional<fs::path> start_time_log_file;
  const optional<int> max_probes;
  const int n_packets;
  const int probing_rate;
  const int sniffer_buffer_size;
  const string protocol;
  const Tins::NetworkInterface interface;
  const optional<fs::path> bgp_filter_file;
  const optional<fs::path> prefix_filter_file;
};

class HeartbeatConfigBuilder {
 public:
  // void set_input_file(const fs::path p);
  void set_output_file(const fs::path p);
  void set_start_time_log_file(const fs::path p);
  void set_probing_rate(const int rate);
  void set_protocol(const string s);
  void set_interface(const string s);
  void set_sniffer_buffer_size(const int size);
  void set_max_probes(const int count);
  void set_n_packets(const int count);
  void set_bgp_filter_file(const fs::path p);
  void set_prefix_filter_file(const fs::path p);
  HeartbeatConfig build() const;

 private:
  // optional<fs::path> m_input_file;
  optional<fs::path> m_output_file;
  optional<fs::path> m_start_time_log_file;
  optional<int> m_probing_rate;
  optional<string> m_protocol;
  optional<string> m_interface;
  optional<int> m_sniffer_buffer_size;
  optional<int> m_max_probes;
  optional<int> m_n_packets;
  optional<fs::path> m_bgp_filter_file;
  optional<fs::path> m_prefix_filter_file;
};

std::ostream& operator<<(std::ostream& os, HeartbeatConfig const& v);
