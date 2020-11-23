#pragma once

#include <tins/tins.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

using std::optional;
using std::string;

namespace fs = std::filesystem;

struct HeartbeatConfig {
  const optional<fs::path> input_file;
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
  void set_input_file(const fs::path p) {
    if (!fs::exists(p)) {
      throw std::invalid_argument(p.string() + " does not exists");
    }
    m_input_file = p;
  }

  void set_output_file(const fs::path p) { m_output_file = p; }

  void set_start_time_log_file(const fs::path p) { m_start_time_log_file = p; }

  void set_probing_rate(const int rate) {
    if (rate <= 0) {
      throw std::domain_error("rate must be > 0");
    }
    m_probing_rate = rate;
  }

  void set_protocol(const string s) {
    if (s == "udp" || s == "tcp") {
      m_protocol = s;
    } else {
      throw std::invalid_argument(s + " is not a valid protocol");
    }
  }

  void set_interface(const string s) { m_interface = s; }

  void set_sniffer_buffer_size(const int size) {
    if (size <= 0) {
      throw std::domain_error("sniffer_buffer_size must be > 0");
    }
    m_sniffer_buffer_size = size;
  }

  void set_max_probes(const int count) {
    if (count <= 0) {
      throw std::domain_error("max_probes must be > 0");
    }
    m_max_probes = count;
  }

  void set_n_packets(const int count) {
    if (count <= 0) {
      throw std::domain_error("n_packets must be > 0");
    }
    m_n_packets = count;
  }

  void set_bgp_filter_file(const fs::path p) {
    if (!fs::exists(p)) {
      throw std::invalid_argument(p.string() + " does not exists");
    }
    m_bgp_filter_file = p;
  }

  void set_prefix_filter_file(const fs::path p) {
    if (!fs::exists(p)) {
      throw std::invalid_argument(p.string() + " does not exists");
    }
    m_prefix_filter_file = p;
  }

  void set_filter_min_ip(const string s) {
    m_filter_min_ip = Tins::IPv4Address{s};
  }

  void set_filter_max_ip(const string s) {
    m_filter_max_ip = Tins::IPv4Address{s};
  }

  void set_filter_min_ttl(const int ttl) {
    if (ttl < 0) {
      throw std::domain_error("min_ttl must be > 0");
    }
    m_filter_min_ttl = ttl;
  }

  void set_filter_max_ttl(const int ttl) {
    if (ttl < 0) {
      throw std::domain_error("max_ttl must be > 0");
    }
    m_filter_max_ttl = ttl;
  }

  HeartbeatConfig build() const {
    if (!m_output_file) {
      throw std::invalid_argument("No output file provided");
    }

    if (!m_protocol) {
      throw std::invalid_argument("No protocol specified");
    }

    if (!m_probing_rate) {
      throw std::invalid_argument("No probing rate specified");
    }

    if (!m_sniffer_buffer_size) {
      throw std::invalid_argument("No sniffer buffer size specified");
    }

    if (!m_n_packets) {
      throw std::invalid_argument("No packet count specified");
    }

    Tins::NetworkInterface interface;
    if (m_interface) {
      interface = Tins::NetworkInterface{m_interface.value()};
    } else {
      interface = Tins::NetworkInterface::default_interface();
    }

    // TODO: Destination port parameter?
    // TODO: min/max IP/TTL
    return HeartbeatConfig{m_input_file,
                           m_output_file.value(),
                           m_start_time_log_file,
                           m_max_probes,
                           m_n_packets.value(),
                           m_probing_rate.value(),
                           m_sniffer_buffer_size.value(),
                           m_protocol.value(),
                           interface,
                           m_bgp_filter_file,
                           m_prefix_filter_file};
  }

 private:
  optional<fs::path> m_input_file;
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
  optional<Tins::IPv4Address> m_filter_min_ip;
  optional<Tins::IPv4Address> m_filter_max_ip;
  optional<int> m_filter_min_ttl;
  optional<int> m_filter_max_ttl;
};

inline std::ostream& operator<<(std::ostream& os, HeartbeatConfig const& v) {
  os << "HeartbeatConfig{";
  if (v.input_file) {
    os << "\n\tinput_file=" << v.input_file.value();
  }
  os << "\n\toutput_file=" << v.output_file;
  os << ",\n\tstart_time_log_file=" << v.start_time_log_file.value_or("");
  if (v.max_probes) {
    os << ",\n\tmax_probes=" << v.max_probes.value();
  }
  os << ",\n\tn_packets=" << v.n_packets;
  os << ",\n\tprobing_rate=" << v.probing_rate;
  os << ",\n\tsniffer_buffer_size=" << v.sniffer_buffer_size;
  os << ",\n\tprotocol=" << v.protocol;
  os << ",\n\tinterface=" << v.interface.name() << ":"
     << v.interface.ipv4_address();
  os << "\n}";
  return os;
}
