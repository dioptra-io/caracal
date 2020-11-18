#include "heartbeat_config.hpp"

#include <tins/tins.h>

#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

/* void HeartbeatConfigBuilder::set_input_file(const fs::path p) { */
// if (!fs::exists(p)) {
//   throw std::invalid_argument(p.string() + " does not exists");
// }
// m_input_file = p;
/* } */

void HeartbeatConfigBuilder::set_output_file(const fs::path p) {
  m_output_file = p;
}

void HeartbeatConfigBuilder::set_start_time_log_file(const fs::path p) {
  m_start_time_log_file = p;
}

void HeartbeatConfigBuilder::set_probing_rate(const int rate) {
  if (rate <= 0) {
    throw std::domain_error("rate must be > 0");
  }
  m_probing_rate = rate;
}

void HeartbeatConfigBuilder::set_protocol(const string s) {
  if (s == "udp" || s == "tcp") {
    m_protocol = s;
  } else {
    throw std::invalid_argument(s + " is not a valid protocol");
  }
}

void HeartbeatConfigBuilder::set_interface(const string s) { m_interface = s; }

void HeartbeatConfigBuilder::set_sniffer_buffer_size(const int size) {
  if (size <= 0) {
    throw std::domain_error("sniffer_buffer_size must be > 0");
  }
  m_sniffer_buffer_size = size;
}

void HeartbeatConfigBuilder::set_max_probes(const int count) {
  if (count <= 0) {
    throw std::domain_error("max_probes must be > 0");
  }
  m_max_probes = count;
}

void HeartbeatConfigBuilder::set_n_packets(const int count) {
  if (count <= 0) {
    throw std::domain_error("n_packets must be > 0");
  }
  m_n_packets = count;
}

void HeartbeatConfigBuilder::set_bgp_filter_file(const fs::path p) {
  if (!fs::exists(p)) {
    throw std::invalid_argument(p.string() + " does not exists");
  }
  m_bgp_filter_file = p;
}

void HeartbeatConfigBuilder::set_prefix_filter_file(const fs::path p) {
  if (!fs::exists(p)) {
    throw std::invalid_argument(p.string() + " does not exists");
  }
  m_prefix_filter_file = p;
}

HeartbeatConfig HeartbeatConfigBuilder::build() const {
  // if (!m_input_file) {
  //   throw std::invalid_argument("No input file provided");
  // }

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
  return HeartbeatConfig{m_output_file.value(),  m_start_time_log_file,
                         m_max_probes,           m_n_packets.value(),
                         m_probing_rate.value(), m_sniffer_buffer_size.value(),
                         m_protocol.value(),     interface,
                         m_bgp_filter_file,      m_prefix_filter_file};
}

std::ostream& operator<<(std::ostream& os, HeartbeatConfig const& v) {
  os << "HeartbeatConfig{";
  // os << "\n\tinput_file=" << v.input_file;
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
