#include <tins/tins.h>

#include <dminer/prober_config.hpp>
#include <filesystem>
#include <optional>
#include <string>

using std::optional;
using std::string;

namespace fs = std::filesystem;

namespace dminer::Prober {

void Config::set_input_file(const fs::path& p) {
  if (!fs::exists(p)) {
    throw std::invalid_argument(p.string() + " does not exists");
  }
  input_file = p;
}

void Config::set_output_file_csv(const fs::path& p) { output_file_csv = p; }

void Config::set_output_file_pcap(const fs::path& p) { output_file_pcap = p; }

void Config::set_probing_rate(const int rate) {
  if (rate <= 0) {
    throw std::domain_error("rate must be > 0");
  }
  probing_rate = static_cast<uint64_t>(rate);
}

void Config::set_protocol(const string& s) {
  if (s == "icmp" || s == "udp") {
    protocol = s;
  } else {
    throw std::invalid_argument(s + " is not a valid protocol");
  }
}

void Config::set_interface(const string& s) { interface = s; }

void Config::set_sniffer_buffer_size(const int size) {
  if (size <= 0) {
    throw std::domain_error("sniffer_buffer_size must be > 0");
  }
  sniffer_buffer_size = static_cast<uint64_t>(size);
}

void Config::set_sniffer_wait_time(const int seconds) {
  if (seconds < 0) {
    throw std::domain_error("sniffer_wait_time must be >= 0");
  }
  sniffer_wait_time = static_cast<uint64_t>(seconds);
}

void Config::set_max_probes(const uint64_t count) {
  if (count <= 0) {
    throw std::domain_error("max_probes must be > 0");
  }
  max_probes = count;
}

void Config::set_n_packets(const int count) {
  if (count <= 0) {
    throw std::domain_error("n_packets must be > 0");
  }
  n_packets = static_cast<uint64_t>(count);
}

void Config::set_prefix_excl_file(const fs::path& p) {
  if (!fs::exists(p)) {
    throw std::invalid_argument(p.string() + " does not exists");
  }
  prefix_excl_file = p;
}

void Config::set_prefix_incl_file(const fs::path& p) {
  if (!fs::exists(p)) {
    throw std::invalid_argument(p.string() + " does not exists");
  }
  prefix_incl_file = p;
}

void Config::set_filter_min_ttl(const int ttl) {
  if (ttl < 0) {
    throw std::domain_error("min_ttl must be > 0");
  }
  filter_min_ttl = ttl;
}

void Config::set_filter_max_ttl(const int ttl) {
  if (ttl < 0) {
    throw std::domain_error("max_ttl must be > 0");
  }
  filter_max_ttl = ttl;
}

void Config::set_meta_round(const string& round) { meta_round = round; }

std::ostream& operator<<(std::ostream& os, Config const& v) {
  auto print_if_value = [&os](const string& name, const auto opt) {
    if (opt) {
      os << ",\n\t" << name << "=" << opt.value();
    }
  };

  os << "Prober::Config{";
  os << "\n\tn_packets=" << v.n_packets;
  os << ",\n\tprobing_rate=" << v.probing_rate;
  os << ",\n\tsniffer_buffer_size=" << v.sniffer_buffer_size;
  os << ",\n\tsniffer_wait_time=" << v.sniffer_wait_time;
  os << ",\n\tprotocol=" << v.protocol;
  os << ",\n\tinterface=" << v.interface.name() << ":"
     << v.interface.ipv4_address();
  print_if_value("input_file", v.input_file);
  print_if_value("output_file_csv", v.output_file_csv);
  print_if_value("output_file_pcap", v.output_file_pcap);
  print_if_value("max_probes", v.max_probes);
  print_if_value("prefix_excl_file", v.prefix_excl_file);
  print_if_value("prefix_incl_file", v.prefix_incl_file);
  print_if_value("min_ttl", v.filter_min_ttl);
  print_if_value("max_ttl", v.filter_max_ttl);
  print_if_value("round", v.meta_round);
  os << "\n}";
  return os;
}

}  // namespace dminer::Prober
