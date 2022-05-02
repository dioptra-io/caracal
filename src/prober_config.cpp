#include <tins/tins.h>

#include <caracal/prober_config.hpp>
#include <filesystem>
#include <optional>
#include <random>
#include <string>

using std::optional;
using std::string;

namespace fs = std::filesystem;

namespace caracal::Prober {

uint16_t Config::get_default_id() {
  std::random_device device;
  std::mt19937 generator(device());
  std::uniform_int_distribution<uint16_t> distribution(
      0, std::numeric_limits<uint16_t>::max());
  return distribution(generator);
}

std::string Config::get_default_interface() {
  return Tins::NetworkInterface::default_interface().name();
}

void Config::set_caracal_id(const int id) {
  if (id < 0) {
    throw std::domain_error("caracal_id must be > 0");
  }
  caracal_id = id;
}

void Config::set_n_packets(const int count) {
  if (count <= 0) {
    throw std::domain_error("n_packets must be > 0");
  }
  n_packets = static_cast<uint64_t>(count);
}

void Config::set_batch_size(const int size) {
  if (size <= 0) {
    throw std::domain_error("batch_size must be > 0");
  }
  batch_size = static_cast<uint64_t>(size);
}

void Config::set_probing_rate(const int rate) {
  if (rate <= 0) {
    throw std::domain_error("rate must be > 0");
  }
  probing_rate = static_cast<uint64_t>(rate);
}

void Config::set_sniffer_wait_time(const int seconds) {
  if (seconds < 0) {
    throw std::domain_error("sniffer_wait_time must be >= 0");
  }
  sniffer_wait_time = static_cast<uint64_t>(seconds);
}

void Config::set_integrity_check(const bool check) { integrity_check = check; }

void Config::set_interface(const string& s) { interface = s; }

void Config::set_rate_limiting_method(const string& s) {
  if (s == "auto" || s == "active" || s == "sleep" || s == "none") {
    rate_limiting_method = s;
  } else {
    throw std::invalid_argument(s + " is not a valid rate limiting method");
  }
}

void Config::set_max_probes(const uint64_t count) {
  if (count <= 0) {
    throw std::domain_error("max_probes must be > 0");
  }
  max_probes = count;
}

void Config::set_output_file_csv(const fs::path& p) { output_file_csv = p; }

void Config::set_output_file_pcap(const fs::path& p) { output_file_pcap = p; }

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
      os << " " << name << "=" << opt.value();
    }
  };

  os << "caracal_id=" << v.caracal_id;
  os << " n_packets=" << v.n_packets;
  os << " probing_rate=" << v.probing_rate;
  os << " sniffer_wait_time=" << v.sniffer_wait_time;
  os << " integrity_check=" << v.integrity_check;
  os << " interface=" << v.interface;
  os << " rate_limiting_method=" << v.rate_limiting_method;
  print_if_value("output_file_csv", v.output_file_csv);
  print_if_value("output_file_pcap", v.output_file_pcap);
  print_if_value("max_probes", v.max_probes);
  print_if_value("prefix_excl_file", v.prefix_excl_file);
  print_if_value("prefix_incl_file", v.prefix_incl_file);
  print_if_value("min_ttl", v.filter_min_ttl);
  print_if_value("max_ttl", v.filter_max_ttl);
  print_if_value("round", v.meta_round);
  return os;
}

}  // namespace caracal::Prober
