#pragma once

#include <ostream>
#include <unordered_set>

struct ProberStatistics {
  uint64_t read = 0;
  uint64_t sent = 0;
  uint64_t filtered_lo_ip = 0;
  uint64_t filtered_hi_ip = 0;
  uint64_t filtered_lo_ttl = 0;
  uint64_t filtered_hi_ttl = 0;
  uint64_t filtered_prefix_excl = 0;
  uint64_t filtered_prefix_not_incl = 0;
  uint64_t filtered_prefix_not_routable = 0;
};

inline std::ostream& operator<<(std::ostream& os, ProberStatistics const& v) {
  os << "probes_read=" << v.read;
  os << " probes_sent=" << v.sent;
  os << " filtered_low_ip=" << v.filtered_lo_ip;
  os << " filtered_high_ip=" << v.filtered_hi_ip;
  os << " filtered_low_ttl=" << v.filtered_lo_ttl;
  os << " filtered_high_ttl=" << v.filtered_hi_ttl;
  os << " filtered_prefix_excl=" << v.filtered_prefix_excl;
  os << " filtered_prefix_not_incl=" << v.filtered_prefix_not_incl;
  os << " filtered_prefix_not_routable=" << v.filtered_prefix_not_routable;
  return os;
}

struct SnifferStatistics {
  uint64_t received_count = 0;
  std::unordered_set<uint32_t> icmp_messages_all;
  std::unordered_set<uint32_t> icmp_messages_path;
};

inline std::ostream& operator<<(std::ostream& os, SnifferStatistics const& v) {
  os << "total_received=" << v.received_count;
  os << " icmp_distinct_all=" << v.icmp_messages_all.size();
  os << " icmp_distinct_path=" << v.icmp_messages_path.size();
  return os;
}
