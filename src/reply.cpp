#include <arpa/inet.h>
#include <spdlog/fmt/fmt.h>

#include <dminer/pretty.hpp>
#include <dminer/reply.hpp>
#include <sstream>
#include <string>

namespace dminer {

uint32_t Reply::prefix() const noexcept { return (inner_dst_ip >> 8) << 8; }

/// Serialize the reply in the CSV format.
/// @param include_rtt sets the RTT field to -1.0 if false.
/// @return the reply in CSV format.
std::string Reply::to_csv(const bool include_rtt) const {
  return fmt::format("{},{},{},{},{},{},{},{},{},{},{},{:.1f},{},{}", dst_ip,
                     prefix(), inner_dst_ip, src_ip, inner_proto,
                     inner_src_port, inner_dst_port, inner_ttl,
                     inner_ttl_from_transport, icmp_type, icmp_code,
                     include_rtt ? rtt : -1.0, ttl, size);
}

std::ostream& operator<<(std::ostream& os, Reply const& v) {
  os << "src_ip=" << in_addr{htonl(v.src_ip)};
  os << " dst_ip=" << in_addr{htonl(v.dst_ip)};
  os << " ttl=" << +v.ttl;
  os << " icmp_code=" << +v.icmp_code;
  os << " icmp_type=" << +v.icmp_type;
  os << " inner_dst_ip=" << in_addr{htonl(v.inner_dst_ip)};
  os << " inner_size=" << v.inner_size;
  os << " inner_ttl=" << +v.inner_ttl;
  os << " inner_proto=" << +v.inner_proto;
  os << " inner_src_port=" << v.inner_src_port;
  os << " inner_dst_port=" << v.inner_dst_port;
  os << " inner_ttl_from_transport=" << +v.inner_ttl_from_transport;
  os << " rtt=" << v.rtt;
  return os;
}

}  // namespace dminer
