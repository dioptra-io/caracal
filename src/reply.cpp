#include <spdlog/fmt/fmt.h>
#include <spdlog/fmt/ostr.h>

#include <dminer/pretty.hpp>
#include <dminer/reply.hpp>
#include <sstream>
#include <string>

namespace dminer {

std::string Reply::to_csv(const bool include_rtt) const {
  return fmt::format("{},{},{},{},{},{},{},{},{},{},{},{},{:.1f}", dst_ip,
                     inner_dst_ip, inner_src_port, inner_dst_port, inner_ttl,
                     inner_ttl_from_transport, src_ip, inner_proto, icmp_type,
                     icmp_code, ttl, size, include_rtt ? rtt : -1.0);
}

std::ostream& operator<<(std::ostream& os, Reply const& v) {
  os << "src_ip=" << v.src_ip;
  os << " dst_ip=" << v.dst_ip;
  os << " ttl=" << +v.ttl;
  os << " icmp_code=" << +v.icmp_code;
  os << " icmp_type=" << +v.icmp_type;
  os << " inner_dst_ip=" << v.inner_dst_ip;
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
