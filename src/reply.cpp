#include <spdlog/fmt/fmt.h>
#include <spdlog/fmt/ostr.h>

#include <caracal/pretty.hpp>
#include <caracal/reply.hpp>
#include <sstream>
#include <string>

namespace caracal {

std::string Reply::to_csv() const {
  return fmt::format("{},{},{},{},{},{},{},{},{},{},{},{},{},\"[{}]\",{:.1f}",
                     reply_dst_addr, probe_dst_addr, probe_src_port,
                     probe_dst_port, probe_ttl_l3, probe_ttl_l4, probe_protocol,
                     reply_src_addr, reply_protocol, reply_icmp_type,
                     reply_icmp_code, reply_ttl, reply_size,
                     fmt::join(reply_mpls_labels, ","), rtt);
}

bool Reply::is_icmp_time_exceeded() const {
  return (reply_protocol == IPPROTO_ICMP && reply_icmp_type == 11) ||
         (reply_protocol == IPPROTO_ICMPV6 && reply_icmp_type == 3);
}

std::ostream& operator<<(std::ostream& os, Reply const& v) {
  os << "reply_src_addr=" << v.reply_src_addr;
  os << " reply_dst_addr=" << v.reply_dst_addr;
  os << " reply_ttl=" << +v.reply_ttl;
  os << " reply_protocol=" << +v.reply_protocol;
  os << " reply_icmp_code=" << +v.reply_icmp_code;
  os << " reply_icmp_type=" << +v.reply_icmp_type;
  os << " reply_mpls_labels="
     << fmt::format("{}", fmt::join(v.reply_mpls_labels, ","));
  os << " probe_size=" << v.probe_size;
  os << " probe_protocol=" << +v.probe_protocol;
  os << " probe_ttl_l3=" << +v.probe_ttl_l3;
  os << " probe_ttl_l4=" << +v.probe_ttl_l4;
  os << " probe_dst_addr=" << v.probe_dst_addr;
  os << " probe_src_port=" << v.probe_src_port;
  os << " probe_dst_port=" << v.probe_dst_port;
  os << " rtt=" << v.rtt;
  return os;
}

}  // namespace caracal
