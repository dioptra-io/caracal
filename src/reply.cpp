#include <spdlog/fmt/fmt.h>
#include <spdlog/fmt/ostr.h>

#include <caracal/checksum.hpp>
#include <caracal/constants.hpp>
#include <caracal/pretty.hpp>
#include <caracal/reply.hpp>
#include <sstream>
#include <string>

namespace caracal {

std::string Reply::to_csv() const {
  return fmt::format(
      "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\"[{}]\",{},{},{},{},{},"
      "{},{},{},"
      "{}",
      probe_protocol, reply_dst_addr, probe_dst_addr, probe_src_port,
      probe_dst_port, probe_ttl, quoted_ttl, reply_src_addr, reply_protocol,
      reply_icmp_type, reply_icmp_code, reply_ttl, reply_size,
      reply_originate_timestamp, reply_receive_timestamp,
      reply_transmit_timestamp, fmt::join(reply_mpls_labels, ","),
      reply_timestamps[0].first, reply_timestamps[0].second,
      reply_timestamps[1].first, reply_timestamps[1].second,
      reply_timestamps[2].first, reply_timestamps[2].second,
      reply_timestamps[3].first, reply_timestamps[3].second, rtt);
}

uint16_t Reply::checksum(uint32_t caracal_id) const {
  // TODO: IPv6 support? Or just encode the last 32 bits for IPv6?
  return Checksum::caracal_checksum(caracal_id, probe_dst_addr.s6_addr32[3],
                                    probe_src_port, probe_ttl);
}

bool Reply::is_valid(uint32_t caracal_id) const {
  // Currently, we only validate IPv4 ICMP time exceeded and destination
  // unreachable messages. We cannot validate echo replies as they do not
  // contain the probe_id field contained in the source IP header.
  // TODO: IPv6 support?
  if (reply_protocol == IPPROTO_ICMP &&
      (reply_icmp_type == 3 || reply_icmp_type == 11)) {
    return probe_id == checksum(caracal_id);
  }
  return true;
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
  os << " reply_originate_timestamp=" << v.reply_originate_timestamp;
  os << " reply_receive_timestamp=" << v.reply_receive_timestamp;
  os << " reply_transmit_timestamp=" << v.reply_transmit_timestamp;
  os << " reply_mpls_labels="
     << fmt::format("{}", fmt::join(v.reply_mpls_labels, ","));
  for (const auto& entry : v.reply_timestamps) {
    os << " reply_timestamp=" << entry.first << ":" << entry.second;
  }
  os << " probe_id=" << v.probe_id;
  os << " probe_size=" << v.probe_size;
  os << " probe_protocol=" << +v.probe_protocol;
  os << " probe_ttl=" << +v.probe_ttl;
  os << " probe_dst_addr=" << v.probe_dst_addr;
  os << " probe_src_port=" << v.probe_src_port;
  os << " probe_dst_port=" << v.probe_dst_port;
  os << " quoted_ttl=" << +v.quoted_ttl;
  os << " rtt=" << v.rtt / 10.0;
  return os;
}

}  // namespace caracal
