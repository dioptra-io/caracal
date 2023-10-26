#include <spdlog/fmt/fmt.h>
#include <spdlog/fmt/ostr.h>

#include <caracal/checksum.hpp>
#include <caracal/constants.hpp>
#include <caracal/pretty.hpp>
#include <caracal/reply.hpp>
#include <sstream>
#include <string>

namespace caracal {

std::string mpls_label_to_csv(MPLSLabel mpls_label) {
  return fmt::format("({},{},{},{})", std::get<0>(mpls_label),
                     std::get<1>(mpls_label), std::get<2>(mpls_label),
                     std::get<3>(mpls_label));
}

std::string Reply::to_csv(const std::string& round) const {
  std::vector<std::string> mpls_labels_csv;
  std::transform(reply_mpls_labels.begin(), reply_mpls_labels.end(),
                 std::back_inserter(mpls_labels_csv), mpls_label_to_csv);
  return fmt::format(
      "{},{},{},{},{},{},{},{},{},{},{},{},{},{},\"[{}]\",{},{}",
      capture_timestamp / 1'000'000, probe_protocol, reply_dst_addr,
      probe_dst_addr, probe_src_port, probe_dst_port, probe_ttl, quoted_ttl,
      reply_src_addr, reply_protocol, reply_icmp_type, reply_icmp_code,
      reply_ttl, reply_size, fmt::join(mpls_labels_csv, ","), rtt, round);
}

std::string Reply::csv_header() {
  const std::string columns[17] = {"capture_timestamp",
                                   "probe_protocol",
                                   "probe_src_addr",
                                   "probe_dst_addr",
                                   "probe_src_port",
                                   "probe_dst_port",
                                   "probe_ttl",
                                   "quoted_ttl",
                                   "reply_src_addr",
                                   "reply_protocol",
                                   "reply_icmp_type",
                                   "reply_icmp_code",
                                   "reply_ttl",
                                   "reply_size",
                                   "reply_mpls_labels",
                                   "rtt",
                                   "round"};
  return fmt::format("{}", fmt::join(columns, ","));
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

bool Reply::is_destination_unreachable() const {
  return (reply_protocol == IPPROTO_ICMP && reply_icmp_type == 3) ||
         (reply_protocol == IPPROTO_ICMPV6 && reply_icmp_type == 1);
}

bool Reply::is_echo_reply() const {
  return (reply_protocol == IPPROTO_ICMP && reply_icmp_type == 0) ||
         (reply_protocol == IPPROTO_ICMPV6 && reply_icmp_type == 129);
}

bool Reply::is_time_exceeded() const {
  return (reply_protocol == IPPROTO_ICMP && reply_icmp_type == 11) ||
         (reply_protocol == IPPROTO_ICMPV6 && reply_icmp_type == 3);
}

std::ostream& operator<<(std::ostream& os, Reply const& v) {
  os << "capture_timestamp=" << v.capture_timestamp;
  os << " reply_src_addr=" << v.reply_src_addr;
  os << " reply_dst_addr=" << v.reply_dst_addr;
  os << " reply_ttl=" << +v.reply_ttl;
  os << " reply_protocol=" << +v.reply_protocol;
  os << " reply_icmp_code=" << +v.reply_icmp_code;
  os << " reply_icmp_type=" << +v.reply_icmp_type;
  for (const auto& mpls_label : v.reply_mpls_labels) {
    os << "reply_mpls_label=" << mpls_label_to_csv(mpls_label);
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
