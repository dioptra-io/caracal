#pragma once

#include <string>
#include <tuple>
#include <vector>

namespace caracal {

using MPLSLabel = std::tuple<uint32_t, uint8_t, uint8_t, uint8_t>;

/// A traceroute reply (all values are in host order, including the IP
/// addresses).
struct Reply {
  /// @name Capture attributes
  /// @{
  int64_t capture_timestamp;  ///< The capture timestamp in microseconds.
  /// @}
  /// @name Reply attributes (IP)
  /// @{
  in6_addr reply_src_addr;  ///< The source IP of the reply packet.
  in6_addr reply_dst_addr;  ///< The destination IP of the reply packet.
  uint16_t reply_id;        ///< The ID field of the reply packet (0 for IPv6).
  uint16_t reply_size;      ///< The size in bytes of the reply packet.
                            ///< For IPv6 this doesn't include the IP header.
  uint8_t reply_ttl;        ///< The TTL of the reply packet.
  uint8_t reply_protocol;   ///< The L3 protocol of the reply.
  /// @}

  /// @name Reply attributes (IP → ICMP)
  /// @{
  uint8_t reply_icmp_type;  ///< ICMP type (0 if not an ICMP reply)
  uint8_t reply_icmp_code;  ///< ICMP code (0 if not an ICMP reply)
  std::vector<MPLSLabel>
      reply_mpls_labels;  ///< MPLS labels contained in the
                          ///< ICMP extension (label, exp, stack bit, ttl).
  /// @}

  /// @name Probe attributes (IP → ICMP → IP)
  /// @{
  in6_addr
      probe_dst_addr;      ///< The IP that was targeted by the probe,
                           ///< if we received a reply from this IP,
                           ///< then \ref reply_src_addr == \ref probe_dst_addr.
  uint16_t probe_id;       ///< The ID field of the probe packet (0 for IPv6).
  uint16_t probe_size;     ///< The size in bytes of the probe packet.
                           ///< For IPv6 this doesn't include the IP header.
  uint8_t probe_protocol;  ///< The protocol of the probe packet.
  uint8_t quoted_ttl;      ///< The TTL as seen by the host that emitted the
                           ///< ICMP reply.
  /// @}

  /// @name Probe attributes (IP → ICMP → IP → ICMP/UDP)
  /// @{
  uint16_t probe_src_port;  ///< The source port of the probe packet.
                            ///< For ICMP probes, we encode the source port
                            ///< in the ICMP checksum and ID fields
                            ///< in order to vary the flow ID.
  uint16_t probe_dst_port;  ///< The destination port of the probe packet,
                            ///< 0 for ICMP probes.
  uint8_t probe_ttl;        ///< The TTL that was encoded in the L4
                            ///< header, 0 if not available.
  /// @}

  /// @name Estimated attributes
  /// @{
  uint16_t rtt;  ///< The estimated round-trip time, in tenth of milliseconds.
  /// @}

  /// Compute the caracal checksum used to verify the reply integrity.
  [[nodiscard]] uint16_t checksum(uint32_t caracal_id) const;

  /// True if the caracal checksum is equal to the checksum stored in the probe.
  [[nodiscard]] bool is_valid(uint32_t caracal_id) const;

  /// True if the reply is an ICMP of ICMPv6 destination unreachable message.
  [[nodiscard]] bool is_destination_unreachable() const;

  /// True if the reply is an ICMP of ICMPv6 echo reply message.
  [[nodiscard]] bool is_echo_reply() const;

  /// True if the reply is an ICMP of ICMPv6 time exceeded message.
  [[nodiscard]] bool is_time_exceeded() const;

  /// Serialize the reply in the CSV format.
  /// @return the reply in CSV format.
  [[nodiscard]] std::string to_csv(const std::string &round) const;

  [[nodiscard]] static std::string csv_header();
};

std::ostream &operator<<(std::ostream &os, Reply const &v);

}  // namespace caracal
