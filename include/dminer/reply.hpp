#pragma once

#include <string>

namespace dminer {

/// A traceroute reply (all values are in host order, including the IP
/// addresses).
struct Reply {
  /// @name Reply attributes (IP)
  /// @{
  in6_addr src_ip;  ///< The source IP of the reply packet.
  in6_addr dst_ip;  ///< The destination IP of the reply packet.
  uint16_t size;    ///< The size in bytes of the reply packet.
  uint8_t ttl;      ///< The TTL of the reply packet.
  /// @}

  /// @name Reply attributes (IP → ICMP)
  /// @{
  uint8_t icmp_code;  ///< ICMP code (0 if not an ICMP reply)
  uint8_t icmp_type;  ///< ICMP type (0 if not an ICMP reply)
  /// @}

  /// @name Probe attributes (IP → ICMP → IP)
  /// @{
  in6_addr inner_dst_ip;  ///< The IP that was targeted by the probe,
                          ///< if we received a reply from this IP,
                          ///< then \ref src_ip == \ref inner_dst_ip.
  uint16_t inner_size;    ///< The size in bytes of the probe packet.
  uint8_t inner_ttl;      ///< The TTL of the probe packet.
  uint8_t inner_proto;    ///< The protocol of the probe packet.
  /// @}

  /// @name Probe attributes (IP → ICMP → IP → ICMP/UDP)
  /// @{
  uint16_t inner_src_port;  ///< The source port of the probe packet.
                            ///< For ICMP probes, we encode the source port
                            ///< in the ICMP checksum and ID fields
                            ///< in order to vary the flow ID.
  uint16_t inner_dst_port;  ///< The destination port of the probe packet,
                            ///< 0 for ICMP probes.
  uint8_t inner_ttl_from_transport;  ///< The TTL that was encoded in the L4
                                     ///< header, 0 if not available.
  /// @}

  /// @name Estimated attributes
  /// @{
  double rtt;  ///< The estimated round-trip time, in milliseconds.
  /// @}

  /// Serialize the reply in the CSV format.
  /// @param include_rtt sets the RTT field to -1.0 if false.
  /// @return the reply in CSV format.
  [[nodiscard]] std::string to_csv(bool include_rtt = true) const;
};

std::ostream& operator<<(std::ostream& os, Reply const& v);

}  // namespace dminer
