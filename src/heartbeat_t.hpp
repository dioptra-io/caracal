#pragma once

#include <tins/tins.h>

#include <atomic>
#include <patricia.hpp>
#include <string>
#include <thread>

#include "probing_options_t.hpp"

class heartbeat_t {
 public:
  heartbeat_t(const std::string& interface_s, const std::string& hw_gateway,
              const probing_options_t& options);

  void send_exhaustive();

  void send_from_probes_file();

  void send_from_targets_file(uint8_t max_ttl);

  /**
   * Starts the heartbeat (sniffer and sender)
   */
  void start();

  // Alias type
  //    using ip_integers_set = std::unordered_set<uint32_t>;
  //    using intramonitor_redundancy_t = std::unordered_map<uint8_t,
  //    ip_integers_set >; using redundant_destinations_t =
  //    std::unordered_map<uint8_t, ip_integers_set >;

 private:
  bool check_destination_ttl(uint32_t, uint8_t, uint32_t);
  // Build the targets (< 100000) from a targets file.
  std::vector<uint32_t> targets_from_file();

  // Attributes
  Patricia m_patricia_trie;
  Patricia m_patricia_trie_excluded;

  Tins::NetworkInterface m_interface;
  Tins::HWAddress<6> m_hw_gateway;

  probing_options_t m_options;
};