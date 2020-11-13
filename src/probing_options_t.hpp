//
// Created by System Administrator on 2019-05-29.
//

#ifndef HEARTBEAT_OPTIONS_T_HPP
#define HEARTBEAT_OPTIONS_T_HPP

#include <string>

struct probing_options_t {

    std::string interface;
    uint8_t proto;
    std::string output_file;
    std::string probes_file;
    bool is_send_from_probes_file;
    uint32_t pps;
    uint32_t buffer_sniffer_size = 2000000;
    uint16_t sport = 24000;
    uint16_t dport = 33434;
    uint8_t  min_ttl = 3;
    uint8_t  max_ttl = 30;
    uint32_t inf_born;
    uint32_t sup_born;
    uint32_t n_destinations_per_24;

    bool is_from_prefix_file;
    std::string prefix_file;

    bool is_from_bgp;
    std::string bgp_file;

    std::string exclusion_file;
    bool is_record_timestamp;
    std::string start_time_log_file;
    bool is_send_from_targets_file;
    std::string targets_file;

    uint64_t max_packets;

    bool experimental_host_offset;
};

#endif //HEARTBEAT_OPTIONS_T_HPP
