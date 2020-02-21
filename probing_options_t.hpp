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
    uint16_t sport = 24000;
    uint16_t dport = 33434;
    uint32_t inf_born;
    uint32_t sup_born;
    uint32_t n_destinations_per_24;
    bool is_only_routable;
    std::string bgp_file;
    bool is_record_timestamp;
    std::string start_time_log_file;
    bool is_send_from_targets_file;
    std::string targets_file;



};

#endif //HEARTBEAT_OPTIONS_T_HPP
