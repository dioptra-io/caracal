//
// Created by System Administrator on 2019-05-29.
//

#ifndef HEARTBEAT_PROCESS_OPTIONS_T_HPP
#define HEARTBEAT_PROCESS_OPTIONS_T_HPP

#include <string>

struct process_options_t {
    uint32_t round;
    uint32_t snapshot;
    std::string input_file;
    std::string output_file;
    bool is_generate = false;
    bool is_generate_snapshot = false;
    bool is_read = false;
    uint32_t inf_born;
    uint32_t sup_born;
    uint16_t sport = 24000;
    uint16_t dport = 33434;

    std::string skip_prefixes_file;
    int snapshot_reference;

    bool is_compute_rtt;
    std::string start_time_file;
};


#endif //HEARTBEAT_PROCESS_OPTIONS_T_HPP
