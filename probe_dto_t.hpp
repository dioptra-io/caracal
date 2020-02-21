//
// Created by System Administrator on 2019-02-06.
//

#ifndef HEARTBEAT_PROBE_DTO_T_HPP
#define HEARTBEAT_PROBE_DTO_T_HPP

#include <string>

struct probe_dto_t {

    probe_dto_t() = default;

    uint32_t m_source_ip;
    uint32_t m_indirect_ip;
    uint32_t m_reply_ip;
    uint16_t m_size;
    uint8_t  m_ttl;
    uint8_t  m_proto;
    uint16_t m_sport;
    uint16_t m_dport;
    uint8_t  m_type;
    uint8_t  m_code;
    double   m_rtt;
    uint8_t  m_reply_ttl;
    uint16_t m_reply_size;
};


#endif //HEARTBEAT_PROBE_DTO_T_HPP
