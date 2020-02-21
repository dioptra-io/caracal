//
// Created by System Administrator on 2019-06-27.
//

#ifndef HEARTBEAT_TRACELINK_T_HPP
#define HEARTBEAT_TRACELINK_T_HPP


#include <cstdint>
#include <string>
#include <utility>
#include <boost/functional/hash.hpp>

struct tracelink_t {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::pair<uint8_t, uint8_t> ttls;


    const std::string to_string() const ;

    friend bool operator == (const tracelink_t&, const tracelink_t &);

};

struct tracelink_hasher_f
{
    std::size_t operator()(const tracelink_t & tracelink) const
    {
        std::size_t seed = 0;
        boost::hash_combine(seed, tracelink.src_ip);
        boost::hash_combine(seed, tracelink.dst_ip);
        boost::hash_combine(seed, tracelink.src_port);
        boost::hash_combine(seed, tracelink.dst_port);
        boost::hash_combine(seed, tracelink.ttls.first);
        return seed;
    }
};


#endif //HEARTBEAT_TRACELINK_T_HPP
