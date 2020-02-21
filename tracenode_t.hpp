//
// Created by System Administrator on 2019-07-09.
//

#ifndef HEARTBEAT_TRACENODE_T_HPP
#define HEARTBEAT_TRACENODE_T_HPP

#include <cstdint>
#include <string>
#include <utility>
#include <boost/functional/hash.hpp>

struct tracenode_t {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint32_t reply_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  ttl;


    const std::string to_string() const ;

    friend bool operator == (const tracenode_t&, const tracenode_t&);

};

struct tracenode_hasher_f
{
    std::size_t operator()(const tracenode_t & tracelink) const
    {
        std::size_t seed = 0;
        boost::hash_combine(seed, tracelink.src_ip);
        boost::hash_combine(seed, tracelink.dst_ip);
        boost::hash_combine(seed, tracelink.src_port);
        boost::hash_combine(seed, tracelink.dst_port);
        boost::hash_combine(seed, tracelink.ttl);
        return seed;
    }
};
#endif //HEARTBEAT_TRACENODE_T_HPP
