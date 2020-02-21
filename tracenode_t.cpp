//
// Created by System Administrator on 2019-07-09.
//

#include "tracenode_t.hpp"
#include <sstream>

const std::string tracenode_t::to_string() const  {
    std::stringstream s;
    s << src_ip << " " << dst_ip << " " << src_port << " " << dst_port << " " << static_cast<uint32_t >(ttl);
    return s.str();
}


bool operator == (const tracenode_t & t1, const tracenode_t & t2){
    return t1.src_ip == t2.src_ip
           && t1.dst_ip == t2.dst_ip
           && t1.src_port == t2.src_port
           && t1.dst_port == t2.dst_port
           && t1.ttl == t2.ttl;
}