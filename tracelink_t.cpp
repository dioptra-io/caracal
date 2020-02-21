//
// Created by System Administrator on 2019-06-27.
//

#include "tracelink_t.hpp"
#include <sstream>

const std::string tracelink_t::to_string() const  {
    std::stringstream s;
    s << src_ip << " " << dst_ip << " " << src_port << " " << dst_port << " " << static_cast<uint32_t >(ttls.first);
    return s.str();
}


bool operator == (const tracelink_t & t1, const tracelink_t & t2){
    return t1.src_ip == t2.src_ip
           && t1.dst_ip == t2.dst_ip
           && t1.src_port == t2.src_port
           && t1.dst_port == t2.dst_port
           && t1.ttls.first == t2.ttls.first;
}