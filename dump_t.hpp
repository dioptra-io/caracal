//
// Created by System Administrator on 2019-06-06.
//

#ifndef HEARTBEAT_DUMP_T_HPP
#define HEARTBEAT_DUMP_T_HPP

#include <unordered_set>
#include <ostream>

#include <boost/functional/hash.hpp>


class dump_t {
public:
    static void dump_edges(const std::unordered_set<std::pair<uint32_t , uint32_t >, boost::hash<std::pair<uint32_t , uint32_t >>> & edges, std::ostream & );
};


#endif //HEARTBEAT_DUMP_T_HPP
