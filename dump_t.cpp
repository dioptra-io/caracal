//
// Created by System Administrator on 2019-06-06.
//

#include "dump_t.hpp"

void dump_t::dump_edges(const std::unordered_set<std::pair<uint32_t , uint32_t >, boost::hash<std::pair<uint32_t , uint32_t >>> & edges, std::ostream & ostream) {

    for (const auto & edge : edges){
        ostream << edge.first << "," << edge.second << "\n";
    }

}
