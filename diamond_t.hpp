//
// Created by System Administrator on 2019-02-11.
//

#ifndef HEARTBEAT_DIAMOND_T_HPP
#define HEARTBEAT_DIAMOND_T_HPP


#include <cstdint>
#include <unordered_map>
#include <graph_utils_t.hpp>
#include <boost/functional/hash.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>

struct diamond_t {
    // Network view
    std::unordered_map<uint8_t, edges_t> links_by_ttl;
    std::unordered_map<uint8_t, nodes_t> nodes_by_ttl;

    // Graph view
    using graph_t = boost::adjacency_list<boost::vecS, boost::vecS, boost::directedS>;
    graph_t graph;
    // Access the graph vertices by ips
    std::unordered_map<uint32_t, int> vertex_by_ip;

    uint32_t m_divergence_point = 0;
    uint32_t m_convergence_point = 0;



    friend bool operator == (const diamond_t & d1, const diamond_t & d2);
};

struct diamond_hash_f
{
    std::size_t operator()(const diamond_t & diamond) const
    {
        std::size_t seed = 0;
        boost::hash_combine(seed, diamond.m_divergence_point);
        boost::hash_combine(seed, diamond.m_convergence_point);
        return seed;
    }
};

#endif //HEARTBEAT_DIAMOND_T_HPP
