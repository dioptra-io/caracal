//
// Created by System Administrator on 2019-02-11.
//

#ifndef HEARTBEAT_TRACEROUTE_GRAPH_T_HPP
#define HEARTBEAT_TRACEROUTE_GRAPH_T_HPP


#include <cstdint>
#include <vector>
#include <utils/struct_utils_t.hpp>
#include <unordered_map>
#include <unordered_set>
#include <memory>

class traceroute_graph_t {
public:

    traceroute_graph_t(uint8_t max_ttl);

    struct node_t{

        node_t();

        uint32_t m_ip;
        std::unordered_set<uint16_t> m_flow_ids;
        uint8_t  m_ttl;

        std::unordered_set<std::shared_ptr<node_t>, utils::deref_hash, utils::deref_compare> m_successors;
    };

    struct edge_t{
        std::shared_ptr<node_t> m_source;
        std::shared_ptr<node_t> m_destination;
    };

    struct graph_t{
        std::vector<std::shared_ptr<node_t>> m_nodes;

        std::unordered_map<uint8_t , std::pair<int, int>> m_probes_links_by_ttl;

        const std::unordered_map<uint8_t , std::pair<int,int>> & get_probes_links_by_ttl() const;

        std::unordered_map<uint8_t , std::pair<int,int>> & get_probes_links_by_ttl();

        std::shared_ptr<node_t> m_divergence_point {nullptr};
        std::shared_ptr<node_t> m_convergence_point{nullptr};

    };

    graph_t & get_graph();
    const std::vector<graph_t> & get_diamonds() const;

    const std::unordered_map<uint8_t , uint16_t > & get_max_flow_by_ttl() const;
    std::unordered_map<uint8_t , uint16_t > & get_max_flow_by_ttl();

    void set_flows_per_ttl(const std::unordered_map<uint8_t,std::vector<uint16_t>> & );

    void compute_diamonds();

private:




    graph_t m_graph;

    std::vector<graph_t> m_diamonds;
    std::unordered_map<uint8_t , uint16_t > m_max_flow_by_ttl;
    std::unordered_map<uint8_t,std::vector<uint16_t>> m_flows_per_ttl;

    uint32_t m_source;
    uint32_t m_destination;



};

bool operator== (const traceroute_graph_t::node_t & n1, const traceroute_graph_t::node_t & n2);

namespace std {
    template <> struct hash<traceroute_graph_t::node_t>
    {
        size_t operator()(const traceroute_graph_t::node_t & x) const
        {
            return std::hash<uint32_t >{} (x.m_ip) ^ std::hash<uint8_t > {}(x.m_ttl);
        }
    };
}


#endif //HEARTBEAT_TRACEROUTE_GRAPH_T_HPP
