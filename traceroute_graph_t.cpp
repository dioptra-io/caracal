//
// Created by System Administrator on 2019-02-11.
//

#include "traceroute_graph_t.hpp"

#include <algorithm>

namespace {
    traceroute_graph_t::node_t dummy_node;
}

traceroute_graph_t::traceroute_graph_t(uint8_t max_ttl)  {
//    m_probes_links_by_ttl.set_empty_key(0);
//    m_max_flow_by_ttl.set_empty_key(0);
//    for (uint8_t ttl = 1; ttl <= max_ttl ; ++ttl){
//        m_probes_links_by_ttl[ttl] = std::make_pair(0, 0);
//        m_max_flow_by_ttl[ttl] = 0;
//    }

}

void traceroute_graph_t::compute_diamonds() {
    // Extract the diamonds of this graph
    graph_t diamond;

    bool is_inside_diamond = false;


    // Sort the nodes by ttl
    std::sort(m_graph.m_nodes.begin(), m_graph.m_nodes.end(), [](const auto & node1, const auto & node2){
        return node1->m_ttl < node2->m_ttl;
    });

    for (const auto & node : m_graph.m_nodes){
        uint8_t ttl = node->m_ttl;
        // Check if all the flows that responded are passing via this node.
        // If it it the case, we are on the convergence point.
        if (is_inside_diamond){
            if (node->m_flow_ids.size() == m_flows_per_ttl[ttl].size()){
                // Flush the diamond
                diamond.m_convergence_point = node;
                diamond.m_nodes.push_back(node);
                m_diamonds.push_back(diamond);

                diamond.m_nodes.clear();
                diamond.m_probes_links_by_ttl.clear();
                is_inside_diamond = false;
            }
        }

        auto n_successors = node->m_successors.size();
        if (is_inside_diamond){
            diamond.m_nodes.push_back(node);
        }
        else {
            if ( n_successors > 1){
                // This node is a LB. Are we inside a diamond or is it a new one?
                diamond.m_nodes.push_back(node);
                diamond.m_divergence_point = node;
                is_inside_diamond = true;
            }
        }

        // All the ttls are computed, if flows are missing for n1.
        diamond.m_probes_links_by_ttl[ttl].second += n_successors;
        diamond.m_probes_links_by_ttl[ttl].first += node->m_flow_ids.size();
        auto & max_flow = m_max_flow_by_ttl[ttl];
        auto max_flow_node = *std::max_element(node->m_flow_ids.begin(), node->m_flow_ids.end());
        if (max_flow < max_flow_node){
            max_flow = max_flow_node;
        }

    }

    // Flush the las diamond in case no convergence point found in the traceroute
    if (!diamond.m_nodes.empty() && is_inside_diamond){
        m_diamonds.push_back(diamond);
        diamond.m_nodes.clear();
    }
}

traceroute_graph_t::graph_t &traceroute_graph_t::get_graph() {
    return m_graph;
}

const std::unordered_map<uint8_t, std::pair<int, int>>  & traceroute_graph_t::graph_t::get_probes_links_by_ttl() const {
    return m_probes_links_by_ttl;
}

const std::unordered_map<uint8_t, uint16_t> & traceroute_graph_t::get_max_flow_by_ttl() const {
    return m_max_flow_by_ttl;
}

std::unordered_map<uint8_t, std::pair<int, int>> &traceroute_graph_t::graph_t::get_probes_links_by_ttl() {
    return m_probes_links_by_ttl;
}

std::unordered_map<uint8_t, uint16_t> &traceroute_graph_t::get_max_flow_by_ttl() {
    return m_max_flow_by_ttl;
}

const std::vector<traceroute_graph_t::graph_t> &traceroute_graph_t::get_diamonds() const {
    return m_diamonds;
}

void traceroute_graph_t::set_flows_per_ttl(const std::unordered_map<uint8_t, std::vector<uint16_t>> & flows_per_ttl) {
    m_flows_per_ttl = flows_per_ttl;
}


bool operator==(const traceroute_graph_t::node_t &n1, const traceroute_graph_t::node_t &n2) {
    return n1.m_ip == n2.m_ip && n1.m_ttl == n2.m_ttl;
}

traceroute_graph_t::node_t::node_t() {
//    m_successors.set_empty_key(std::shared_ptr<node_t>(&dummy_node));
}
