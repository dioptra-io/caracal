//
// Created by System Administrator on 2019-07-24.
//

#ifndef HEARTBEAT_CLICKHOUSE_DYNAMICS_T_HPP
#define HEARTBEAT_CLICKHOUSE_DYNAMICS_T_HPP


#include "clickhouse_t.hpp"

class clickhouse_dynamics_t : public clickhouse_t{


    using nodes_tracenodes_t = std::unordered_map<uint32_t, std::vector<tracenode_t >>;
    using edges_tracelinks_t = std::unordered_map<std::pair<uint32_t , uint32_t >, std::vector<tracelink_t>, boost::hash<std::pair<uint32_t , uint32_t >>>;





    /**
     * Compute nodes of the graph.
     * @param table
     * @param inf_born_node
     * @param sup_born_node
     * @return
     */
    nodes_tracenodes_t nodes_tracenodes(const std::string & table, uint32_t inf_born_node, uint32_t sup_born_node);

    /**
     * Compute all the edges of the graph in a map with their tracelinks as values
     * @param table
     * @param round
     * @return
     */
    edges_tracelinks_t edges_tracelinks(const std::string &table, uint32_t inf_born_edge_src, uint32_t sup_born_edge_src);


    dynamics_t dynamics(const std::vector<std::string> &tables, uint32_t inf_born_edge_src,
                        uint32_t sup_born_edge_src);






};


#endif //HEARTBEAT_CLICKHOUSE_DYNAMICS_T_HPP
