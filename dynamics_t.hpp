//
// Created by System Administrator on 2019-07-10.
//

#ifndef HEARTBEAT_DYNAMICS_T_HPP
#define HEARTBEAT_DYNAMICS_T_HPP

#include <unordered_map>

#include <tracenode_t.hpp>


class dynamics_t {
public:
    /**
    * This structure has the finest level of granularity. It keeps trakcs of tracenode evolution across different snapshots.
    */
    using tracenodes_dynamics_t = std::unordered_map<tracenode_t, std::vector<uint32_t>, tracenode_hasher_f>;

    /**
     * This structure capture the traceroute ttl granularity. The key is (dst_ip, ttl). It keeps track of the vector (snapshot) of vector
     * (tracenodes) that corresponds to the key.
     */
    using traceroute_ttl_dynamics_t = std::unordered_map<std::pair<uint32_t , uint8_t >, std::vector<std::vector<tracenode_t>>, boost::hash<std::pair<uint32_t , uint32_t >>>;


    /**
     * This keeps track of the subgraph node granularity. The key represents a node in the graph (a reply_ip) and the value is the vector (snapshot)
     * of vector (tracenodes) that have discovered this reply_ip.
     */
    using subgraph_node_dynamics_t = std::unordered_map<uint32_t, std::vector<std::vector<tracenode_t>>>;


    tracenodes_dynamics_t     & tracenodes_dynamics();
    traceroute_ttl_dynamics_t & traceroute_ttl_dynamics();
    subgraph_node_dynamics_t  & subgraph_node_dynamics();


private:

    tracenodes_dynamics_t     m_tracenodes_dynamics;
    traceroute_ttl_dynamics_t m_traceroute_ttl_dynamics;
    subgraph_node_dynamics_t  m_subgraph_node_dynamics;

};


#endif //HEARTBEAT_DYNAMICS_T_HPP
