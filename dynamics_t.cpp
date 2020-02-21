//
// Created by System Administrator on 2019-07-10.
//

#include "dynamics_t.hpp"

dynamics_t::tracenodes_dynamics_t &dynamics_t::tracenodes_dynamics() {
    return m_tracenodes_dynamics;
}

dynamics_t::traceroute_ttl_dynamics_t &dynamics_t::traceroute_ttl_dynamics() {
    return m_traceroute_ttl_dynamics;
}

dynamics_t::subgraph_node_dynamics_t &dynamics_t::subgraph_node_dynamics() {
    return m_subgraph_node_dynamics;
}
