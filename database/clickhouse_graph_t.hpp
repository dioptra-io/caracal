//
// Created by System Administrator on 2019-07-23.
//

#ifndef HEARTBEAT_CLICKHOUSE_GRAPH_T_HPP
#define HEARTBEAT_CLICKHOUSE_GRAPH_T_HPP

#include <clickhouse_t.hpp>
#include <utils/graph_utils_t.cpp>

class clickhouse_graph_t : public clickhouse_t{

public:

    explicit clickhouse_graph_t(const std::string & host);
    /**
     * Compute the nodes of a snapshot in a table
     * @param table
     * @param round
     * @return
     */
     nodes_t nodes(const std::string & table, int round);

    /**
     * Compute the edges of a snapshot in a table
     * @return
     */
    edges_t edges(const std::string & table, int round, int snapshot);



    
private:
    void edges_recurse(const std::string & table,  int round, int snapshot,
            // Shrinking recursion arguments,
            uint32_t inf_born, uint32_t sup_born,
            uint64_t batch_row_limit,
            std::unordered_set<std::pair<uint32_t , uint32_t >, boost::hash<std::pair<uint32_t , uint32_t >>> & edges );

};


#endif //HEARTBEAT_CLICKHOUSE_GRAPH_T_HPP
