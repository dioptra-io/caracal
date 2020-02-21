//
// Created by System Administrator on 2019-08-02.
//

#ifndef HEARTBEAT_CLICKHOUSE_DIAMONDS_T_HPP
#define HEARTBEAT_CLICKHOUSE_DIAMONDS_T_HPP


//
// Created by System Administrator on 2019-07-23.
//

#ifndef HEARTBEAT_CLICKHOUSE_GRAPH_T_HPP
#define HEARTBEAT_CLICKHOUSE_GRAPH_T_HPP

#include <clickhouse_t.hpp>
#include <diamond_t.hpp>
class clickhouse_diamonds_t : public clickhouse_t{

public:

    explicit clickhouse_diamonds_t(const std::string & host);

    /**
     * Compute the diamonds of a snapshot in a table
     * @param table
     * @param round
     * @return
     */
    using diamonds_t = std::unordered_set<diamond_t>;
    diamonds_t diamonds(const std::string & table, int round);




private:
    void diamonds_recurse(const std::string & table,  int round,
            // Shrinking recursion arguments,
                       uint32_t inf_born, uint32_t sup_born,
                       uint64_t batch_row_limit,
                       std::unordered_set<diamond_t> & diamonds,
                       diamond_t & current_diamond,
                       uint32_t  & current_prefix);

};


#endif //HEARTBEAT_CLICKHOUSE_GRAPH_T_HPP



#endif //HEARTBEAT_CLICKHOUSE_DIAMONDS_T_HPP
