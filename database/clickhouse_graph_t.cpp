//
// Created by System Administrator on 2019-07-23.
//

#include "clickhouse_graph_t.hpp"

#include <iostream>

using namespace clickhouse;

clickhouse_graph_t::clickhouse_graph_t(const std::string& host) : clickhouse_t(host){

}

clickhouse_graph_t::edges_t clickhouse_graph_t::edges(const std::string & table, int round, int snapshot) {

    auto ipv4_split = 64;
    uint64_t batch_row_limit = 100000000;
    clickhouse_graph_t::edges_t edges_set;
    for (auto i = 0; i < ipv4_split; ++i) {

//        if (i == 1){
//            break;
//        }

        auto inf_born = static_cast<uint32_t> (i * ((std::pow(2, 32) - 1) / ipv4_split));
        auto sup_born = static_cast<uint32_t >((i + 1) * ((std::pow(2, 32) - 1) / ipv4_split));
        edges_recurse(table, round, snapshot,
                inf_born, sup_born,
                batch_row_limit, edges_set
                );
        std::cout << i << " of " << ipv4_split << " IPv4 space done\n";
    }
    return edges_set;
}

void clickhouse_graph_t::edges_recurse(const std::string & table,  int round, int snapshot,
        // Shrinking recursion arguments,
        uint32_t inf_born, uint32_t sup_born,
        uint64_t batch_row_limit,
        edges_t & edges_set){

    auto sup_born_division = 1;
    auto temporary_sup_born = sup_born;
    uint64_t n_rows = batch_row_limit + 1;
    while (n_rows > batch_row_limit){
        std::string count_query = "SELECT count()\n"
                                  "FROM " + table + "\n"
                                  "WHERE dst_ip > " + std::to_string(inf_born) + " AND dst_ip <= " + std::to_string(temporary_sup_born);

//        std::cout << count_query << "\n";
        m_client.Select(count_query, [&n_rows](const Block &block) {
            for (size_t k = 0; k < block.GetRowCount(); ++k) {
                n_rows = block[0]->As<ColumnUInt64>()->At(k);
//              std::cout << n_rows << "\n";
            }
        });
        if (n_rows > batch_row_limit){
            temporary_sup_born = (temporary_sup_born - inf_born) / 2 + inf_born;
            sup_born_division += 1;
        }

    }


    for (auto j = 0; j < std::pow(2, sup_born_division-1); ++j) {

        auto inf_born_div = static_cast<uint32_t >(inf_born +
                                                   j * ((sup_born - inf_born) / std::pow(2, sup_born_division - 1)));
        auto sup_born_div = static_cast<uint32_t >(inf_born + (j + 1) * ((sup_born - inf_born) /
                                                                         std::pow(2, sup_born_division - 1)));


        if (sup_born_division > 1) {
            edges_recurse(table, round, snapshot,
                          inf_born_div, sup_born_div,
                          batch_row_limit,
                          edges_set
            );
        } else {
            std::cout << "IPv4 subspace : " << inf_born_div << " AND " << sup_born_div << "\n";
            std::string edges_query = "SELECT DISTINCT((p1.reply_ip, p2.reply_ip))\n"
                                      "FROM \n"
                                      "(\n"
                                      "    SELECT *\n"
                                      "    FROM " + table + "\n"
                                                            "    WHERE dst_ip > " + std::to_string(inf_born_div) +
                                      " AND dst_ip <= " + std::to_string(sup_born_div) +
                                      " AND  dst_port >= 33434 AND dst_port <= 65000 AND round <= " +
                                      std::to_string(round) + " AND snapshot = " + std::to_string(snapshot) +  "\n"
                                                              ") AS p1 \n"
                                                              "INNER JOIN \n"
                                                              "(\n"
                                                              "    SELECT *\n"
                                                              "    FROM " + table + "\n"
                                                                                    "    WHERE dst_ip > " +
                                      std::to_string(inf_born_div) + " AND dst_ip <= " + std::to_string(sup_born_div) +
                                      " AND  dst_port >= 33434 AND dst_port <= 65000 AND round <= " +
                                      std::to_string(round) + " AND snapshot = " + std::to_string(snapshot) +  "\n"
                                                              ") AS p2 ON (p1.src_ip = p2.src_ip) AND (p1.dst_prefix = p2.dst_prefix) AND (p1.dst_ip = p2.dst_ip) AND (p1.src_port = p2.src_port) AND (p1.dst_port = p2.dst_port) AND (p1.round = p2.round) AND (p1.snapshot = p2.snapshot) AND (toUInt8(p1.ttl + toUInt8(1)) = p2.ttl)\n"
                                                              "WHERE dst_ip NOT IN \n"
                                                              "(\n"
                                                              "    SELECT distinct(dst_ip)\n"
                                                              "    FROM \n"
                                                              "    (\n"
                                                              "        SELECT \n"
                                                              "            src_ip, \n"
                                                              "            dst_ip, \n"
                                                              "            ttl, \n"
                                                              "            COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow, \n"
                                                              "            COUNT((src_ip, dst_prefix, dst_ip, ttl, src_port, dst_port)) AS cnt\n"
                                                              "        FROM " + table + "\n"
                                                                                        "        WHERE dst_ip > " +
                                      std::to_string(inf_born_div) + " AND dst_ip <= " + std::to_string(sup_born_div) +
                                      " AND  dst_port >= 33434 AND dst_port <= 65000 AND round <= " +
                                      std::to_string(round) + " AND snapshot = " + std::to_string(snapshot) +  "\n"
                                                              "        GROUP BY (src_ip, dst_prefix, dst_ip, ttl, src_port, dst_port, round, snapshot)\n"
                                                              "        HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)\n"
                                                              //                                  "        ORDER BY (src_ip, dst_ip, ttl) ASC\n"
                                                              "    ) \n"
                                                              "    GROUP BY (src_ip, dst_ip)\n"
                                                              ") "
                                                              " AND p1.reply_ip != p2.reply_ip AND p2.reply_ip != dst_ip AND p1.reply_ip != dst_ip";


//            std::cout << edges_query << "\n";

            m_client.Select(edges_query, [&edges_set](const Block &block) {
//                std::cout << block.GetRowCount() << " rows in this block\n";
                for (size_t k = 0; k < block.GetRowCount(); ++k) {
                    auto edge = block[0]->As<ColumnTuple>();
                    uint32_t src = (*edge)[0]->As<ColumnUInt32>()->At(k);
                    uint32_t dst = (*edge)[1]->As<ColumnUInt32>()->At(k);
                    std::pair<uint32_t , uint32_t > edge_pair = std::make_pair(src, dst);
                    edges_set.insert(edge_pair);

                }
            });
            std::cout << edges_set.size() << " edges\n";
        }
    }

}


nodes_t clickhouse_graph_t::nodes(const std::string &table, int round) {

    std::string nodes_query = "SELECT distinct(reply_ip)\n"
                              "FROM \n"
                              "(\n"
                              "    SELECT *\n"
                              "    FROM " + table + "\n"
                                                    "    WHERE round <=  " + std::to_string(round) + "\n"
                                                                                                     ") \n"
                                                                                                     "WHERE dst_ip NOT IN \n"
                                                                                                     "(\n"
                                                                                                     "    SELECT dst_ip\n"
                                                                                                     "    FROM \n"
                                                                                                     "    (\n"
                                                                                                     "        SELECT \n"
                                                                                                     "            src_ip, \n"
                                                                                                     "            dst_ip, \n"
                                                                                                     "            ttl, \n"
                                                                                                     "            COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt\n"
                                                                                                     "        FROM " + table + "\n"
                                                                                                                               "        WHERE round = 1\n"
                                                                                                                               "        GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, round)\n"
                                                                                                                               "        HAVING cnt > 2\n"
                                                                                                                               "        ORDER BY (src_ip, dst_ip, ttl) ASC\n"
                                                                                                                               "    ) \n"
                                                                                                                               "    GROUP BY (src_ip, dst_ip)\n"
                                                                                                                               ")";

    std::unordered_set<uint32_t> nodes;
    m_client.Select(nodes_query, [&nodes](const Block & block){
        for (size_t k = 0; k < block.GetRowCount(); ++k) {
            auto reply_ip = block[0]->As<ColumnUInt32>()->At(k);
            nodes.insert(reply_ip);
        }
    });

    return nodes;
}


