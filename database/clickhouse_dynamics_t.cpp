//
// Created by System Administrator on 2019-07-24.
//

#include "clickhouse_dynamics_t.hpp"

#include <iostream>

using namespace clickhouse;

clickhouse_dynamics_t::edges_tracelinks_t clickhouse_dynamics_t::edges_tracelinks(const std::string &table, uint32_t inf_born_edge_src, uint32_t sup_born_edge_src) {


    auto ipv4_split = 2048;


    edges_tracelinks_t edges_tracelinks;

    for (auto i = 0; i < ipv4_split; ++i) {

        if (i == 20){
            break;
        }

        auto inf_born = static_cast<uint32_t> (i * ((std::pow(2, 32) - 1) / ipv4_split));
        auto sup_born = static_cast<uint32_t >((i + 1) * ((std::pow(2, 32) - 1) / ipv4_split));

        std::string edges_tracelinks_query = "SELECT DISTINCT \n"
                                             "    (p1.reply_ip, p2.reply_ip, \n"
                                             "    p1.src_ip, p1.dst_ip, p1.ttl, p2.ttl, p1.src_port, p1.dst_port) AS tracelink\n"
                                             "FROM \n"
                                             "(\n"
                                             "    SELECT *\n"
                                             "    FROM " + table + "\n"
                                                                   "    WHERE dst_ip > " + std::to_string(inf_born) + " AND dst_ip <= " + std::to_string(sup_born) + " AND  dst_port >= 33434 AND dst_port <= 65000 \n"
                                                                                                                                                                     ") "
                                                                                                                                                                     "AS p1 \n"
                                                                                                                                                                     "INNER JOIN \n"
                                                                                                                                                                     "(\n"
                                                                                                                                                                     "    SELECT *\n"
                                                                                                                                                                     "    FROM " + table + "\n"
                                                                                                                                                                                           "    WHERE dst_ip > " + std::to_string(inf_born) + " AND dst_ip <= " + std::to_string(sup_born) + " AND  dst_port >= 33434 AND dst_port <= 65000 \n"
                                                                                                                                                                                                                                                                                             ") AS p2 ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip) AND (p1.src_port = p2.src_port) AND (p1.dst_port = p2.dst_port) AND (p1.round = p2.round) AND (toUInt8(p1.ttl + toUInt8(1)) = p2.ttl)\n"
                                                                                                                                                                                                                                                                                             "WHERE dst_ip NOT IN \n"
                                                                                                                                                                                                                                                                                             "(\n"
                                                                                                                                                                                                                                                                                             "    SELECT DISTINCT dst_ip\n"
                                                                                                                                                                                                                                                                                             "    FROM \n"
                                                                                                                                                                                                                                                                                             "    (\n"
                                                                                                                                                                                                                                                                                             "        SELECT \n"
                                                                                                                                                                                                                                                                                             "            src_ip, \n"
                                                                                                                                                                                                                                                                                             "            dst_ip, \n"
                                                                                                                                                                                                                                                                                             "            ttl, \n"
                                                                                                                                                                                                                                                                                             "            COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow, \n"
                                                                                                                                                                                                                                                                                             "            COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt\n"
                                                                                                                                                                                                                                                                                             "        FROM " + table + "\n"
                                                                                                                                                                                                                                                                                                                       "        WHERE dst_ip > " + std::to_string(inf_born) + " AND dst_ip <= " + std::to_string(sup_born) + " AND  dst_port >= 33434 AND dst_port <= 65000 \n"
                                                                                                                                                                                                                                                                                                                                                                                                                             "        GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, round)\n"
                                                                                                                                                                                                                                                                                                                                                                                                                             "        HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)\n"
                                                                                                                                                                                                                                                                                                                                                                                                                             //                                             "        ORDER BY (src_ip, dst_ip, ttl) ASC\n"
                                                                                                                                                                                                                                                                                                                                                                                                                             "    ) \n"
                                                                                                                                                                                                                                                                                                                                                                                                                             ")\n";
//                                             "GROUP BY link";

        std::cout << i << "/" << ipv4_split << " of IPv4 space done\n";
        m_client.Select(edges_tracelinks_query, [&edges_tracelinks, inf_born_edge_src, sup_born_edge_src](const Block &block) {
            for (size_t k = 0; k < block.GetRowCount(); ++k) {

                auto db_tracelink = block[0]->As<ColumnTuple>();

                uint32_t edge_src = (*db_tracelink)[0]->As<ColumnUInt32>()->At(k);
                uint32_t edge_dst = (*db_tracelink)[1]->As<ColumnUInt32>()->At(k);
                uint32_t src_ip = (*db_tracelink)[2]->As<ColumnUInt32>()->At(k);
                uint32_t dst_ip = (*db_tracelink)[3]->As<ColumnUInt32>()->At(k);
                uint8_t src_ttl = (*db_tracelink)[4]->As<ColumnUInt8>()->At(k);
                uint8_t dst_ttl = (*db_tracelink)[5]->As<ColumnUInt8>()->At(k);
                uint16_t src_port = (*db_tracelink)[6]->As<ColumnUInt16>()->At(k);
                uint16_t dst_port = (*db_tracelink)[7]->As<ColumnUInt16>()->At(k);

                if (edge_src != edge_dst && edge_src > inf_born_edge_src && edge_src <= sup_born_edge_src){
                    auto edge = std::make_pair(edge_src, edge_dst);
                    tracelink_t tracelink {src_ip, dst_ip, src_port, dst_port, std::make_pair(src_ttl, dst_ttl)};
                    edges_tracelinks[edge].push_back(tracelink);
                }

            }
        });
    }

    return edges_tracelinks;
}

clickhouse_dynamics_t::nodes_tracenodes_t
clickhouse_dynamics_t::nodes_tracenodes(const std::string &table, uint32_t inf_born_node, uint32_t sup_born_node) {

    auto ipv4_split = 512;


    nodes_tracenodes_t nodes_tracenodes;

    for (auto i = 0; i < ipv4_split; ++i) {

        auto inf_born = static_cast<uint32_t> (i * ((std::pow(2, 32) - 1) / ipv4_split));
        auto sup_born = static_cast<uint32_t >((i + 1) * ((std::pow(2, 32) - 1) / ipv4_split));

        std::string nodes_tracenodes_query = "SELECT DISTINCT(reply_ip, src_ip, dst_ip, src_port, dst_port, ttl)\n"
                                             "FROM\n"
                                             "(SELECT *\n"
                                             "FROM " + table + "\n"
                                                               "WHERE dst_ip > " + std::to_string(inf_born) + " AND dst_ip <= " + std::to_string(sup_born) + " AND  dst_port >= 33434 AND dst_port <= 65000 \n"
                                                                                                                                                             ")\n"
                                                                                                                                                             "WHERE dst_ip NOT IN\n"
                                                                                                                                                             "(\n"
                                                                                                                                                             "(SELECT dst_ip FROM\n"
                                                                                                                                                             "(SELECT\n"
                                                                                                                                                             "        src_ip,\n"
                                                                                                                                                             "        dst_ip,\n"
                                                                                                                                                             "        ttl,\n"
                                                                                                                                                             "        COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow,\n"
                                                                                                                                                             "        COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt,\n"
                                                                                                                                                             "        MAX(round) as max_round\n"
                                                                                                                                                             "FROM " + table + "\n"
                                                                                                                                                                               "    WHERE dst_ip > " + std::to_string(inf_born) + " AND dst_ip <= " + std::to_string(sup_born) + " AND  dst_port >= 33434 AND dst_port <= 65000 \n"
                                                                                                                                                                                                                                                                                 "    GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)\n"
                                                                                                                                                                                                                                                                                 "    HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)\n"
                                                                                                                                                                                                                                                                                 "    ORDER BY (src_ip, dst_ip, ttl) ASC\n"
                                                                                                                                                                                                                                                                                 ")\n"
                                                                                                                                                                                                                                                                                 ")\n"
                                                                                                                                                                                                                                                                                 ")";


        std::cout << i << "/" << ipv4_split << " of IPv4 space done\n";
        m_client.Select(nodes_tracenodes_query, [&nodes_tracenodes, inf_born_node, sup_born_node](const Block &block) {
            for (size_t k = 0; k < block.GetRowCount(); ++k) {

                auto db_tracenode = block[0]->As<ColumnTuple>();

                uint32_t node = (*db_tracenode)[0]->As<ColumnUInt32>()->At(k);
                uint32_t src_ip = (*db_tracenode)[1]->As<ColumnUInt32>()->At(k);
                uint32_t dst_ip = (*db_tracenode)[2]->As<ColumnUInt32>()->At(k);
                uint16_t src_port = (*db_tracenode)[3]->As<ColumnUInt16>()->At(k);
                uint16_t dst_port = (*db_tracenode)[4]->As<ColumnUInt16>()->At(k);
                uint8_t ttl = (*db_tracenode)[5]->As<ColumnUInt8>()->At(k);


                if (node > inf_born_node && node <= sup_born_node){
                    tracenode_t tracenode {src_ip, dst_ip, src_port, dst_port, ttl};
                    nodes_tracenodes[node].push_back(tracenode);
                }

            }
        });
    }
    return nodes_tracenodes;
}

dynamics_t
clickhouse_dynamics_t::dynamics(const std::vector<std::string> &tables, uint32_t inf_born_edge_src,
                       uint32_t sup_born_edge_src) {

    dynamics_t dynamics;
    auto & tracenodes_dynamics     = dynamics.tracenodes_dynamics();
    auto & traceroute_ttl_dynamics = dynamics.traceroute_ttl_dynamics();
    auto & subgraph_dynamics       = dynamics.subgraph_node_dynamics();

    for (int i = 0; i < tables.size(); ++i) {
        const auto &table = tables[i];
        std::string dynamics_query = "SELECT DISTINCT(src_ip, dst_ip, reply_ip, src_port, dst_port, ttl)\n"
                                     "FROM\n"
                                     "(SELECT *\n"
                                     "FROM " + table + "\n"
                                                       "WHERE dst_ip > " + std::to_string(inf_born_edge_src) +
                                     " AND dst_ip <= " + std::to_string(sup_born_edge_src) +
                                     " AND  dst_port >= 33434 AND dst_port <= 65000 \n"
                                     ")\n"
                                     "WHERE dst_ip NOT IN\n"
                                     "(\n"
                                     "(SELECT dst_ip FROM\n"
                                     "(SELECT\n"
                                     "        src_ip,\n"
                                     "        dst_ip,\n"
                                     "        ttl,\n"
                                     "        COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow,\n"
                                     "        COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt\n"
                                     //                                             "        MAX(round) as max_round\n"
                                     "FROM " + table + "\n"
                                                       "    WHERE dst_ip > " + std::to_string(inf_born_edge_src) +
                                     " AND dst_ip <= " + std::to_string(sup_born_edge_src) +
                                     " AND  dst_port >= 33434 AND dst_port <= 65000 \n"
                                     "    GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, round)\n"
                                     "    HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)\n"
                                     "    ORDER BY (src_ip, dst_ip, ttl) ASC\n"
                                     ")\n"
                                     ")\n"
                                     ")";
//        std::cout << dynamics_query << "\n";
        m_client.Select(dynamics_query, [&tracenodes_dynamics, &traceroute_ttl_dynamics, &subgraph_dynamics, &tables, i](const Block &block) {
            for (size_t k = 0; k < block.GetRowCount(); ++k) {

                auto db_tracenode = block[0]->As<ColumnTuple>();


                uint32_t src_ip   = (*db_tracenode)[0]->As<ColumnUInt32>()->At(k);
                uint32_t dst_ip   = (*db_tracenode)[1]->As<ColumnUInt32>()->At(k);
                uint32_t reply_ip = (*db_tracenode)[2]->As<ColumnUInt32>()->At(k);
                uint16_t src_port = (*db_tracenode)[3]->As<ColumnUInt16>()->At(k);
                uint16_t dst_port = (*db_tracenode)[4]->As<ColumnUInt16>()->At(k);
                uint8_t  ttl      = (*db_tracenode)[5]->As<ColumnUInt8>()->At(k);


                tracenode_t tracenode{src_ip, dst_ip, reply_ip, src_port, dst_port, ttl};
//                auto tracenode_it = tracenodes_dynamics.find(tracenode);
//                if (tracenode_it == tracenodes_dynamics.end()) {
//                    // Create a new vector of size table with all 0
//                    std::vector<uint32_t> tracenodes_dynamics_v(tables.size(), 0);
//                    tracenodes_dynamics_v[i] = reply_ip;
//                    tracenodes_dynamics.insert(std::make_pair(tracenode, tracenodes_dynamics_v));
//                } else {
//                    tracenodes_dynamics[tracenode][i] = reply_ip;
//                }
//                auto traceroute_ttl_key = std::make_pair(dst_ip, ttl);
//                auto traceroute_ttl_it  = traceroute_ttl_dynamics.find(traceroute_ttl_key);
//                if (traceroute_ttl_it == traceroute_ttl_dynamics.end()){
//                    std::vector<std::vector<tracenode_t>> traceroute_ttl_dynamics_v(tables.size());
//                    traceroute_ttl_dynamics_v[i].emplace_back(tracenode);
//                    traceroute_ttl_dynamics.insert(std::make_pair(traceroute_ttl_key, traceroute_ttl_dynamics_v));
//                } else {
//                    traceroute_ttl_dynamics[traceroute_ttl_key][i].emplace_back(tracenode);
//                }

                auto subgraph_key = reply_ip;
                auto subgraph_it  = subgraph_dynamics.find(subgraph_key);
                if (subgraph_it == subgraph_dynamics.end()){
                    std::vector<std::vector<tracenode_t>> subgraph_dynamics_v(tables.size());
                    subgraph_dynamics_v[i].emplace_back(tracenode);
                    subgraph_dynamics.insert(std::make_pair(subgraph_key, subgraph_dynamics_v));
                } else {
                    subgraph_dynamics[subgraph_key][i].emplace_back(tracenode);
                }

            }
        });
    };

    return dynamics;
}