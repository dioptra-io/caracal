//
// Created by System Administrator on 2019-06-06.
//

#include <clickhouse_graph_t.hpp>
#include <dump_t.hpp>
#include <iostream>
#include <mutex>  // For std::unique_lock
#include <shared_mutex>
#include <thread>
#include <algorithm>


int main(int argc, char **argv){
    clickhouse_graph_t clickhouse("132.227.123.200");

    std::vector<std::string> tables;

    tables.emplace_back("heartbeat.probes");
//    tables.emplace_back("heartbeat.probes_mit");

    auto max_round = 10;
    auto max_snapshot = 3;
    for (const auto & table : tables){
        // Compare rounds efficiency
            for (auto round = 10; round >= 1; --round) {
                for (auto snapshot = 2; snapshot <= max_snapshot; ++snapshot){
                    auto edges = clickhouse.edges(table, round, snapshot);
                    std::cout << "Edges found in round " << round << ": " << edges.size() << "\n";

                    if (round == 10) {
                        std::ofstream ofile;
                        ofile.open("resources/edges_snapshot_" + table + "_" + std::to_string(snapshot));
                        for (const auto &edge: edges) {
                            ofile << edge.first << " " << edge.second << "\n";
                        }
                    }
            }
        }

    }






//    for (int r = 1; r <= max_round; ++r){
//        auto edges = clickhouse.edges(table, r);
//        std::cout << "Edges found at round " << r << ": " << edges.size() << "\n";
//
//    }
//
//    for (int r = 1; r <= max_round; ++r){
//        auto nodes = clickhouse.nodes(table, r);
//        std::cout << "Nodes found at round " << r << ": " << nodes.size() << "\n";
//
//    }
//    std::ofstream ofile;
//    ofile.open("resources/heartbeat.redundancy");

//    auto tracelinks_by_edge = clickhouse.edges_tracelinks(table);
//
//    // Redundancy tuple represents (number of tracelinks, ttl at which the edge was found, number of distinct ttls)
//    std::vector<std::tuple<std::size_t, uint8_t, std::size_t>> redundancy;
//
//    for(const auto & edge_tracelinks : tracelinks_by_edge){
//        const auto & tracelinks = edge_tracelinks.second;
//
//        // This could be optimized in a one shot loop, but STL is clearer.
//        uint8_t min_ttl = std::min_element(tracelinks.begin(), tracelinks.end(),
//                [](const auto & tracelink1, const auto & tracelink2){
//                    return tracelink1.ttls.first < tracelink2.ttls.first;
//        })->ttls.first;
//
//        std::unordered_set<uint8_t> distinct_ttls;
//
//        for (const auto & tracelink : tracelinks){
//            distinct_ttls.insert(tracelink.ttls.first);
//        }
//
//        redundancy.emplace_back(std::make_tuple(tracelinks.size(), min_ttl, distinct_ttls.size()));
//
//    }
//
//    for (auto tuple : redundancy){
//        ofile << std::get<0>(tuple) << "," <<  static_cast<int>(std::get<1>(tuple)) << "," << std::get<2>(tuple) << "\n";
//    }
//
//    ofile.close();


    // For each edge, we compute a list of list of tracelinks.
//    using edges_tracelinks_multiple_snapshots_t = std::unordered_map<std::pair<uint32_t , uint32_t >, std::vector<std::vector<tracelink_t>>, boost::hash<std::pair<uint32_t , uint32_t >>>;
//    using edges_tracelinks_binary_v_multiple_snapshots_t = std::unordered_map<std::pair<uint32_t , uint32_t >,
//            std::unordered_map<tracelink_t, std::vector<bool>, tracelink_hasher_f>, boost::hash<std::pair<uint32_t , uint32_t >>>;
//
//
//    // Split the edge space into smallest to not overload the RAM
//    uint32_t inf_born_edge_src = 0;
//    uint32_t sup_born_edge_src = std::pow(2, 32) - 1;


    /**
     * EDGE PART
     */

//    edges_tracelinks_multiple_snapshots_t edges_tracelinks_multiple_snapshots;
//    std::vector<std::string> tables;
//    tables.emplace_back("heartbeat.probes");
//    tables.emplace_back("heartbeat.probes_2");
//    tables.emplace_back("heartbeat.probes_0704");
//    tables.emplace_back("heartbeat.probes_0705");
//    tables.emplace_back("heartbeat.probes_0706");
//    tables.emplace_back("heartbeat.probes_0707");
//
//
//
//    std::shared_mutex mutex;
//
//    auto extract_edge_tracelinks_f = [&edges_tracelinks_multiple_snapshots, &tables, &mutex, inf_born_edge_src, sup_born_edge_src](const auto & table){
//        clickhouse_t clickhouse("132.227.123.200", "heartbeat.probes");
//        auto tracelinks_by_edge = clickhouse.edges_tracelinks(table, inf_born_edge_src, sup_born_edge_src);
//        for(auto & edge_tracelinks : tracelinks_by_edge) {
//            const auto &edge = edge_tracelinks.first;
//            auto &tracelinks = edge_tracelinks.second;
//            // Move to save space.
//
//            auto table_it = std::find(tables.begin(), tables.end(), table);
//            auto index = std::distance(tables.begin(), table_it);
//
//            std::scoped_lock lock(mutex);
//            auto edge_it = edges_tracelinks_multiple_snapshots.find(edge);
//            if (edge_it == edges_tracelinks_multiple_snapshots.end()){
//                // Create a new vector of size tables.size()
//                std::vector<std::vector<tracelink_t>> value(tables.size());
//                value[index] = std::move(tracelinks);
//                edges_tracelinks_multiple_snapshots[edge] = std::move(value);
//            }
//            else {
//                edges_tracelinks_multiple_snapshots[edge][index] = std::move(tracelinks);
//            }
//
//        }
//    };


//    std::vector<std::thread> table_threads;
//    for (const auto & table: tables){
//        table_threads.emplace_back(extract_edge_tracelinks_f, table);
//    }
//
//    for (auto & t : table_threads){
//        t.join();
//    }

//    edges_tracelinks_binary_v_multiple_snapshots_t edges_tracelinks_binary_v_multiple_snapshots;
//
//    for (const auto & edge_tracelinks_multiple_snapshots : edges_tracelinks_multiple_snapshots){
//        // Compute the tracelinks that we will save
//        // For each tracelink, construct a binary vector to see if it has seen the edge
//        std::unordered_map<tracelink_t, std::vector<bool>, tracelink_hasher_f> binary_v_tracelinks;
//        auto & edge = edge_tracelinks_multiple_snapshots.first;
//        auto & multiple_snapshots_tracelinks = edge_tracelinks_multiple_snapshots.second;
//        for (std::size_t i = 0; i < multiple_snapshots_tracelinks.size(); ++i){
//            auto & single_snapshot_tracelinks = multiple_snapshots_tracelinks[i];
//            for (const auto & tracelink : single_snapshot_tracelinks){
//                auto binary_v_tracelink = binary_v_tracelinks.find(tracelink);
//                if (binary_v_tracelink == binary_v_tracelinks.end()){
//                    // Initalize all the tracelinks to false by default.
//                    std::vector<bool> binary_v (tables.size(), false);
//                    binary_v[i] = true;
//                    binary_v_tracelinks.insert(std::make_pair(tracelink, binary_v));
//                }
//                else {
//                    binary_v_tracelinks[tracelink][i] = true;
//                }
//            }
//        }
//
//        edges_tracelinks_binary_v_multiple_snapshots[edge] = binary_v_tracelinks;
//
//    }
//
//    std::cout << "Processed "  << edges_tracelinks_binary_v_multiple_snapshots.size() << " edges.\n";
//
//    std::unordered_map<std::pair<uint32_t , uint32_t >, int, boost::hash<std::pair<uint32_t , uint32_t >>> stable_edges;
//
//    for (const auto & edge_tracelinks_binary_v_multiple_snapshots : edges_tracelinks_binary_v_multiple_snapshots){
//        const auto & edge = edge_tracelinks_binary_v_multiple_snapshots.first;
//        stable_edges[edge] = 0;
////        std::cout << edge.first << "->" << edge.second << "\n";
//        const auto & tracelinks_binary_v_multiple_snapshots = edge_tracelinks_binary_v_multiple_snapshots.second;
//        for (const auto & tracelink_binary_v_multiple_snapshots : tracelinks_binary_v_multiple_snapshots){
//            const auto & tracelink = tracelink_binary_v_multiple_snapshots.first;
//            const auto & binary_v  = tracelink_binary_v_multiple_snapshots.second;
////            std::cout << tracelink.to_string() << ": ";
//
//            if (std::all_of(binary_v.begin(), binary_v.end(),
//                    [](const auto & b){
//                return b;
//            })
//            ){
//                stable_edges[edge] = 1;
//            }
//
////            for (const auto & b : binary_v){
////                if (b){
////                    std::cout << 1;
////                } else {
////                    std::cout << 0;
////                }
////            }
////            std::cout << "\n";
//        }
//
//    }
//
//
//    auto n_stable_edge = std::count_if(stable_edges.begin(), stable_edges.end(), [](const auto & edge_b){
//       return edge_b.second == 1;
//    });
//    std::cout << n_stable_edge << " stable edges\n";


    /**
     * Node part
     */



//
//    using nodes_tracenodes_multiple_snapshots_t = std::unordered_map<uint32_t, std::vector<std::vector<tracenode_t>>>;
//    using nodes_tracenodes_binary_v_multiple_snapshots_t = std::unordered_map<uint32_t ,
//            std::unordered_map<tracenode_t, std::vector<bool>, tracenode_hasher_f>>;
//
//    std::vector<std::string> tables;
//    tables.emplace_back("heartbeat.probes");
//    tables.emplace_back("heartbeat.probes_2");
//    tables.emplace_back("heartbeat.probes_0704");
//    tables.emplace_back("heartbeat.probes_0705");
//    tables.emplace_back("heartbeat.probes_0706");
//    tables.emplace_back("heartbeat.probes_0707");
//
//
//    auto ipv4_split_node = 10;
//
//    std::unordered_map<uint32_t, int> stable_nodes;
//
//    for (auto i = 0; i < ipv4_split_node ; ++i) {
//        nodes_tracenodes_multiple_snapshots_t nodes_tracenodes_multiple_snapshots;
//
//        auto inf_born_node = static_cast<uint32_t> (i * ((std::pow(2, 32) - 1) / ipv4_split_node));
//        auto sup_born_node = static_cast<uint32_t >((i + 1) * ((std::pow(2, 32) - 1) / ipv4_split_node));
//
//        std::shared_mutex mutex;
//
//        auto extract_node_tracenodes_f = [&nodes_tracenodes_multiple_snapshots, &tables, &mutex, inf_born_node, sup_born_node](
//                const auto &table) {
//            clickhouse_t clickhouse("132.227.123.200", "heartbeat.probes");
//            auto tracenodes_by_node = clickhouse.nodes_tracenodes(table, inf_born_node, sup_born_node);
//            for (auto &node_tracenodes : tracenodes_by_node) {
//                const auto &node = node_tracenodes.first;
//                auto &tracenodes = node_tracenodes.second;
//                // Move to save space.
//
//                auto table_it = std::find(tables.begin(), tables.end(), table);
//                auto index = std::distance(tables.begin(), table_it);
//
//                std::scoped_lock lock(mutex);
//                auto node_it = nodes_tracenodes_multiple_snapshots.find(node);
//                if (node_it == nodes_tracenodes_multiple_snapshots.end()) {
//                    // Create a new vector of size tables.size()
//                    std::vector<std::vector<tracenode_t>> value(tables.size());
//                    value[index] = std::move(tracenodes);
//                    nodes_tracenodes_multiple_snapshots[node] = std::move(value);
//                } else {
//                    nodes_tracenodes_multiple_snapshots[node][index] = std::move(tracenodes);
//                }
//
//            }
//        };
//
//
//        std::vector<std::thread> table_threads;
//        for (const auto &table: tables) {
//            table_threads.emplace_back(extract_node_tracenodes_f, table);
//        }
//
//        for (auto &t : table_threads) {
//            t.join();
//        }
//
//        nodes_tracenodes_binary_v_multiple_snapshots_t nodes_tracenodes_binary_v_multiple_snapshots;
//
//        for (const auto &node_tracenodes_multiple_snapshots : nodes_tracenodes_multiple_snapshots) {
//            // Compute the tracelinks that we will save
//            // For each tracelink, construct a binary vector to see if it has seen the edge
//            std::unordered_map<tracenode_t, std::vector<bool>, tracenode_hasher_f> binary_v_tracenodes;
//            auto &node = node_tracenodes_multiple_snapshots.first;
//            auto &multiple_snapshots_tracenodes = node_tracenodes_multiple_snapshots.second;
//            for (std::size_t i = 0; i < multiple_snapshots_tracenodes.size(); ++i) {
//                auto &single_snapshot_tracenodes = multiple_snapshots_tracenodes[i];
//                for (const auto &tracenode : single_snapshot_tracenodes) {
//                    auto binary_v_tracenode = binary_v_tracenodes.find(tracenode);
//                    if (binary_v_tracenode == binary_v_tracenodes.end()) {
//                        // Initalize all the tracelinks to false by default.
//                        std::vector<bool> binary_v(tables.size(), false);
//                        binary_v[i] = true;
//                        binary_v_tracenodes.insert(std::make_pair(tracenode, binary_v));
//                    } else {
//                        binary_v_tracenodes[tracenode][i] = true;
//                    }
//                }
//            }
//
//            nodes_tracenodes_binary_v_multiple_snapshots[node] = binary_v_tracenodes;
//
//        }
//
//        std::cout << "Processed " << nodes_tracenodes_binary_v_multiple_snapshots.size() << " nodes.\n";
//
//        for (const auto &node_tracenodes_binary_v_multiple_snapshots : nodes_tracenodes_binary_v_multiple_snapshots) {
//            const auto &node = node_tracenodes_binary_v_multiple_snapshots.first;
//            stable_nodes[node] = 0;
////        std::cout << node.first << "->" << node.second << "\n";
//            const auto &tracenodes_binary_v_multiple_snapshots = node_tracenodes_binary_v_multiple_snapshots.second;
//            for (const auto &tracenode_binary_v_multiple_snapshots : tracenodes_binary_v_multiple_snapshots) {
//                const auto &tracenode = tracenode_binary_v_multiple_snapshots.first;
//                const auto &binary_v = tracenode_binary_v_multiple_snapshots.second;
////            std::cout << tracelink.to_string() << ": ";
//
//                if (std::all_of(binary_v.begin(), binary_v.end(),
//                                [](const auto &b) {
//                                    return b;
//                                })
//                        ) {
//                    stable_nodes[node] = 1;
//                }
//
////            for (const auto & b : binary_v){
////                if (b){
////                    std::cout << 1;
////                } else {
////                    std::cout << 0;
////                }
////            }
////            std::cout << "\n";
//            }
//
//        }
//
//
//        auto n_stable_node = std::count_if(stable_nodes.begin(), stable_nodes.end(), [](const auto &node_b) {
//            return node_b.second == 1;
//        });
//        std::cout << n_stable_node << " stable tracenodes\n";
//
//    }

    // DEBUG just print some binary vectors



    /**
     * Tracenode dynamics
     */
//    std::vector<std::string> tables;
////    tables.emplace_back("heartbeat.probes");
////    tables.emplace_back("heartbeat.probes_2");
//    tables.emplace_back("heartbeat.probes_0704");
//    tables.emplace_back("heartbeat.probes_0705");
////    tables.emplace_back("heartbeat.probes_0706");
////    tables.emplace_back("heartbeat.probes_0707");
//
//
//    // Number of tracenode dynamics per traceroute ttl per snapshot
//    using total_tracenodes_dynamics_per_traceroute_t = std::unordered_map<std::pair<uint32_t, uint8_t >, std::vector<int>, boost::hash<std::pair<uint32_t, uint8_t >>>;
//    total_tracenodes_dynamics_per_traceroute_t total_tracenode_dynamics_per_traceroute;
//
//    // Number of traceroute ttl dynamics per snpashot
//    using total_traceroute_ttl_dynamics_t = std::unordered_map<std::pair<uint32_t, uint8_t >, std::vector<int>, boost::hash<std::pair<uint32_t, uint8_t >>>;
//    total_traceroute_ttl_dynamics_t total_traceroute_ttl_dynamics;
//
//    // Number of tracenode dynamics per node per snapshot
//    using total_subgraph_dynamics_t = std::unordered_map<uint32_t, std::vector<int>>;
//    total_subgraph_dynamics_t total_subgraph_dynamics;
//
//
//    auto ipv4_split = 128;
//
//    // Split the IPv4 split into n_thread for clickhouse running parralelized queries
//    auto n_thread = 1;
//
//    auto dynamics_f = [&tables](auto inf_born_thread, auto sup_born_thread,
//                                total_tracenodes_dynamics_per_traceroute_t & n_tracenodes_dynamics_per_traceroute,
//                                total_traceroute_ttl_dynamics_t            & n_traceroute_ttl_dynamics,
//                                total_subgraph_dynamics_t                  & n_subgraph_dynamics){
//        clickhouse_t clickhouse("132.227.123.200", "heartbeat.probes");
//
//        dynamics_t dynamics = clickhouse.dynamics(tables, inf_born_thread, sup_born_thread);
//
//        auto tracenodes_dynamics = dynamics.tracenodes_dynamics();
//
//        auto traceroute_ttl_dynamics = dynamics.traceroute_ttl_dynamics();
//
//        auto subgraph_dynamics = dynamics.subgraph_node_dynamics();
//
//
//        for (const auto & e : tracenodes_dynamics){
//            const auto & tracenode = e.first;
//
//            // Create the key if not present
//            const auto traceroute_ttl_key = std::make_pair(tracenode.dst_ip, tracenode.ttl);
//            auto traceroute_ttl_it = n_tracenodes_dynamics_per_traceroute.find(traceroute_ttl_key);
//            if (traceroute_ttl_it == n_tracenodes_dynamics_per_traceroute.end()){
//                n_tracenodes_dynamics_per_traceroute.insert(std::make_pair(traceroute_ttl_key, std::vector<int>(tables.size(), 0)));
//            }
//
//
//
//            const auto & local_dynamics  = e.second;
//
//            // A dynamic is characterized by a change in the reply of flow id
//            for (std::size_t d = 1; d < local_dynamics.size(); ++d){
//                if (local_dynamics[d] != local_dynamics[d-1]){
////                    std::cout << "Changing flow !\n";
//                    n_tracenodes_dynamics_per_traceroute[traceroute_ttl_key][d] += 1;
//                }
//            }
//        }
//
//        for (const auto & e : traceroute_ttl_dynamics){
//            const auto & traceroute_ttl = e.first;
//
//            // Create the key
//            const auto & traceroute_ttl_key = traceroute_ttl;
//            auto traceroute_ttl_it = n_traceroute_ttl_dynamics.find(traceroute_ttl_key);
//            if (traceroute_ttl_it == n_traceroute_ttl_dynamics.end()){
//                n_traceroute_ttl_dynamics.insert(std::make_pair(traceroute_ttl_key, std::vector<int>(tables.size(), 0)));
//            }
//
//            const auto & local_dynamics       = e.second;
//
//            // Here, a dynamic is characterized by not the same elements being seen per ttl in a traceroute.
//            // Check the different sets
//            std::vector<std::unordered_set<uint32_t>> unique_ips_traceroute_ttl_snapshots;
//            for (const auto & snapshot_tracenodes : local_dynamics){
//                std::unordered_set<uint32_t> unique_ips_traceroute_ttl;
//                std::transform(snapshot_tracenodes.begin(), snapshot_tracenodes.end(),
//                               std::inserter(unique_ips_traceroute_ttl, unique_ips_traceroute_ttl.begin()), [](const auto & tracenode){
//                            return tracenode.reply_ip;
//                        });
//                unique_ips_traceroute_ttl_snapshots.emplace_back(unique_ips_traceroute_ttl);
//            }
//
//            for (std::size_t d = 1; d < unique_ips_traceroute_ttl_snapshots.size(); ++d){
//                std::vector<uint32_t> intersection_ips_traceroute_ttl_dynamics;
//                std::vector<uint32_t> union_ips_traceroute_ttl_dynamics;
//                std::set_intersection(unique_ips_traceroute_ttl_snapshots[d].begin(),unique_ips_traceroute_ttl_snapshots[d].end(),
//                                      unique_ips_traceroute_ttl_snapshots[d-1].begin(), unique_ips_traceroute_ttl_snapshots[d-1].end(),
//                                      std::back_inserter(intersection_ips_traceroute_ttl_dynamics));
//                std::set_union(unique_ips_traceroute_ttl_snapshots[d].begin(),unique_ips_traceroute_ttl_snapshots[d].end(),
//                                      unique_ips_traceroute_ttl_snapshots[d-1].begin(), unique_ips_traceroute_ttl_snapshots[d-1].end(),
//                                      std::back_inserter(union_ips_traceroute_ttl_dynamics));
//
//
//                n_traceroute_ttl_dynamics[traceroute_ttl][d] = union_ips_traceroute_ttl_dynamics.size() - intersection_ips_traceroute_ttl_dynamics.size();
//
//            }
//        }
//
//        for (const auto & e : subgraph_dynamics){
//            const auto & node     = e.first;
//            const auto & local_dynamics = e.second;
//
//            // Create the key
//            const auto & node_key = node;
//            auto node_it = n_subgraph_dynamics.find(node_key);
//            if (node_it == n_subgraph_dynamics.end()){
//                n_subgraph_dynamics.insert(std::make_pair(node_key, std::vector<int>(tables.size(), 0)));
//            }
//
//            // Here, a dynamic is whether or not the node still appears in the graph.
//            for (std::size_t d = 0; d < local_dynamics.size(); ++d){
//                if (!local_dynamics[d].empty()){
//                    n_subgraph_dynamics[node][d] = 1;
//                }
//            }
//        }
//    };
//
//
//
//    auto n_total_flow_dynamics = 0;
//    auto n_flow_impacted_traceroutes = 0;
//    auto n_flow_not_impacted_traceroutes = 0;
//    auto n_total_subgraph_dynamics = 0;
//
//    for (auto i = 0; i < ipv4_split; ++i) {
//        if (i == 7){
//            break;
//        }
//        std::cout << i << "/" << ipv4_split << " of IPv4 space done\n";
//
//        auto inf_born = static_cast<uint32_t> (i * ((std::pow(2, 32) - 1) / ipv4_split));
//        auto sup_born = static_cast<uint32_t >((i + 1) * ((std::pow(2, 32) - 1) / ipv4_split));
//
////
//        std::vector<std::thread> db_threads;
//        for (auto j = 0; j < n_thread; ++j){
//            auto inf_born_thread = static_cast<uint32_t> (inf_born + j * ((sup_born -inf_born) / n_thread) );
//            auto sup_born_thread = static_cast<uint32_t >(inf_born + (j + 1) * ((sup_born - inf_born)/ n_thread));
//
//            db_threads.emplace_back(dynamics_f, inf_born_thread, sup_born_thread,
//                    std::ref(total_tracenode_dynamics_per_traceroute),
//                    std::ref(total_traceroute_ttl_dynamics),
//                    std::ref(total_subgraph_dynamics));
//        }
//        for (auto &t : db_threads) {
//            t.join();
//        }
////        clickhouse_t clickhouse("132.227.123.200", "heartbeat.probes");
////
////        tracenodes_dynamics_t tracenodes_dynamics = clickhouse.tracenodes_dynamics(tables, inf_born, sup_born);
////
//
//        for (const auto & tracenode_dynamics_per_traceroute : total_tracenode_dynamics_per_traceroute){
//            const auto & traceroute_ttl = tracenode_dynamics_per_traceroute.first;
//            const auto & flow_dynamics  = tracenode_dynamics_per_traceroute.second;
//
//            const auto & traceroute_dynamics = total_traceroute_ttl_dynamics[traceroute_ttl];
//
//            for(std::size_t d = 0; d < flow_dynamics.size(); ++d){
//                auto n_flow_dynamics = flow_dynamics[d];
//                n_total_flow_dynamics += n_flow_dynamics;
//                auto n_traceroute_dynamics = traceroute_dynamics[d];
//                if (n_flow_dynamics > 0 && n_traceroute_dynamics > 0){
//                    n_flow_impacted_traceroutes += 1;
//                } else if (n_flow_dynamics > 0  && n_traceroute_dynamics == 0){
//                    n_flow_not_impacted_traceroutes += 1;
//                }
//            }
//        }
//
//        for (const auto & subgraph_dynamics : total_subgraph_dynamics){
//            const auto & node = subgraph_dynamics.first;
//            const auto & node_dynamics = subgraph_dynamics.second;
//
//
//            for(std::size_t d = 1; d < node_dynamics.size(); ++d){
//                if (node_dynamics[d] != node_dynamics[d-1]){
//                    n_total_subgraph_dynamics += 1;
//                }
//            }
//        }
//    }
//
//
//    std::cout << "Flow dynamics: "  << n_total_flow_dynamics << "\n";
//    std::cout << "Traceroute dynamics impacted by flow: "  << n_flow_impacted_traceroutes << "\n";
//    std::cout << "Traceroute dynamics not impacted by flow: "  << n_flow_not_impacted_traceroutes << "\n";
//    std::cout << "Subgraph dynamics : "  << n_total_subgraph_dynamics << "\n";


}