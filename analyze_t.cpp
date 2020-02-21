//
// Created by System Administrator on 2019-02-10.
//

#include "analyze_t.hpp"
#include "probe_dto_t.hpp"
#include <fstream>
#include <unordered_map>
#include <sstream>
#include <unordered_map>
#include <traceroute_graph_t.hpp>
#include <utils/struct_utils_t.hpp>
#include <memory>
#include <iostream>
#include <random>
#include <algorithm>

namespace {
    std::vector<int> nks95 {0,6,11,16,21,27,32,38,44,50,57,63,69,76,82,89,96,103,109,116,123,130,137,144,151,159,166,173,180,188,195,202,210,217,225,232,240,247,255,263,270,278,285,293,301,309,316,324,332,340,348,356,364,371,379,387,395,403,411,419,427,435,443,452,460,468,476,484,492,500,509,517,525,533,541,550,558,566,575,583,591,600,608,616,625,633,641,650,658,667,675,684,692,701,709,718,726,735,743,752,760,769,777,786,794,803,812,820,829,838,846,855,863,872,881,890,898,907,916,924,933,942,951,959,968,977,986,994,1003,1012,1021,1030,1039,1047,1056,1065,1074,1083,1092,1100,1109,1118,1127,1136,1145,1154,1163,1172,1181,1190,1199,1208,1217,1226,1234,1243,1252,1261,1270,1279,1288,1297,1307,1316,1325,1334,1343,1352,1361,1370,1379,1388,1397,1406,1415,1424,1434,1443,1452,1461,1470,1479,1488,1498,1507,1516,1525,1534,1543,1553,1562,1571,1580,1589,1599,1608,1617,1626,1635};

    auto n_not_single_answer_per_triplet = 0;
    auto n_error_lines = 0;
    constexpr bool is_debug = false;
    constexpr bool is_statistics_enabled = true;

}

using namespace utils;
//using namespace google;

void analyze_t::next_round(const std::string &input_sorted_csv, const std::string &output_shuffle_probes) {
    // Faster read
//    std::ios_base::sync_with_stdio(false);

    /**
     * Statistics
     */

    std::vector<uint16_t > flow_ids;
    for(uint16_t i = 35000; i < 35006; ++i){
        flow_ids.push_back(i);
    }
    std::vector<std::pair<uint32_t , uint32_t>> all_links;
    std::vector<uint32_t> all_nodes;
    std::unordered_set<std::pair<uint32_t , uint32_t >, pair_hash> unique_diamonds;

    std::unordered_map <uint16_t , std::vector<std::pair<uint32_t , uint32_t>>> links_by_flow_id;
    std::unordered_map <uint16_t , std::vector<uint32_t> > nodes_by_flow_id;
    /**
     * IO stuff
     */
    uint8_t max_ttl = 30;
    using node_t = traceroute_graph_t::node_t;

    std::ifstream infile(input_sorted_csv);

    /**
     * Output
     */
    std::vector<probe_dto_t> next_round_probes;


    /**
     * Parsing stuff
     */
//    uint16_t starting_dport = 35000;


    uint32_t src_ip = 0;
    uint32_t old_src_ip = src_ip;

    uint32_t dst_ip = 0;
    uint32_t old_dst_ip = dst_ip;

    uint32_t reply_ip = 0;


    uint16_t sport = 0;
    uint16_t old_sport = sport;
    uint16_t dport = 0;
    uint8_t  ttl = 0;

    char delimiter = ',';

    std::string line;

    std::vector<std::shared_ptr<node_t>> nodes;

    std::unordered_map<uint8_t, std::vector<uint16_t>> flows_per_ttl;

    std::unordered_map<std::pair<uint32_t , uint8_t>, std::shared_ptr<node_t>,pair_hash> nodes_by_ip_flow_ids;
//    nodes_by_ip_flow_ids.set_empty_key(std::make_pair(0,0));
    std::unordered_map<std::pair<uint16_t , uint8_t>, std::shared_ptr<node_t>,pair_hash> nodes_by_ttl_flow_ids;
//    nodes_by_ttl_flow_ids.set_empty_key(std::make_pair(0,0));
    auto count = 0;
    while (std::getline(infile, line)) {
        ++count;
        if (count %1000000 == 0) {
            std::cout << count << "\n";
        }
//        if (count == 20000000){
//            break;
//        }

//        std::cout << line << "\n";
//        continue;
        bool is_same_traceroute = true;

        std::stringstream stream_line(line);
        std::string token;
        int index = 0;
        bool is_error_line = false;
        while(std::getline(stream_line, token,delimiter)){
            auto token_uint = static_cast<uint32_t>(std::stoul(token));
            ++index;

            if (token_uint == 0){
                // 0 is an incorrect value for any field.
                is_error_line = true;
            }

            if (index == 1){
                //src_ip
                old_src_ip = src_ip;
                if (token_uint != src_ip){
                    src_ip = token_uint;
                    is_same_traceroute = false;
                }
            } else if (index == 2){

                old_dst_ip = dst_ip;
                if (token_uint != dst_ip){
                    dst_ip = token_uint;
                    is_same_traceroute = false;
                }

            } else if (index == 3){
                reply_ip = token_uint;
            } else if (index == 4){
                old_sport = sport;
                if (token_uint != sport){
                    sport = static_cast<uint16_t>(token_uint);
                }
            } else if (index == 5){
                if (token_uint != dport){
                    dport = static_cast<uint16_t>(token_uint);
                }
            } else if (index == 6){

                if (token_uint != ttl){
                    ttl = static_cast<uint8_t>(token_uint);
                }
            }
        }
        if (!is_same_traceroute){
            flush_traceroute(old_src_ip, old_dst_ip, old_sport, max_ttl, nodes, flows_per_ttl, unique_diamonds, next_round_probes);
            clear_data_structure(nodes, nodes_by_ip_flow_ids, nodes_by_ttl_flow_ids, flows_per_ttl);
        }

        if (is_error_line){
            ++n_error_lines;
            continue;
        }

        // Update the nodes
        update_traceroute_node(dst_ip, reply_ip, ttl, dport,nodes, flows_per_ttl, nodes_by_ip_flow_ids, nodes_by_ttl_flow_ids,
                all_nodes, all_links, nodes_by_flow_id, links_by_flow_id);

        if (is_statistics_enabled){
            // Transform the nodes to set and clear the vector so it does not use too much RAM

        }


    }

    if (is_statistics_enabled){

//        std::unordered_set<uint32_t > unique_nodes(std::make_move_iterator(all_nodes.begin()),
//                std::make_move_iterator(all_nodes.end()));
        std::sort(all_nodes.begin(), all_nodes.end());
        auto it_unique_nodes  = std::unique(all_nodes.begin(), all_nodes.end());


//        std::unordered_set<std::pair<uint32_t, uint32_t >, pair_hash> unique_links(std::make_move_iterator(all_links.begin()),
//                                                   std::make_move_iterator(all_links.end()));
        std::sort(all_links.begin(), all_links.end());
        auto it_unique_links = std::unique(all_links.begin(), all_links.end());

        auto n_unique_nodes = std::distance(all_nodes.begin(), it_unique_nodes);
        auto n_unique_links = std::distance(all_links.begin(), it_unique_links);
        std::cout << "Found " << n_error_lines << " lines with a field with a 0.\n";
        std::cout << "Found " << n_not_single_answer_per_triplet << " anomalies\n";
        std::cout << "Found " << unique_diamonds.size() << " unique diamonds.\n";

        std::cout << "Found " << n_unique_nodes << " unique nodes.\n";
        std::cout << "Found " << n_unique_links << " unique links.\n";

        for (const auto flow_id : flow_ids){
            auto & v = nodes_by_flow_id[flow_id];
            std::sort(v.begin(), v.end());
            auto it_unique  = std::unique(v.begin(), v.end());
            auto n_unique = std::distance(v.begin(), it_unique);
            std::cout << "Found " << n_unique << " nodes for flow id " << flow_id << "\n";
        }

        for (const auto flow_id : flow_ids){
            auto & v = links_by_flow_id[flow_id];
            std::sort(v.begin(), v.end());
            auto it_unique  = std::unique(v.begin(), v.end());
            auto n_unique = std::distance(v.begin(), it_unique);
            std::cout << "Found " << n_unique << " links for flow id " << flow_id << "\n";
        }
    }


    // Shuffle the next round probes
    auto rng = std::default_random_engine {};
//    std::shuffle(next_round_probes.begin(), next_round_probes.end(), rng);

    std::ofstream ofile {output_shuffle_probes};

    for (const auto & probe : next_round_probes){
        ofile << probe.m_source_ip << "," << probe.m_indirect_ip << "," << probe.m_sport << ","<< probe.m_dport<<","<< unsigned(probe.m_ttl)<<"\n";
    }



}

void analyze_t::update_traceroute_node(uint32_t dst_ip, uint32_t reply_ip, uint8_t ttl, uint16_t dport,
                                       std::vector<std::shared_ptr<traceroute_graph_t::node_t>> & nodes,
                                       std::unordered_map<uint8_t, std::vector<uint16_t>> & flows_per_ttl,
                                       std::unordered_map<std::pair<uint32_t , uint8_t>, std::shared_ptr<traceroute_graph_t::node_t>,pair_hash> & nodes_by_ip_flow_ids,
                                       std::unordered_map<std::pair<uint16_t , uint8_t>, std::shared_ptr<traceroute_graph_t::node_t>,pair_hash> & nodes_by_ttl_flow_ids,
                                       std::vector<uint32_t> & unique_nodes,
                                       std::vector<std::pair<uint32_t, uint32_t >> & unique_links,
                                       std::unordered_map<uint16_t, std::vector<uint32_t >> & nodes_by_flow_id,
                                       std::unordered_map <uint16_t , std::vector<std::pair<uint32_t , uint32_t>>> & links_by_flow_id) const
                                       {
    using node_t = traceroute_graph_t::node_t;


    auto key_node = std::make_pair(reply_ip, ttl);
    auto it = nodes_by_ip_flow_ids.find(key_node);
    if (it == nodes_by_ip_flow_ids.end()){
        std::shared_ptr<node_t> new_node {new node_t};
        new_node->m_ip = reply_ip;
        new_node->m_flow_ids.insert(dport);
        new_node->m_ttl = ttl;

//        nodes_by_ttl_flow_ids[std::make_pair(new_node->m_ttl, dport)] = new_node;
        auto is_inserted = nodes_by_ttl_flow_ids.insert(std::make_pair(std::make_pair(ttl, dport), new_node));
        if (is_inserted.second){
            if  (is_statistics_enabled){
                unique_nodes.push_back(reply_ip);
//                if (unique_nodes.size() % 100000 == 0){
//                    std::cout << "Found " << unique_nodes.size() << " unique nodes.\n";
//                }
            }

            nodes_by_ip_flow_ids[key_node] = new_node;
            nodes.push_back(new_node);
        } else {
            // Surely a misconfiguration, manually investigate the cases and print the corresponding triplet
            ++n_not_single_answer_per_triplet;
            if (n_not_single_answer_per_triplet % 10000 == 0){
                std::cerr << "Anomalies: " << n_not_single_answer_per_triplet << "\n";
            }
            if (is_debug){

                std::cerr << "Triplet (IP in big endian): " << dst_ip << "," << unsigned(ttl) << "," << dport << "," << reply_ip <<  "\n";
                std::cerr << "Fail insert, was: " << is_inserted.first->second->m_ip << "," << unsigned(is_inserted.first->second->m_ttl) << "\n";
            }

            // Do not update the links and return.
            return;
        }


    } else {
        it->second->m_flow_ids.insert(dport);
        nodes_by_ttl_flow_ids[std::make_pair(it->second->m_ttl, dport)] = it->second;

    }
    // Update the links
    auto & node = nodes_by_ttl_flow_ids[std::make_pair(ttl, dport)];
    auto predecessor_it = nodes_by_ttl_flow_ids.find(std::make_pair(node->m_ttl - 1, dport));
    if (predecessor_it != nodes_by_ttl_flow_ids.end()){
        predecessor_it->second->m_successors.insert(node);
        if (is_statistics_enabled){
            if (predecessor_it->second->m_ip != reply_ip){
                auto link = std::make_pair(predecessor_it->second->m_ip,reply_ip);
                unique_links.push_back(link);
//                if (unique_links.size() % 100000 == 0){
//                    std::cout << "Found " << unique_links.size() << " unique links.\n";
//                }
                links_by_flow_id[dport].push_back(link);
            }
        }

    }

    if (is_statistics_enabled){
        nodes_by_flow_id[dport].push_back(reply_ip);
    }
//    if (dst_ip == 112544773 && ttl == 8){
//        std::cerr << "Link inserted\n";
//    }

    // Update the flows
    flows_per_ttl[ttl].push_back(dport);

}

void analyze_t::flush_traceroute(uint32_t src_ip, uint32_t dst_ip, uint16_t sport, uint8_t max_ttl,
        const std::vector<std::shared_ptr<traceroute_graph_t::node_t>> & nodes,
        const std::unordered_map<uint8_t, std::vector<uint16_t> > & flows_per_ttl,
        std::unordered_set<std::pair<uint32_t, uint32_t >, pair_hash> & unique_diamonds,
        std::vector<probe_dto_t> & next_round_probes
) const  {
// Flush the traceroute needed probes to the csv file.
    traceroute_graph_t traceroute_graph(max_ttl);

    traceroute_graph.get_graph().m_nodes = nodes;
    traceroute_graph.set_flows_per_ttl(flows_per_ttl);
    traceroute_graph.compute_diamonds();

    if(unique_diamonds.size() % 10000 == 0){
        std::cout << "Found " << unique_diamonds.size() << " unique diamonds.\n";
    }

    // Compute the number of flows needed on a link based MDA.
    std::unordered_map<uint8_t, int> probes_by_ttl;
//    for(uint8_t i = 0; i < max_ttl; ++i){
//        probes_by_ttl[i] = 0;
//    }

    for (const auto & diamond : traceroute_graph.get_diamonds()){
        if (diamond.m_divergence_point.get() != nullptr && diamond.m_convergence_point.get() != nullptr){
            auto is_new_diamond = unique_diamonds.insert(std::make_pair(diamond.m_divergence_point->m_ip, diamond.m_convergence_point->m_ip)).second;

            if(!is_new_diamond){
                continue;
            }
        }

        for (const auto & links_by_ttl : diamond.get_probes_links_by_ttl()){
            const auto & iter_ttl = links_by_ttl.first;
            auto & probes_ttl = probes_by_ttl[iter_ttl];
            auto & probes_ttl_plus_1 = probes_by_ttl[iter_ttl+1];

            const auto & probes_links = links_by_ttl.second;
            if (probes_links.second >= nks95.size()){

                if (is_debug){
                    std::cerr << "Error in traceroute to: "<< dst_ip << "\n";
                    std::cout << probes_links.second << " Missing nks values, too many links discovered between ttl" <<
                              unsigned(iter_ttl) << "and " << unsigned(iter_ttl + 1) << "\n";
                    for (const auto & node : nodes){
                        std::cout << node->m_ip << "," << unsigned(node->m_ttl) << "\n";
                    }
                }
                exit(1);
            }
            auto additional_probes = nks95[probes_links.second] - probes_links.first;

            // Assume that the first round use nks[1] flows. Then, if the first round discovered only one interface for n1 flows, do not
            // send more probes there ?
            // Now the implementation is conservative, still sending to the single node ttl.

            if (additional_probes > probes_ttl){
                probes_ttl = additional_probes;
            }

            // Flush these new probes for TTL

            if (additional_probes > probes_ttl_plus_1){
                probes_ttl_plus_1 = additional_probes;
            }
        }
    }



    for (const auto & probes_ttl : probes_by_ttl){
        probe_dto_t new_probe;
        new_probe.m_source_ip = src_ip;
        new_probe.m_indirect_ip = dst_ip;
        new_probe.m_sport = sport;
        new_probe.m_ttl = probes_ttl.first;
        for (int i = 0; i < probes_ttl.second; ++i){
            auto max_flow = traceroute_graph.get_max_flow_by_ttl()[new_probe.m_ttl];
            new_probe.m_dport = max_flow + static_cast<uint16_t >(i+1) ;
            next_round_probes.push_back(new_probe);
        }
    }
}

void analyze_t::clear_data_structure(std::vector<std::shared_ptr<traceroute_graph_t::node_t>> & nodes,
                                     std::unordered_map<std::pair<uint32_t , uint8_t>, std::shared_ptr<traceroute_graph_t::node_t>,pair_hash> & nodes_by_ip_flow_ids,
std::unordered_map<std::pair<uint16_t , uint8_t>, std::shared_ptr<traceroute_graph_t::node_t>,pair_hash> & nodes_by_ttl_flow_ids,
std::unordered_map<uint8_t, std::vector<uint16_t>> & flows_per_ttl
) {
    nodes.clear();
    nodes_by_ttl_flow_ids.clear();
    nodes_by_ip_flow_ids.clear();
    flows_per_ttl.clear();
}

void analyze_t::count_unique(const std::string & ifile) {


    std::ifstream infile{ifile};
    std::unordered_set<std::pair<uint32_t , uint32_t>, pair_hash> unique_links;
    std::unordered_set<uint32_t> unique_nodes;
    std::unordered_map<uint16_t , std::unordered_set<uint32_t>> unique_nodes_by_flow_id;

    std::vector<uint16_t > flow_ids;

    for (uint16_t i = 0; i < 1 ; ++i){
        flow_ids.push_back(static_cast<unsigned short &&>(35000 + i));
    }

    std::string line;
    int count = 0;
    char delimiter = ',';
    bool is_terminate = false;
    while (std::getline(infile, line)) {
        ++count;
        if (count %1000000 == 0) {
            std::cout << count << "\n";
        }
//        if (count == 100000){
//            break;
//        }

//        std::cout << line << "\n";
//        continue;
        bool is_same_traceroute = true;

        std::stringstream stream_line(line);
        std::string token;
        int index = 0;
        bool is_error_line = false;

        uint32_t reply_ip = 0;

        while(std::getline(stream_line, token,delimiter)){
            auto token_uint = static_cast<uint32_t>(std::stoul(token));
            if (token_uint == 0){
                // 0 is an incorrect value for any field.
                is_error_line = true;
                break;
            }

            if (index == 2) {
                unique_nodes.insert(token_uint);
                reply_ip = token_uint;
                if (unique_nodes.size() % 100000 == 0){
                    std::cout << "Found " << unique_nodes.size() << " unique nodes.\n";
                }
            }
            else if (index == 4){
                if (std::find(flow_ids.begin(), flow_ids.end(), static_cast<uint16_t> (token_uint)) != flow_ids.end()){
                    unique_nodes_by_flow_id[static_cast<uint16_t >(token_uint)].insert(reply_ip);
                } else if (token_uint == 35001) {
                    is_terminate = true;
                }
                break;
            }
//                if (token_uint != dport){
//                    dport = static_cast<uint16_t>(token_uint);
//                }
//                reply_ip = token_uint;
//            if (index == 0){
//                //src_ip
//                old_src_ip = src_ip;
//                if (token_uint != src_ip){
//                    src_ip = token_uint;
//                    is_same_traceroute = false;
//                }
//            } else if (index == 1){
//                old_dst_ip = dst_ip;
//                if (token_uint != dst_ip){
//                    dst_ip = token_uint;
//                    is_same_traceroute = false;
//                }
//            } else if (index == 2){
//                reply_ip = token_uint;
//            } else if (index == 3){
//                old_sport = sport;
//                if (token_uint != sport){
//                    sport = static_cast<uint16_t>(token_uint);
//                }
//            } else if (index == 4){
//                if (token_uint != dport){
//                    dport = static_cast<uint16_t>(token_uint);
//                }
//            } else if (index == 5){
//
//                if (token_uint != ttl){
//                    ttl = static_cast<uint8_t>(token_uint);
//                }
//            }
            ++index;
        }
        if (is_error_line){
            continue;
        }
        if (is_terminate){
            break;
        }
        // Update the nodes
//        update_traceroute_node(reply_ip, ttl, dport,nodes, flows_per_ttl, nodes_by_ip_flow_ids, nodes_by_ttl_flow_ids);
    }
    // Compute the difference
    std::unordered_set<uint32_t> load_balancing_interfaces;
    for (const auto & flow_ids_ips : unique_nodes_by_flow_id){

        if (flow_ids_ips.first == 35000){
            continue;
        }
        for (const auto & ip: flow_ids_ips.second){
            bool found_by_first_flow_id = true;
            for (const auto & ip_ref : unique_nodes_by_flow_id[35000]){
                if (ip == ip_ref){
                    found_by_first_flow_id = false;
                    break;
                }
            }
            if (found_by_first_flow_id){
                load_balancing_interfaces.insert(ip);
            }
        }
    }

    std::cout << "Found " << unique_nodes.size() << " unique nodes.\n";
    std::cout << "Found " << unique_links.size() << " unique links.\n";
    std::cout << "Found " << load_balancing_interfaces.size() << " unique interfaces via LB.\n";
}



