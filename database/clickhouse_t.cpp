//
// Created by System Administrator on 2019-05-22.
//

#include "clickhouse_t.hpp"
#include <utils/network_utils_t.hpp>
#include <utils/parameters_utils_t.hpp>
#include <cmath>
#include <iostream>
#include <random>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <algorithm>
#include <maths/stopping_points_t.hpp>
#include <arpa/inet.h>
#include <mutex>  // For std::unique_lock
#include <shared_mutex>
#include <thread>

using namespace clickhouse;
using namespace utils;
clickhouse_t::clickhouse_t(const process_options_t & options):
m_client{ClientOptions().SetHost(options.db_host)},
m_options(options),
m_patricia_trie_excluded((32))
{
    // Initialize client connection.
    // Initialize patricia trie for private and excluded prefixes
    m_patricia_trie_excluded.populateBlock(AF_INET, m_options.exclusion_file.c_str());
}

void clickhouse_t::set_skip_prefixes(const std::string &skip_prefixes_file)
{
    // Initialize skip prefixes
    std::ifstream file(skip_prefixes_file);
    std::string prefix_str;
    while (std::getline(file, prefix_str))
    {

        uint32_t prefix;
        std::istringstream iss (prefix_str);
        iss >> prefix;
        if (iss.fail()) {
            // something wrong happened
        }
        m_prefixes_done[prefix] = true;
    }
}

void clickhouse_t::write_skip_prefixes(const std::string & skip_prefixes_file) {

    std::ofstream ofstream;
    ofstream.open(skip_prefixes_file);

    for (const auto & prefix : m_prefixes_done){
        if (prefix.second){
            ofstream << prefix.first << "\n";
        }
    }
}

void clickhouse_t::next_max_ttl_traceroutes(const std::string &table, uint32_t vantage_point_src_ip,
                                            const process_options_t &options, std::ostream &ostream) {

    int first_round_max_ttl = 30;
    int absolute_max_ttl = 40;

    int snapshot = options.snapshot;
    int round = options.round;
    uint32_t vp_inf_born = options.inf_born;
    uint32_t vp_sup_born = options.sup_born;

    auto interval_split = 64; // Power of 2 because we want to keep track of all /24 prefixes

    for (auto i = 0; i < interval_split; ++i) {
        auto inf_born = static_cast<uint32_t >(vp_inf_born + i * ((vp_sup_born - vp_inf_born) / interval_split));
        auto sup_born = static_cast<uint32_t >(vp_inf_born + (i + 1) * ((vp_sup_born - vp_inf_born) / interval_split));
//        std::cout << "Computing next round for " << inf_born << " AND " << sup_born << "\n";
        if (can_skip_ipv4_block(inf_born, sup_born)) {
            continue;
        }


        std::string request = build_subspace_request_per_prefix_max_ttl(table, vantage_point_src_ip, snapshot, round,
                inf_born,
                sup_born,
                options);
#ifndef NDEBUG
        std::cout << request << std::endl;
#endif
//    std::cout << request << std::endl;

        m_client.Select(request, [&ostream, &options, first_round_max_ttl, absolute_max_ttl](const Block &block) {
            for (size_t k = 0; k < block.GetRowCount(); ++k) {
                uint32_t src_ip = block[0]->As<ColumnUInt32>()->At(k);
                uint32_t dst_ip = block[1]->As<ColumnUInt32>()->At(k);
                uint8_t max_ttl = block[2]->As<ColumnUInt8>()->At(k);

                if (max_ttl > absolute_max_ttl){
                    continue;
                }
//            uint16_t min_dst_port = block[6]->As<ColumnUInt16>()->At(k);
//            uint16_t max_dst_port = block[7]->As<ColumnUInt16>()->At(k);
//            uint32_t max_round = block[8]->As<ColumnUInt32>()->At(k);
                if (max_ttl > 20) {
                    for (auto i = first_round_max_ttl + 1; i <= max_ttl + 10 && i <= absolute_max_ttl; ++i) {

//                    std::cout << src_ip << ","
//                              << dst_ip << ","
//                              // default sport
//                              << options.sport << ","
//                              << options.dport  << ","
//                              << i << "\n";

                        ostream << htonl(src_ip) << ","
                                << htonl(dst_ip) << ","
                                // default sport
                                << options.sport << ","
                                << options.dport << ","
                                << i << "\n";
                    }
                }


            }
        });

        std::cout << i << " on " << interval_split << " IPv4 space done\n";

    }



}

std::string
clickhouse_t::build_subspace_request_per_prefix_max_ttl(const std::string &table, uint32_t vantage_point_src_ip,
                                                        int snapshot, int round, uint32_t inf_born, uint32_t sup_born,
                                                        const process_options_t & options) {

    std::string subspace_request = {
            "SELECT \n"
            "    src_ip, \n"
            "    dst_ip, \n"
            "    max(" + options.encoded_ttl_from + ") as max_ttl \n"
            "FROM \n"
            "(\n"
            "    SELECT *\n"
            "    FROM " + table + "\n"
            "    WHERE dst_prefix > " + std::to_string(inf_born) + " AND dst_prefix <= " + std::to_string(sup_born) + " AND round <= " + std::to_string(round) + "\n"
            "    AND src_ip = " + std::to_string(vantage_point_src_ip) + " \n"
            "    AND snapshot = " + std::to_string(snapshot) + " \n"
            ") \n"
            "WHERE "
            " dst_prefix NOT IN "
            "(\n"
            " SELECT dst_prefix\n"
            "    FROM \n"
            "    (\n"
            "        SELECT \n"
            "            src_ip, \n"
            "            dst_prefix, \n"
            "            MAX(round) AS max_round\n"
            "        FROM " + table + "\n"
            "        WHERE dst_prefix > " + std::to_string(inf_born) + " AND dst_prefix <= " + std::to_string(sup_born) + "\n"
            "        AND src_ip = " + std::to_string(vantage_point_src_ip) + " \n"
            "        AND snapshot = " + std::to_string(snapshot) + " \n"
            "        GROUP BY (src_ip, dst_prefix)\n"
            "        HAVING max_round < " + std::to_string(round - 1) + "\n"
            "    ) \n"
            ") "
            " AND dst_prefix NOT IN (\n"
            " SELECT dst_prefix\n"
            "    FROM \n"
            "    (\n"
            "        SELECT \n"
            "            src_ip, \n"
            "            dst_prefix, \n"
            "            " + options.encoded_ttl_from + ", \n"
            "            COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow, \n"
            "            COUNT((src_ip, dst_ip,  " + options.encoded_ttl_from + ", src_port, dst_port)) AS cnt \n"
            "        FROM " + table + "\n"
            "        WHERE dst_prefix > " + std::to_string(inf_born) + " AND dst_prefix <= " + std::to_string(sup_born) + "\n"
            "        AND src_ip = " + std::to_string(vantage_point_src_ip) + " \n"
            "        AND snapshot = " + std::to_string(snapshot) + " \n"
            "        GROUP BY (src_ip, dst_prefix, dst_ip, " + options.encoded_ttl_from + ", src_port, dst_port, snapshot)\n"
            "        HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)\n"
            //                                  "        ORDER BY (src_ip, dst_ip, ttl) ASC\n"
            "    ) \n"
            "    GROUP BY (src_ip, dst_prefix)\n"
            "   )"
            //            ")"
            " AND dst_ip != reply_ip \n"
            " GROUP BY (src_ip, dst_ip) \n"
    };

    return subspace_request;
}

void
clickhouse_t::next_round_csv(const std::string & table, uint32_t vantage_point_src_ip, const process_options_t & options,
                                              std::ostream &ostream
) {


    int snapshot = options.snapshot;
    int round = options.round;
    uint32_t vp_inf_born = options.inf_born;
    uint32_t vp_sup_born = options.sup_born;
    // Split the IPv4 space in n so that we do not overload server RAM.
    auto interval_split = 64; // Power of 2 because we want to keep track of all /24 prefixes

    for (auto i = 0; i < interval_split; ++i) {

//        if (i < 5){
//            continue;
//        }

        auto inf_born = static_cast<uint32_t >(vp_inf_born + i * ((vp_sup_born - vp_inf_born) / interval_split));
        auto sup_born = static_cast<uint32_t >(vp_inf_born + (i + 1) * ((vp_sup_born - vp_inf_born) / interval_split));
//        std::cout << "Computing next round for " << inf_born << " AND " << sup_born << "\n";
        if (can_skip_ipv4_block(inf_born, sup_born)){
            continue;
        }

        if (sup_born > 3758096384){ // 224.0.0.0
            continue;
        }

//        auto inf_born = static_cast<uint32_t> (i * ((std::pow(2, 32) - 1) / interval_split));
//        auto sup_born = static_cast<uint32_t >((i + 1) * ((std::pow(2, 32) - 1) / interval_split));

        std::string link_query = build_subspace_request_per_prefix_load_balanced_paths(table, vantage_point_src_ip,
                                                                                       snapshot, round, inf_born,
                                                                                       sup_born, options);
#ifndef NDEBUG
        std::cout << link_query << std::endl;
#endif

//        std::cout << link_query << "\n";

        // Represents nodes at ttl i
        std::vector<int> nodes_per_ttl(max_ttl + 1, 0);
        // Represents links between ttl i and i + 1
        std::vector<int> links_per_ttl(max_ttl + 1, 0);
        std::vector<int> previous_max_flow_per_ttl(max_ttl + 1, 0);
        uint32_t current_source = 0;
        uint32_t current_prefix = 0;
        uint32_t current_max_dst_ip = 0;
        uint16_t current_max_src_port = options.sport;
        uint16_t current_min_dst_port = options.dport;
        uint16_t current_max_dst_port = options.dport;
        uint32_t current_max_round = 0;
        // Maximum src port used at ttl i

        m_client.Select(link_query,
                        [this, inf_born, sup_born, round,
                         &current_source, &current_prefix, &current_max_dst_ip,
                         &current_min_dst_port, &current_max_dst_port, &current_max_src_port, &current_max_round,
                         &nodes_per_ttl, &links_per_ttl, &previous_max_flow_per_ttl,
                         &options, &ostream](
                                const Block &block) {
//            if (block.GetRowCount() == 0){
//                // Insert all the /24 prefixes in this block to be skipped
//                auto prefix = closest_prefix(inf_born, 24);
//                for (; prefix <= sup_born ;prefix += 256){
//                    m_prefixes_done[prefix] = true;
//                }
//            }
            for (size_t k = 0; k < block.GetRowCount(); ++k) {
                uint32_t src_ip = block[0]->As<ColumnUInt32>()->At(k);
                uint32_t dst_prefix = block[1]->As<ColumnUInt32>()->At(k);
                uint16_t max_src_port = block[5]->As<ColumnUInt16>()->At(k);
                uint32_t max_dst_ip = block[2]->As<ColumnUInt32>()->At(k);
                uint16_t min_dst_port = block[6]->As<ColumnUInt16>()->At(k);
                uint16_t max_dst_port = block[7]->As<ColumnUInt16>()->At(k);
                uint32_t max_round = block[8]->As<ColumnUInt32>()->At(k);

                if(current_prefix == 0){
                    // First prefix in the batch
                    current_prefix = dst_prefix;
                }

                if(dst_prefix == current_prefix){
                    // We are still in the same prefix so check if we have a higher IP address and a higher port.
                    if (current_max_dst_ip < max_dst_ip){
                        current_max_dst_ip = max_dst_ip;
                    }

                    if (current_max_src_port < max_src_port){
                        current_max_src_port = max_src_port;
                    }

                    if (current_max_round < max_round){
                        current_max_round = max_round;
                    }
                }


                if (dst_prefix != current_prefix){
                    // Flush the current structure and reset it.
                    if (current_max_round == round){
//                        std::cout << current_prefix << std::endl;
                        // We did not get any answers from the previous round, so stop probing this prefix.
                        flush_traceroute(round, current_source, current_prefix, current_max_dst_ip,
                                         current_min_dst_port, current_max_dst_port, current_max_src_port,
                                         nodes_per_ttl, links_per_ttl, previous_max_flow_per_ttl,
                                         options,
                                         ostream);
                    }

                    //                    std::cout << "Flushed traceroute from " << current_source << " to " << current_prefix << "\n";
                    current_source = src_ip;
                    current_prefix = dst_prefix;
                    current_max_dst_ip = max_dst_ip;
                    current_min_dst_port = min_dst_port;
                    current_max_dst_port = max_dst_port;
                    current_max_src_port = max_src_port;
                    nodes_per_ttl.assign(max_ttl + 1, 0);
                    links_per_ttl.assign(max_ttl + 1, 0);
                    previous_max_flow_per_ttl.assign(max_ttl + 1, 0);
                }

                // Get TTL
                int ttl = static_cast<int>(block[3]->As<ColumnUInt8>()->At(k));
                if (ttl > max_ttl){
                    continue;
                }
                // Get number of nodes
                int n_nodes = static_cast<int>(block[9]->As<ColumnUInt64>()->At(k));
                nodes_per_ttl[ttl] = n_nodes;

//                std::cout << block[4]->Type()->GetName() << "\n";
                int n_links = static_cast<int>(block[4]->As<ColumnUInt64>()->At(k));
                links_per_ttl[ttl] = n_links;




                int max_flow = max_dst_ip - (dst_prefix + default_dst_ip);
                if (round == 1){
                    if (max_flow < 6){
                        max_flow = 6;
                    }
                }
                previous_max_flow_per_ttl[ttl] = max_flow;

            }
        });
        // Flush the last traceroute
        flush_traceroute(round,
                current_source, current_prefix, current_max_dst_ip,
                current_min_dst_port, current_max_dst_port, current_max_src_port,
                nodes_per_ttl, links_per_ttl, previous_max_flow_per_ttl,
                options,
                ostream);


        std::cout << i << " on " << interval_split << " IPv4 space done\n";

    }

}


std::string clickhouse_t::build_subspace_request_per_prefix_load_balanced_paths(const std::string &table,
                                                                                uint32_t vantage_point_src_ip,
                                                                                int snapshot, int round,
                                                                                uint32_t inf_born,
                                                                                uint32_t sup_born,
                                                                                const process_options_t & options) {

    std::string subspace_request {
        "WITH groupUniqArray((dst_prefix, dst_ip, p1.reply_ip, p2.reply_ip)) as links_per_dst_ip,\n"
        "arrayFilter((x->(x.2 != x.4 AND x.3 != x.4 AND x.3!=0  AND x.4 != 0 )), links_per_dst_ip) as core_links_per_dst_ip,\n"
        "arrayMap((x->(x.3, x.4)), core_links_per_dst_ip) as core_links_per_prefix,\n"
        "arrayDistinct(core_links_per_prefix) as unique_core_links_per_prefix,\n"
        "length(unique_core_links_per_prefix) as n_links,\n"
        "length(groupUniqArray((p1.reply_ip))) as n_nodes \n"
        "SELECT \n"
        "    src_ip, \n"
        "    dst_prefix, \n"
        "    max(p1.dst_ip), \n"

        "    " + options.encoded_ttl_from + ", \n"
        "    n_links, \n"
        "    max(src_port), \n"
        "    min(dst_port), \n"
        "    max(dst_port), \n"
        "    max(round), \n"
        "    n_nodes \n"
        "FROM \n"
        "(\n"
        "    SELECT *\n"
        "    FROM " + table + "\n"
        "    WHERE dst_prefix > " + std::to_string(inf_born) + " AND dst_prefix <= " + std::to_string(sup_born) + " AND round <= " + std::to_string(round) + "\n"
        "    AND src_ip = " + std::to_string(vantage_point_src_ip) + " \n"
        "    AND snapshot = " + std::to_string(snapshot) + " \n"
        ") AS p1 \n"
        "LEFT OUTER JOIN \n"
        "(\n"
        "    SELECT *\n"
        "    FROM " + table + "\n"
        "    WHERE dst_prefix > " + std::to_string(inf_born) + " AND dst_prefix <= " + std::to_string(sup_born) + " AND round <= " + std::to_string(round) + "\n"
        "    AND src_ip = " + std::to_string(vantage_point_src_ip) + " \n"
        "    AND snapshot = " + std::to_string(snapshot) + " \n"
        ") AS p2 ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip) "
        " AND (p1.src_port = p2.src_port) AND (p1.dst_port = p2.dst_port) "
        " AND (p1.round = p2.round) AND (p1.snapshot = p2.snapshot) "
        " AND (toUInt8(p1." + options.encoded_ttl_from + " + toUInt8(1)) = p2."+ options.encoded_ttl_from + ")\n"
        "WHERE dst_prefix NOT IN (\n"
        " SELECT dst_prefix\n"
        "    FROM \n"
        "    (\n"
        "        SELECT \n"
        "            src_ip, \n"
        "            dst_prefix, \n"
        "            MAX(round) AS max_round\n"
        "        FROM " + table + "\n"
        "        WHERE dst_prefix > " + std::to_string(inf_born) + " AND dst_prefix <= " + std::to_string(sup_born) + "\n"
        "        AND src_ip = " + std::to_string(vantage_point_src_ip) + " \n"
        "        AND snapshot = " + std::to_string(snapshot) + " \n"
        "        GROUP BY (src_ip, dst_prefix)\n"
        "        HAVING max_round < " + std::to_string(round - 1) + "\n"
        "    ) \n"
        ") AND dst_prefix NOT IN (\n"
        "    SELECT dst_prefix\n"
        "    FROM \n"
        "    (\n"
        "        SELECT \n"
        "            src_ip, \n"
        "            dst_prefix, \n"
        "            " + options.encoded_ttl_from +  ", \n"
        "            COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow, \n"
        "            COUNT((src_ip, dst_ip, " + options.encoded_ttl_from +", src_port, dst_port)) AS cnt \n"
        "        FROM " + table + "\n"
        "        WHERE dst_prefix > " + std::to_string(inf_born) + " AND dst_prefix <= " + std::to_string(sup_born) + "\n"
        "        AND src_ip = " + std::to_string(vantage_point_src_ip) + " \n"
        "        AND snapshot = " + std::to_string(snapshot) + " \n"
        "        GROUP BY (src_ip, dst_prefix, dst_ip, " + options.encoded_ttl_from +", src_port, dst_port, snapshot)\n"
        "        HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)\n"
//        "        ORDER BY (src_ip, dst_ip, ttl) ASC\n"
        "    ) \n"
        "    GROUP BY (src_ip, dst_prefix)\n"
        ")\n"
        "GROUP BY (src_ip, dst_prefix, "+ options.encoded_ttl_from +")\n"
        "HAVING n_links > 1 or (n_links=0 and n_nodes > 1) \n"
        "ORDER BY \n"
        "    dst_prefix ASC, \n"
        "    " +options.encoded_ttl_from + " ASC\n"
//        "LIMIT 200\n"
        ""};

    return subspace_request;
}



void clickhouse_t::flush_traceroute(int round, uint32_t src_ip, uint32_t dst_prefix, uint32_t dst_ip,
        uint16_t min_dst_port, uint16_t max_dst_port, uint16_t max_src_port,
        const std::vector<int> & nodes_per_ttl,
        const std::vector<int> & links_per_ttl,
        const std::vector<int> & previous_max_flow_per_ttl,
        const process_options_t & options,
        std::ostream & ostream) {



    std::vector<int> flows_per_ttl(max_ttl + 1, 0);
    std::vector<int> real_previous_max_flow_per_ttl(max_ttl + 1, 0);

    for (int ttl = 1; ttl < links_per_ttl.size(); ++ttl){
        if (links_per_ttl[ttl] == 0 && nodes_per_ttl[ttl] == 0){
            continue;
        }

        // Compute the number of flows that were sent at the previous round.
        // It is the upper bound of the of the maximum dst ip in the nks.
        auto n_to_send = 0;
        auto max_flow = 0;
        max_flow = *std::lower_bound(mda_maths::nks95.begin(), mda_maths::nks95.end(), previous_max_flow_per_ttl[ttl]);
//        max_flow = *std::lower_bound(mda_maths::nks95.begin(), mda_maths::nks95.end(), 8);
        if (round == 1) {
            if (max_flow < default_1_round_flows){
                max_flow = default_1_round_flows;
            }
        }

        if (links_per_ttl[ttl] == 0){
            n_to_send = mda_maths::nks95[nodes_per_ttl[ttl]] - max_flow;
        }
        else {
            n_to_send = mda_maths::nks95[links_per_ttl[ttl]] - max_flow;
        }

//        if (dst_ip == 8671 && (ttl == 14 || ttl == 13)){
//            std::cout << ttl << ", " << links_per_ttl[ttl] << "," << mda_maths::nks95[links_per_ttl[ttl]]<< ", " << max_flow << ", " << n_to_send << "\n";
//        }

        flows_per_ttl[ttl] = n_to_send;
        real_previous_max_flow_per_ttl[ttl] = max_flow;
    }

    bool is_done = true;

    for (auto ttl = 1; ttl < flows_per_ttl.size(); ++ttl){
        if (nodes_per_ttl[ttl] == 0){
            continue;
        }
        auto n_to_send = 0;
        auto dominant_ttl = 0;
        if (!(links_per_ttl[ttl] == 0 && links_per_ttl[ttl-1] == 0)){
            // There is at least one link
            if (ttl == max_ttl){
                auto max_it = std::max_element(flows_per_ttl.begin() + ttl - 1, flows_per_ttl.begin() + ttl);
                dominant_ttl = max_it - flows_per_ttl.begin();
                n_to_send = *max_it;

            } else {
                auto max_it = std::max_element(flows_per_ttl.begin() + ttl - 1, flows_per_ttl.begin() + ttl + 1);
                dominant_ttl = max_it - flows_per_ttl.begin();
                n_to_send = *max_it;
            }
        }
        else {
            // Otherwise only look at the nodes
            dominant_ttl = ttl;
            n_to_send = flows_per_ttl[ttl];
        }



//        if (dst_ip == 8671 && (ttl == 14 || ttl == 13)){
//            std::cout << ttl << ", " << real_previous_max_flow_per_ttl[dominant_ttl] << ", " << n_to_send << "\n";
//        }

        bool is_per_flow_needed = false;
        auto remaining_flow_to_send = 0;

        if (n_to_send > 0){
            is_done = false;
        }
        for (auto flow_id = 0; flow_id < n_to_send; ++flow_id){

            if (max_src_port > options.sport){
                is_per_flow_needed = true;
                break;
            }

            int dst_ip_in_24 = real_previous_max_flow_per_ttl[dominant_ttl] + flow_id;
            if (dst_ip_in_24 <= 255){

                // DEBUG
//#ifndef NDEBUG
//                std::cout << src_ip << ","
//                        << dst_prefix + 1 + dst_ip_in_24 << "," // +1 because the first address probed in the prefix is 1.
//                        // default sport
//                        << options.sport << ","
//                        << options.dport  << ","
//                        << ttl << "\n";
//#endif
                ostream << htonl(src_ip) << ","
                        << htonl(dst_prefix + 1 + dst_ip_in_24) << "," // +1 because the first address probed in the prefix is 1.
                        // default sport
                        << options.sport << ","
                        << options.dport  << ","
                        << ttl << "\n";
                remaining_flow_to_send = n_to_send - (flow_id + 1);
            } else {
                is_per_flow_needed = true;
                break;
            }

        }
        if (is_per_flow_needed) {
//            std::cout << "Per flow needed" << dst_ip << "\n";
            if (min_dst_port != options.dport || max_dst_port != options.dport){
                // NAT, so nothing to play with ports.
                return;
            }
            for (auto flow_id = 0; flow_id < remaining_flow_to_send; ++flow_id){

                ostream << htonl(src_ip) << ","
                        << htonl(dst_ip) << ","
                        // default sport
                        << max_src_port + flow_id + 1 << ","
                        << options.dport << ","
                        << ttl << "\n";
            }
        }
    }

//    if (is_done){
//        m_prefixes_done[dst_prefix] = true;
//    }


}


void
clickhouse_t::next_stochastic_snapshot(int snapshot_reference, const std::string &table, uint32_t vantage_point_src_ip, uint32_t vp_inf_born,
                                       uint32_t vp_sup_born,
                                       const process_options_t & options,
                                       std::ostream &ostream) {



    auto interval_split = 256; // Power of 2 because we want to keep track of all /24 prefixes

    for (auto i = 0; i < interval_split; ++i) {
        auto inf_born = static_cast<uint32_t >(vp_inf_born + i * ((vp_sup_born - vp_inf_born) / interval_split));
        auto sup_born = static_cast<uint32_t >(vp_inf_born + (i + 1) * ((vp_sup_born - vp_inf_born) / interval_split));

        std::cout << "Doing " << i << " on " << interval_split << " of IPv4 space\n";


        std::string query = "WITH groupUniqArray(reply_ip) as replies_ip \n"
                            "SELECT \n"
                            "    dst_prefix, \n"
                            "    ttl, \n"
                            "    max(dst_ip), \n"
                            "    max(dst_port),\n"
                            "    min(src_port),\n"
                            "    max(src_port),\n"
                            "    replies_ip    \n"
                            "FROM " + table + " \n"
                            "PREWHERE dst_ip > " + std::to_string(inf_born) + " AND dst_ip <= " + std::to_string(sup_born) +  "\n"
                            "AND src_ip = " + std::to_string(vantage_point_src_ip) + "\n"
                            "AND snapshot = " + std::to_string(snapshot_reference) + "\n"
                                                                                     "AND dst_ip != reply_ip "
                            "GROUP BY (src_ip, dst_prefix, ttl) "
                            "ORDER BY (src_ip, dst_prefix, ttl) ";

        uint32_t current_prefix = 0;
        uint32_t current_last_reply_ip  = 0;
        bool is_traceprefix_done = false;
        m_client.Select(query, [this, vantage_point_src_ip, &current_last_reply_ip, &current_prefix, &is_traceprefix_done, &ostream, &options](const Block &block) {
            for (size_t k = 0; k < block.GetRowCount(); ++k) {
                uint32_t dst_prefix   = block[0]->As<ColumnUInt32>()->At(k);
                uint32_t ttl          = static_cast<uint32_t>(block[1]->As<ColumnUInt8>()->At(k));
                uint32_t max_dst_ip   = block[2]->As<ColumnUInt32>()->At(k);
                uint16_t max_dst_port = block[3]->As<ColumnUInt16>()->At(k);
                uint16_t min_src_port = block[4]->As<ColumnUInt16>()->At(k);
                uint16_t max_src_port = block[5]->As<ColumnUInt16>()->At(k);
                auto col = block[6]->As<ColumnArray>()->GetAsColumn(k);
                if (m_patricia_trie_excluded.get(htonl(dst_prefix)) != nullptr){
//                if (m_patricia_trie_excluded.get(dst_prefix)){
                    continue;
                }
                if (current_prefix != dst_prefix){
                    // Reset some variables
                    current_prefix = dst_prefix;
                    current_last_reply_ip = 0;
                    is_traceprefix_done = false;
                }

                if (is_traceprefix_done){
                    continue;
                }

                if (col->Size() == 1){
                    uint32_t last_reply_ip = (*col->As<ColumnUInt32>())[0];
                    if (current_last_reply_ip == last_reply_ip){
                        // Cycle detected, end of traceroute, just skip the next ttls
                        is_traceprefix_done = true;
                    } else {
                        current_last_reply_ip = last_reply_ip;
                    }
                }
                int probes = 0;
                // Find the closest nk that was supposed to be reached
                int n_replies = (max_dst_ip - dst_prefix) + max_dst_port - options.dport;
                for(int i = 1; i < mda_maths::nks95.size(); ++i){
                    if (mda_maths::nks95[i] >= n_replies){
                        probes = mda_maths::nks95[i];
                        break;
                    }
                }

                auto remaining_probes = probes;
                for(uint32_t addr = 1; addr <= probes; ++addr){
                    if (addr <= 255){
                        remaining_probes -=1;
                        ostream << htonl(vantage_point_src_ip) << ","
                                << htonl(addr + dst_prefix) << ","
                                << options.sport << ","
                                << options.dport << ","
                                << ttl << "\n";
//                        std::cout << vantage_point_src_ip << ","
//                                << addr + dst_prefix << ","
//                                << options.sport << ","
//                                << options.dport << ","
//                                << ttl << "\n";
                    }
                    else {
                        break;
                    }
                }
                if (options.sport == min_src_port && options.sport == max_src_port){
                    // Not behind a NAT.
//                    if (remaining_probes > 0){
//                        std::cout << "Per flow needed " << dst_prefix << " " << ttl << "\n";
//                    }

                    for (uint16_t dport = 1; dport <= remaining_probes; ++dport){

                        ostream << htonl(vantage_point_src_ip) << ","
                                << htonl(max_dst_ip) << ","
                                // default sport
                                << options.sport << ","
                                << options.dport + dport << ","
                                << ttl << "\n";
                    }
                }
            }

        });
    }
}

void clickhouse_t::next_snapshot(const std::string &table, int snapshot_id, int history_versions, std::vector<std::unique_ptr<std::ofstream>> & ostreams) {

    auto ipv4_split = 512;
    auto batch_row_limit = 20000000;

    uint32_t max_redundancy = 5;


    uint64_t total_probes_skipped_redudancy = 0;

    // Compute redundancy over each /16?


    for (auto i = 0; i < ipv4_split; ++i) {
        std::unordered_map<uint32_t, uint32_t > nodes_redundancy;

        std::unordered_map<std::pair<uint32_t , uint32_t >, uint32_t, boost::hash<std::pair<uint32_t , uint32_t >>> edges_redundancy;


        //        if (i == 3) {
//            break;
//        }
        auto inf_born = static_cast<uint32_t> (i * ((std::pow(2, 32) - 1) / ipv4_split));
        auto sup_born = static_cast<uint32_t >((i + 1) * ((std::pow(2, 32) - 1) / ipv4_split));

//        std::cout << "IPv4 subspace: " << inf_born << " AND " << sup_born << "\n";

        shrink_compute_interval(inf_born, sup_born,
                                history_versions, batch_row_limit,table,
                                max_redundancy, nodes_redundancy,  edges_redundancy,
                                total_probes_skipped_redudancy,
                                ostreams);

        // First figure out the number of rows in this batch, if it's > to a certain threshold, just reduce it until the number is
        // below



        std::cout << i << "/" << ipv4_split << " of IPv4 space done\n";
        std::cout << "Probes skipped because of redudancy: " << total_probes_skipped_redudancy << "\n";
    }

}

void clickhouse_t::shrink_compute_interval(
        // Shrinking recursion arguments,
        uint32_t inf_born, uint32_t sup_born,
        // Other parameters not participating to the recursion
        int history_versions, int batch_row_limit, const std::string & table,
        // Parameters for redundancy computation
        uint32_t max_redundancy, std::unordered_map<uint32_t, uint32_t > & nodes_redundancy, std::unordered_map<std::pair<uint32_t , uint32_t >, uint32_t, boost::hash<std::pair<uint32_t , uint32_t >>> & edges_redundancy,
        // Statistics
        uint64_t & total_probes_skipped_redudancy,
        // Flushing output
        std::vector<std::unique_ptr<std::ofstream>> & ostreams
) {

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
//    std::cout << std::pow(2, sup_born_division-1) << " batch of " <<  n_rows << " rows to process\n";
    for (auto j = 0; j < std::pow(2, sup_born_division-1); ++j) {


        std::unordered_map<uint32_t, std::unordered_map<uint8_t , std::unordered_map<uint16_t , bool>>> already_flushed_probes;

        auto inf_born_div = static_cast<uint32_t >(inf_born + j * ((sup_born - inf_born) / std::pow(2, sup_born_division-1)));
        auto sup_born_div = static_cast<uint32_t >(inf_born + (j + 1) * ((sup_born - inf_born) / std::pow(2, sup_born_division-1)));



        if (sup_born_division > 1){
            shrink_compute_interval(inf_born_div, sup_born_div,
                                    history_versions, batch_row_limit,table,
                                    max_redundancy, nodes_redundancy,  edges_redundancy,
                                    total_probes_skipped_redudancy,
                                    ostreams
            );
        } else {
            std::cout << "IPv4 subspace : " << inf_born_div << " AND " << sup_born_div << "\n";
            std::string query = "WITH \n"
                                "arraySort(x -> x.2, groupUniqArray((p1.reply_ip, p2.reply_ip, snapshot))) AS flow_reply_ip_snapshots, \n"
                                "    arrayMap(x -> (x.1, x.2), flow_reply_ip_snapshots) AS reply_ips, \n"
                                "    length(reply_ips) AS n_response, \n"
                                "    arrayDistinct(reply_ips) AS dynamics, \n"
                                "    length(dynamics) AS n_dynamics, \n"
                                "    reply_ips[1] AS edge \n"
                                "SELECT DISTINCT \n"
                                "    (src_ip, dst_ip, src_port, dst_port, ttl), \n"
                                "    n_response, \n"
                                "    n_dynamics, \n"
                                "    edge\n"
                                "FROM \n"
                                "(\n"
                                "    SELECT *\n"
                                "    FROM " + table + "\n"
                                                      "    WHERE dst_ip > " + std::to_string(inf_born_div) +
                                " AND dst_ip <= " + std::to_string(sup_born_div) +
                                " AND  dst_port >= 33434 AND dst_port <= 65000 AND (ttl >= 3)\n"
                                ") AS p1 \n"
                                "LEFT JOIN \n"
                                "(\n"
                                "    SELECT *\n"
                                "    FROM " + table + "\n"
                                                      "    WHERE dst_ip > " + std::to_string(inf_born_div) +
                                " AND dst_ip <= " + std::to_string(sup_born_div) +
                                " AND  dst_port >= 33434 AND dst_port <= 65000 AND (ttl >= 3)\n"
                                ") AS p2 \n"
                                "ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip) AND (p1.src_port = p2.src_port) AND (p1.dst_port = p2.dst_port) AND (p1.round = p2.round) AND (p1.snapshot = p2.snapshot) AND (toUInt8(p1.ttl + toUInt8(1)) = p2.ttl)\n"
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
                                                          "        WHERE dst_ip > " + std::to_string(inf_born_div) +
                                " AND dst_ip <= " + std::to_string(sup_born_div) +
                                " AND  dst_port >= 33434 AND dst_port <= 65000 AND (ttl >= 3)\n"
                                "        GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, round, snapshot)\n"
                                "        HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)\n"
                                "    ) \n"
                                ")\n"
                                "GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)";

//        std::cout << query << "\n";

//        m_client.Select(query, [&total_probes_skipped_redudancy, &ostreams, max_redundancy, history_versions](const Block &block) {
            m_client.Select(query,
                            [&already_flushed_probes, &total_probes_skipped_redudancy, &nodes_redundancy, &edges_redundancy, max_redundancy, history_versions, &ostreams](
                                    const Block &block) {
                                for (size_t k = 0; k < block.GetRowCount(); ++k) {
                                    auto db_tracenode = block[0]->As<ColumnTuple>();


                                    uint32_t src_ip   = (*db_tracenode)[0]->As<ColumnUInt32>()->At(k);
                                    uint32_t dst_ip   = (*db_tracenode)[1]->As<ColumnUInt32>()->At(k);
                                    uint16_t src_port = (*db_tracenode)[2]->As<ColumnUInt16>()->At(k);
                                    uint16_t dst_port = (*db_tracenode)[3]->As<ColumnUInt16>()->At(k);
                                    uint8_t ttl = (*db_tracenode)[4]->As<ColumnUInt8>()->At(k);

                                    uint64_t n_response = block[1]->As<ColumnUInt64>()->At(k);
                                    uint64_t n_dynamics = block[2]->As<ColumnUInt64>()->At(k);

                                    auto any_edge = block[3]->As<ColumnTuple>();
                                    uint32_t edge_src = (*any_edge)[0]->As<ColumnUInt32>()->At(k);
                                    uint32_t edge_dst = (*any_edge)[1]->As<ColumnUInt32>()->At(k);

                                    if (edge_src == edge_dst) {
                                        // We have gone too far in the traceroute, no need to reprobe this edge.
                                        total_probes_skipped_redudancy += 1;
                                        continue;
                                    }

                                    bool is_skipped = false;
                                    if (n_response == history_versions && n_dynamics == 1) {
                                        if (edge_dst != 0) {
                                            auto edge = std::make_pair(edge_src, edge_dst);
                                            // This means that there is an edge discovered for this probe.
                                            if (edges_redundancy[edge] < max_redundancy) {
                                                edges_redundancy[edge] += 1;
                                            } else {
                                                total_probes_skipped_redudancy += 1;
                                                is_skipped = true;
                                            }
                                        } else {
                                            // This means there is not an edge associated with this probe, so we look at the nodes redundancy.
                                            auto node = edge_src;
                                            if (nodes_redundancy[node] < max_redundancy) {
                                                nodes_redundancy[node] += 1;
                                            } else {
                                                total_probes_skipped_redudancy += 1;
                                                is_skipped = true;
                                            }
                                        }
                                    }

                                    if (!is_skipped) {

                                        // Compute a function based on n_response and n_dynamics?
                                        // Very simple at the moment, the reprobe frequency is the number of dynamics.
                                        if (n_dynamics > history_versions) {
                                            // Set a maximum of dynamics.
                                            n_dynamics = ostreams.size() - 1;
                                        }
                                        auto & is_already_flushed_probe_edge_src = already_flushed_probes[dst_ip][ttl][dst_port];

                                        if (!is_already_flushed_probe_edge_src){
                                            *(ostreams[n_dynamics - 1]) << htonl(src_ip) << ","
                                                                        << htonl(dst_ip) << ","
                                                                        << src_port << ","
                                                                        << dst_port << ","
                                                                        << static_cast<int>(ttl) << "\n";

                                            is_already_flushed_probe_edge_src = true;

                                        }

                                        if (edge_dst != 0){
                                            auto & is_already_flushed_probe_edge_dst = already_flushed_probes[dst_ip][ttl + 1][dst_port];
                                            if (!is_already_flushed_probe_edge_dst){
                                                *(ostreams[n_dynamics - 1]) << htonl(src_ip) << ","
                                                                            << htonl(dst_ip) << ","
                                                                            << src_port << ","
                                                                            << dst_port << ","
                                                                            << static_cast<int>(ttl + 1) << "\n";
                                                is_already_flushed_probe_edge_dst = true;
                                            }
                                        }

                                    }
                                }

                            });
        }
        }




}

bool clickhouse_t::can_skip_ipv4_block(uint32_t inf_born, uint32_t sup_born) {

    uint32_t i = closest_prefix(inf_born, 24);
    bool can_skip = true;
    for (auto prefix = i; prefix <= sup_born; prefix += 256){
        auto is_prefix_done = m_prefixes_done.find(prefix);
        if (is_prefix_done == m_prefixes_done.end()){
            can_skip = false;
            break;
        }
    }
    return can_skip;
}






















