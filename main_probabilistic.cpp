//
// Created by System Administrator on 2019-07-29.
//




#include <tins/tins.h>
#include <unordered_map>
#include <unordered_set>
#include <boost/functional/hash.hpp>


#include <maths/stopping_points_t.hpp>
#include <node_t.hpp>


using namespace Tins;

int main(int argc, char ** argv){

    uint8_t max_ttl = 8;

    // Edges
    using edges_t = std::unordered_set<std::pair<uint32_t , uint32_t >, boost::hash<std::pair<uint32_t , uint32_t >>>;

    // In memory structure for the MDA. Tree structure with probabilities of each node to get reached.
    using probability_tree_t = std::vector<std::unordered_map<uint32_t, node_t>>;
    probability_tree_t probability_tree(max_ttl);

    PacketSender sender{NetworkInterface::default_interface()};

    for (uint8_t ttl = 2; ttl < max_ttl; ++ttl){
        // BFS into the tree.
        bool is_ttl_done = false;
        while(!is_ttl_done){
            // Dispatch the probes into different prefixes according to the distribution
            std::vector<IP> probes;

            for (const auto & reply_ip_routing_table : probability_tree[ttl]){

                // Each prefix of the routing table is considered as a possible source of multiple paths.
                // As far as new paths are found within a prefix, we split the prefix in smaller prefixes.
                // The stopping condition occurs when a prefix reach some statistical guarantees?
                const auto & routing_table_distribution = reply_ip_routing_table.second.routing_table_distribution;
                for (const auto & prefix_tracenodes : routing_table_distribution){
                    // Extract number of successors
                    const auto & tracenodes = prefix_tracenodes.second;
                    std::unordered_set<uint32_t> successors;
                    std::transform(tracenodes.begin(), tracenodes.end(), std::inserter(successors, successors.begin()), [](const auto & tracenode){
                        return tracenode.reply_ip;
                    });

                    auto n_successors = successors.size();
                    if (tracenodes.size() < mda_maths::nks95[])


                }


            }

            // Update the graph routing table after receiving the answers.


        }



    }

}