//
// Created by System Administrator on 2019-02-10.
//

#ifndef HEARTBEAT_ANALYZE_T_HPP
#define HEARTBEAT_ANALYZE_T_HPP
#include <string>
#include "traceroute_graph_t.hpp"
#include "probe_dto_t.hpp"

class analyze_t {
public:
    void next_round(const std::string & input_sorted_csv, const std::string & output_shuffle_probes);
    void count_unique(const std::string & );

private:

    void flush_traceroute(uint32_t src_ip, uint32_t dst_ip, uint16_t sport, uint8_t max_ttl,
                          const std::vector<std::shared_ptr<traceroute_graph_t::node_t>> & nodes,
                          const std::unordered_map<uint8_t, std::vector<uint16_t> > & flows_per_ttl,
                          std::unordered_set<std::pair<uint32_t , uint32_t >, utils::pair_hash> & unique_diamonds,
                          std::vector<probe_dto_t> & next_round_probes
    ) const ;

    void clear_data_structure(std::vector<std::shared_ptr<traceroute_graph_t::node_t>> & nodes,
                              std::unordered_map<std::pair<uint32_t , uint8_t>, std::shared_ptr<traceroute_graph_t::node_t>,utils::pair_hash> & nodes_by_ip_flow_ids,
                              std::unordered_map<std::pair<uint16_t , uint8_t>, std::shared_ptr<traceroute_graph_t::node_t>,utils::pair_hash> & nodes_by_ttl_flow_ids,
                              std::unordered_map<uint8_t, std::vector<uint16_t>> & flows_per_tt);

    void update_traceroute_node(uint32_t dst_ip, uint32_t reply_ip, uint8_t ttl, uint16_t dport,
            std::vector<std::shared_ptr<traceroute_graph_t::node_t>> & nodes,
            std::unordered_map<uint8_t, std::vector<uint16_t>> & flows_per_ttl,
            std::unordered_map<std::pair<uint32_t , uint8_t>, std::shared_ptr<traceroute_graph_t::node_t>,utils::pair_hash> & nodes_by_ip_flow_ids,
            std::unordered_map<std::pair<uint16_t , uint8_t>, std::shared_ptr<traceroute_graph_t::node_t>,utils::pair_hash> & nodes_by_ttl_flow_ids,
            std::vector<uint32_t> & all_nodes,
            std::vector<std::pair<uint32_t, uint32_t >> & all_links,
            std::unordered_map<uint16_t , std::vector<uint32_t >> & nodes_by_flow_id,
            std::unordered_map <uint16_t , std::vector<std::pair<uint32_t , uint32_t>>> & links_by_flow_id) const;

};


#endif //HEARTBEAT_ANALYZE_T_HPP
