//
// Created by System Administrator on 2019-05-22.
//

#ifndef HEARTBEAT_CLICKHOUSE_T_HPP
#define HEARTBEAT_CLICKHOUSE_T_HPP

#include <tracelink_t.hpp>
#include <tracenode_t.hpp>

#include <clickhouse/client.h>

#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <boost/functional/hash.hpp>

#include <dynamics_t.hpp>

#include <process_options_t.hpp>

class clickhouse_t {
public:
    clickhouse_t(const std::string & host);
    void set_skip_prefixes(const std::string &skip_prefixes_file);
    void write_skip_prefixes(const std::string &skip_prefixes_file);

    using edges_t = std::unordered_set<std::pair<uint32_t , uint32_t >, boost::hash<std::pair<uint32_t , uint32_t >>>;

    /**
     * Compute the next round, traceroutes by traceroute
     * @param round
     */

//    void next_round_csv(const std::string & table, uint32_t vantage_point_src_ip, int snapshot, int round, uint32_t vp_inf_born, uint32_t vp_sup_born,
//                                 std::ostream &ostream);

    void next_round_csv(const std::string & table, uint32_t vantage_point_src_ip, const process_options_t & options,
                        std::ostream &ostream);


    void next_stochastic_snapshot(int snpashot_reference, const std::string & table,
            uint32_t vantage_point_src_ip, uint32_t vp_inf_born, uint32_t vp_sup_born,
                                  const process_options_t & options,
                                  std::ostream &ostream);



    void next_snapshot(const std::string & table, int snapshot_id, int history_versions, std::vector<std::unique_ptr<std::ofstream>> &);

    virtual ~clickhouse_t() = default;

private:

    /**
     * Next round requests
     */
    std::string build_subspace_request_per_prefix(const std::string & table, uint32_t vantage_point_src_ip, int snapshot, int round, uint32_t inf_born,
                                                uint32_t sup_born);

    bool can_skip_ipv4_block(uint32_t inf_born, uint32_t  sup_born);


    /**
     * Flush a traceroute to an ostream
     * @param src_ip
     * @param dst_ip
     * @param map
     */

    void flush_traceroute(int round, uint32_t src_ip, uint32_t dst_prefix, uint32_t dst_ip,
                                         uint16_t min_dst_port, uint16_t max_dst_port, uint16_t max_src_port,
                                         const std::vector<int> & links_per_ttl, const std::vector<int> & previous_max_flow_per_ttl,
                                         const process_options_t & options,
                                         std::ostream & ostream);


    void shrink_compute_interval(
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
    );


protected:
    clickhouse::Client m_client;

    std::unordered_map<uint32_t, bool> m_prefixes_done;
};


#endif //HEARTBEAT_CLICKHOUSE_T_HPP
