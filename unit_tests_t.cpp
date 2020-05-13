//
// Created by System Administrator on 2020-03-04.
//
#include <iostream>

#include <patricia.hpp>
#include <database/clickhouse_t.hpp>

#include <clickhouse/client.h>
#include <tins/tins.h>

using namespace clickhouse;
using namespace Tins;
void test_write_file(){
    std::string host = "132.227.123.200";
    std::string table = "heartbeat.replies_ministry_ple42_planet_lab_eu_1582833808";
    process_options_t process_options;
    int round = 1;
    int snapshot = 1;
    process_options.round = round;
    process_options.snapshot = snapshot;
    auto inf_born = process_options.inf_born;
    auto sup_born = process_options.sup_born;
    auto vantage_point_src_ip = 2229500714;

//    std::ofstream ofstream {"test_request"};


    clickhouse_t clickhouse {host};


    clickhouse.next_max_ttl_traceroutes(table, vantage_point_src_ip,process_options,std::cout);
}


void test_request(){


    std::string host = "132.227.123.200";
    std::string table = "heartbeat.replies_ministry_ple42_planet_lab_eu_1582833808";
    process_options_t process_options;
    int round = 1;
    int snapshot = 1;
    auto inf_born = process_options.inf_born;
    auto sup_born = process_options.sup_born;
    auto vantage_point_src_ip = 2229500714;

//    std::ofstream ofstream {"test_request"};


    clickhouse_t clickhouse {host};
//    std::cout << "Connected to the database" << std::endl;
//
//    clickhouse.next_max_ttl_traceroutes(table, 0, process_options, ofstream);

    std::string complete_traces = {
            "SELECT \n"
            "    src_ip, \n"
            "    dst_ip, \n"
            "    max(ttl) as max_ttl \n"
            "FROM \n"
            "(\n"
            "    SELECT *\n"
            "    FROM " + table + "\n"
            "    WHERE dst_ip > " + std::to_string(inf_born) + " AND dst_ip <= " + std::to_string(sup_born) + " AND round <= " + std::to_string(round) + "\n"
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
            "            ttl, \n"
            "            COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow, \n"
            "            COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt \n"
            "        FROM " + table + "\n"
            "        WHERE dst_ip > " + std::to_string(inf_born) + " AND dst_ip <= " + std::to_string(sup_born) + "\n"
            "        AND src_ip = " + std::to_string(vantage_point_src_ip) + " \n"
            "        AND snapshot = " + std::to_string(snapshot) + " \n"
            "        GROUP BY (src_ip, dst_prefix, dst_ip, ttl, src_port, dst_port, snapshot)\n"
            "        HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)\n"
            //                                  "        ORDER BY (src_ip, dst_ip, ttl) ASC\n"
            "    ) \n"
            "    GROUP BY (src_ip, dst_prefix)\n"
            "   )"
//            ")"
            " AND dst_ip != reply_ip \n"
            " GROUP BY (src_ip, dst_ip) \n"
            };

    std::cout << complete_traces << std::endl;

    clickhouse::Client client{ClientOptions().SetHost(host)};


    client.Select(complete_traces, [](const Block &block) {
        for (size_t k = 0; k < block.GetRowCount(); ++k) {
            uint32_t src_ip = block[0]->As<ColumnUInt32>()->At(k);
            uint32_t dst_ip = block[1]->As<ColumnUInt32>()->At(k);
            uint8_t  max_ttl = block[2]->As<ColumnUInt8>()->At(k);
//            uint16_t min_dst_port = block[6]->As<ColumnUInt16>()->At(k);
//            uint16_t max_dst_port = block[7]->As<ColumnUInt16>()->At(k);
//            uint32_t max_round = block[8]->As<ColumnUInt32>()->At(k);

        }
    });




}


void test_patricia_trie(){
    Patricia patricia_excluded(32);
    patricia_excluded.populateBlock(AF_INET, "resources/excluded_prefixes");
    auto node = patricia_excluded.get(AF_INET, "8.8.8.8", false);
    assert(node == nullptr);
    node =  patricia_excluded.get(AF_INET, "127.0.0.0", false);
    assert(node != nullptr);
    Patricia patricia(32);
    patricia.populate(AF_INET, "resources/test/test_prefixes", true);
    node = patricia.get(AF_INET, "192.168.1.0", false);
    assert(node != nullptr);
    node = patricia.get(AF_INET, "8.8.8.8", false);
    assert(node != nullptr);
    node = patricia.get(uint32_t(IPv4Address("192.168.1.0")), false);
    assert(node != nullptr);
    node = patricia.get(ntohl(uint32_t(IPv4Address("192.168.1.0"))), false);
    assert(node != nullptr);

}

int main(){
//    test_request(); // Just ensure no exception
//    test_write_file();
    test_patricia_trie();


}

