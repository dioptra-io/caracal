//
// Created by System Administrator on 2019-08-02.
//

#include "clickhouse_diamonds_t.hpp"


//
// Created by System Administrator on 2019-07-23.
//

#include <iostream>

#include <boost/graph/adjacency_list.hpp>


using namespace clickhouse;

clickhouse_diamonds_t::clickhouse_diamonds_t(const std::string& host) : clickhouse_t(host){

}

clickhouse_diamonds_t::diamonds_t clickhouse_diamonds_t::diamonds(const std::string &table, int round){

    auto ipv4_split = 64;
    uint64_t batch_row_limit = 100000000;
    diamonds_t diamonds;
    diamond_t  current_diamond;
    uint32_t current_prefix = 0;
    for (auto i = 0; i < ipv4_split; ++i) {

//        if (i == 1){
//            break;
//        }

        auto inf_born = static_cast<uint32_t> (i * ((std::pow(2, 32) - 1) / ipv4_split));
        auto sup_born = static_cast<uint32_t >((i + 1) * ((std::pow(2, 32) - 1) / ipv4_split));
        diamonds_recurse(table, round,
                      inf_born, sup_born,
                      batch_row_limit, diamonds, current_diamond, current_prefix
        );
        std::cout << i << " of " << ipv4_split << " IPv4 space done\n";
    }
    return diamonds;
}

void clickhouse_diamonds_t::diamonds_recurse(const std::string & table,  int round,
        // Shrinking recursion arguments,
                                       uint32_t inf_born, uint32_t sup_born,
                                       uint64_t batch_row_limit,
                                       diamonds_t & diamonds,
                                       diamond_t  & current_diamond,
                                       uint32_t   & current_prefix){

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
            diamonds_recurse(table, round,
                          inf_born_div, sup_born_div,
                          batch_row_limit,
                          diamonds, current_diamond, current_prefix
            );
        } else {
            std::cout << "IPv4 subspace : " << inf_born_div << " AND " << sup_born_div << "\n";
            std::string diamonds_query = "WITH groupUniqArray((reply_ip, ttl, dst_ip, dst_port)) as replies,\n"
                                         "arraySort(x->x.2, replies) as sorted_replies,\n"
                                         "arrayMap(x->x.1, sorted_replies) as ips,\n"
                                         "arrayMap(x->x.2, sorted_replies) as ttls,\n"
                                         "arrayMap(x->x.3, sorted_replies) as dst_ips,\n"
                                         "arrayMap(x->x.4, sorted_replies) as dst_ports\n"
                                         "SELECT dst_prefix, "
                                         "ips,\n"
                                         "ttls,\n"
                                         "dst_ips,\n"
                                         "dst_ports "
                                         "FROM " + table + "\n"
                                         "WHERE dst_ip > " + std::to_string(inf_born_div) + " AND dst_ip <= " + std::to_string(sup_born_div) +
                                         " AND (dst_ip NOT IN \n"
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
                                         "        FROM versioned_probes\n"
                                         "        WHERE dst_ip > " + std::to_string(inf_born_div) + " AND dst_ip <= " + std::to_string(sup_born_div) +
                                         "        GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, round, snapshot)\n"
                                         "        HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)\n"
                                         "    )\n"
                                         "))\n"
                                         "ORDER BY (src_ip, dst_prefix, ttl) ASC";



            m_client.Select(diamonds_query, [&diamonds, &current_diamond, &current_prefix](const Block &block) {
//                std::cout << block.GetRowCount() << " rows in this block\n";
                for (size_t k = 0; k < block.GetRowCount(); ++k) {
                    auto dst_prefix = block[0]->As<ColumnUInt32>()->At(k);


                    auto reply_ips  = block[1]->As<ColumnArray>()->GetAsColumn(k);
                    auto ttls       = block[2]->As<ColumnArray>()->GetAsColumn(k);
                    auto dst_ips    = block[3]->As<ColumnArray>()->GetAsColumn(k);
                    auto dst_ports  = block[4]->As<ColumnArray>()->GetAsColumn(k);

                    if (dst_prefix != current_prefix){
                        // Insert the current diamond to the diamond set.
                        diamonds.insert(current_diamond);
                        current_diamond = diamond_t();
                        current_prefix  = dst_prefix;
                    }

                    for (size_t i = 0; i < reply_ips->Size(); ++i) {
                        uint32_t reply_ip = (*reply_ips->As<ColumnUInt32>())[i];
                        uint8_t  ttl      = (*ttls->As<ColumnUInt8>())[i];
                        uint32_t dst_ip   = (*dst_ips->As<ColumnUInt32>())[i];
                        uint16_t dst_port = (*dst_ports->As<ColumnUInt32>())[i];
                    }


                }
            });
            std::cout << diamonds.size() << " unique diamonds\n";
        }
    }

}


