//
// Created by System Administrator on 2020-03-04.
//
#include <iostream>


#include <database/clickhouse_t.hpp>

void test_request(){


//    std::string host = "132.227.123.200";
    std::string table = "replies_ministry_ple42_planet_lab_eu_1582833808";
    process_options_t process_options;
    int round = 1;
    int snapshot = 1;
    auto inf_born = process_options.inf_born;
    auto sup_born = process_options.sup_born;
    auto vantage_point_src_ip = 2229500714;

//    std::ofstream ofstream {"test_request"};
//    clickhouse_t clickhouse {"132.227.123.200"};
//
//    clickhouse.next_max_ttl_traceroutes(table, 0, process_options, ofstream);

    std::string subspace_request {

            " (SELECT dst_prefix\n"
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
            "    )) as terminated_prefixes, \n"
            " (SELECT dst_prefix\n"
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
            "    GROUP BY (src_ip, dst_prefix)\n) AS boguous_prefixes\n"
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
//            " dst_prefix NOT IN (\n"
//            " (SELECT dst_prefix from boguous_prefixes) \n"
//            ") \n"
//            " dst_prefix NOT IN terminated_prefixes\n"
            " dst_ip == reply_ip \n"
            " GROUP BY (src_ip, dst_ip) \n"
//            "UNION ALL \n"
//                                                               "WITH \n"
//                                                               " (SELECT dst_prefix\n"
//                                                               "    FROM \n"
//                                                               "    (\n"
//                                                               "        SELECT \n"
//                                                               "            src_ip, \n"
//                                                               "            dst_prefix, \n"
//                                                               "            MAX(round) AS max_round\n"
//                                                               "        FROM " + table + "\n"
//                                                                                         "        WHERE dst_prefix > " + std::to_string(inf_born) + " AND dst_prefix <= " + std::to_string(sup_born) + "\n"
//                                                                                                                                                                                                       "        AND src_ip = " + std::to_string(vantage_point_src_ip) + " \n"
//                                                                                                                                                                                                                                                                        "        AND snapshot = " + std::to_string(snapshot) + " \n"
//                                                                                                                                                                                                                                                                                                                               "        GROUP BY (src_ip, dst_prefix)\n"
//                                                                                                                                                                                                                                                                                                                               "        HAVING max_round < " + std::to_string(round - 1) + "\n"
//                                                                                                                                                                                                                                                                                                                                                                                           "    )) as terminated_prefixes, \n"
//                                                                                                                                                                                                                                                                                                                                                                                           " (SELECT dst_prefix\n"
//                                                                                                                                                                                                                                                                                                                                                                                           "    FROM \n"
//                                                                                                                                                                                                                                                                                                                                                                                           "    (\n"
//                                                                                                                                                                                                                                                                                                                                                                                           "        SELECT \n"
//                                                                                                                                                                                                                                                                                                                                                                                           "            src_ip, \n"
//                                                                                                                                                                                                                                                                                                                                                                                           "            dst_prefix, \n"
//                                                                                                                                                                                                                                                                                                                                                                                           "            ttl, \n"
//                                                                                                                                                                                                                                                                                                                                                                                           "            COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow, \n"
//                                                                                                                                                                                                                                                                                                                                                                                           "            COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt \n"
//                                                                                                                                                                                                                                                                                                                                                                                           "        FROM " + table + "\n"
//                                                                                                                                                                                                                                                                                                                                                                                                                     "        WHERE dst_ip > " + std::to_string(inf_born) + " AND dst_ip <= " + std::to_string(sup_born) + "\n"
//                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           "        AND src_ip = " + std::to_string(vantage_point_src_ip) + " \n"
//                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            "        AND snapshot = " + std::to_string(snapshot) + " \n"
//                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   "        GROUP BY (src_ip, dst_prefix, dst_ip, ttl, src_port, dst_port, snapshot)\n"
//                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   "        HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)\n"
//                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   //                                  "        ORDER BY (src_ip, dst_ip, ttl) ASC\n"
//                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   "    ) \n"
//                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   "    GROUP BY (src_ip, dst_prefix)\n) AS boguous_prefixes \n"
//            "SELECT \n"
//            "    src_ip, \n"
//            "    dst_ip, \n"
//            "    max(ttl) as max_ttl \n"
//            "FROM \n"
//            "(\n"
//            "    SELECT *\n"
//            "    FROM " + table + "\n"
//            "    WHERE dst_ip > " + std::to_string(inf_born) + " AND dst_ip <= " + std::to_string(sup_born) + " AND round <= " + std::to_string(round) + "\n"
//            "    AND src_ip = " + std::to_string(vantage_point_src_ip) + " \n"
//            "    AND snapshot = " + std::to_string(snapshot) + " \n"
//            ") \n"
//            "WHERE dst_prefix NOT IN (\n"
//            " boguous_prefixes \n"
//            ") AND dst_prefix NOT IN terminated_prefixes\n"
//            " AND dst_ip != reply_ip \n"
//            " GROUP BY (src_ip, dst_ip) \n"
            //                                  "LIMIT 200\n"
    };

    std::cout << subspace_request << std::endl;
}

int main(){
    test_request();

}

