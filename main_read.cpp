//
// Created by System Administrator on 2019-01-29.
//

#include <reader_t.hpp>

/* writev.c
002 2:    *
003 3:    * Short writev(2) demo:
004 4:    */
#include <tins/tins.h>

#include <classic_sender_t.hpp>
#include <sys/socket.h>
#include <iostream>
#include <arpa/inet.h>

#include <database/clickhouse_t.hpp>
#include <boost/program_options.hpp>

#include <analyze_t.hpp>
#include <process_options_t.hpp>

#include <utils/network_utils_t.hpp>
#include <utils/parameters_utils_t.hpp>

using namespace Tins;

using namespace utils;

int main(int argc, char ** argv){

    namespace po = boost::program_options;

    std::string help_message;

    process_options_t options;

    std::string output_file;
    // Declare the supported options.
    po::options_description desc("Options");
    desc.add_options()
            ("help,h", help_message.c_str())
            ("read,r", "Read a pcap file and generate the csv from the replies")
            ("generate,g", "Generate the next round of probing")
            ("generate-snapshot,G", "Generate the next snapshot based on a snapshot reference")
            ("input-file,i", po::value<std::string>(), "Pcap input file (only for read mode)")
            ("output-file,o", po::value<std::string>(), "CSV output file")
            ("exclusion-file,E", po::value<std::string>(), "File with prefix to exclude (same format as prefix-file")
            ("vantage-point,v", po::value<uint32_t >(), "IP address in little endian of the vantage point")
            ("round,R", po::value<uint32_t >(), "Index of the round")
            ("snapshot,s", po::value<uint32_t >(), "ID number of the snapshot")
            ("db-host", po::value<std::string>(), "IP address of the DB (default localhost)")
            ("db-table,t", po::value<std::string>(), "Table of the DB to be used for querying and inserting")
            ("dport", po::value<uint16_t>(), "dport used for sending the probes")
            ("inf-born,I", po::value<uint32_t>(), "inf born of the dst_ip")
            ("sup-born,S", po::value<uint32_t>(), "sup born of the dst_ip")
            ("skip-prefixes", po::value<std::string>(), "File that contains /24 prefixes that can be skipped because statistical guarantees have been reached")
            ("compute-rtt", "Compute the RTTs of the probes, needs the start-time-log-file")
            ("start-time-log-file", po::value<std::string>(), "File containing the start time of the D-Miner probes. Necessary to compute the RTTs.")
            ("snapshot-reference", po::value<int>(), "Number of the snapshot that should be taken in reference for a new stochastic snapshot.")
            ("encoded-ttl-from", po::value<std::string>(), "Retrieve the TTL from encoded fields, possible values are ip-id, udp-length");



    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);


    uint32_t vantage_point_src_ip = 0;

    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 1;
    }

    if (vm.count("output-file")){
        options.output_file= vm["output-file"].as<std::string>();
    } else {
        std::cerr << "Missing an output file. Exiting...\n";
        exit(1);
    }

    if (vm.count("exclusion-file")){
        options.exclusion_file = vm["exclusion-file"].as<std::string>();
    } else{
        std::cerr << "No exclusion file given. Taking resources/excluded_prefixes by default \n";
        options.exclusion_file = "resources/excluded_prefixes";
    }

    if (!vm.count("read") and !vm.count("generate") and !vm.count("generate-snapshot")) {
        std::cerr << "Please select a mode for analysis.\n";
        exit(1);
    }
    if (vm.count("read")) {

        options.is_read = true;
        if (vm.count("input-file")){
            options.input_file= vm["input-file"].as<std::string>();
        } else {
            std::cerr << "Please provide a pcap file to analyse.\n";
            exit(1);
        }

    } else if (vm.count("generate")) {
        options.is_generate = true;
    } else if (vm.count("generate-snapshot")){
        options.is_generate_snapshot = true;
    }

    if(vm.count("vantage-point")){
        vantage_point_src_ip = vm["vantage-point"].as<uint32_t >();
    }

    if(vm.count("round")){
        options.round = vm["round"].as<uint32_t >();
    } else {
        std::cerr << "Please provide a number of round.\n";
        exit(1);
    }
    if(vm.count("snapshot")){
        options.snapshot = vm["snapshot"].as<uint32_t >();
    } else {
        if (vm.count("read")){
            std::cerr << "Please provide a number of snapshot.\n";
            exit(1);
        }
    }

    if(vm.count("db-host")){
        options.db_host = vm["db-host"].as<std::string>();
    } else {
        if (vm.count("generate")) {
            std::cerr << "Please provide a database host.\n";
            exit(1);
        }
    }

    if(vm.count("db-table")){
        options.db_table = vm["db-table"].as<std::string>();
    } else {
        if (vm.count("generate")) {
            std::cerr << "Please provide a table name.\n";
            exit(1);
        }
    }

    if(vm.count("dport")){
        options.dport = vm["dport"].as<uint16_t>();
    }

    if(vm.count("inf-born")){
        options.inf_born = vm["inf-born"].as<uint32_t>();
    } 
    
    if(vm.count("sup-born")){
        options.sup_born = vm["sup-born"].as<uint32_t>();
    } 


    if(vm.count("skip-prefixes")){
        options.skip_prefixes_file = vm["skip-prefixes"].as<std::string>();
    }

    if(vm.count("snapshot-reference")){
        options.snapshot_reference = vm["snapshot-reference"].as<int>();
    }

    if (vm.count("compute-rtt")){
        options.is_compute_rtt = true;
        if (vm.count("start-time-log-file")){
            options.start_time_file = vm["start-time-log-file"].as<std::string>();
        } else {
            std::cerr << "Please provide start-time-log-file to compute RTTs.\n";
            exit(1);
        }

    } else {
        options.is_compute_rtt = false;
    }


    if (vm.count("encoded-ttl-from")){
        std::vector<std::string> valid_values;
        valid_values.emplace_back("ip-id");
        valid_values.emplace_back("udp-length");
        options.encoded_ttl_from = vm["encoded-ttl-from"].as<std::string>();
        if (std::find(valid_values.begin(), valid_values.end(), options.encoded_ttl_from) == valid_values.end()){
            std::cerr << "Please provide a valid value for "
                         "encoded-ttl-from, valid values are ip-id, udp-length" << std::endl;
        } else if (options.encoded_ttl_from == "ip-id"){
            options.encoded_ttl_from = "ttl";
        } else if (options.encoded_ttl_from == "udp-length"){
            options.encoded_ttl_from = "ttl_from_udp_length";
        }
    } else {
        // Default value
        options.encoded_ttl_from = "ttl";
    }

    if (options.is_read){
        reader_t reader {options};
        if (options.is_compute_rtt){
            reader.set_reference_time(options.start_time_file);
        }
        output_file_t of(options.output_file, options.round, options.snapshot);
        reader.output(options.input_file, 10000, of);

    }

    else if (options.is_generate){

        clickhouse_t clickhouse(options);
        if (!options.skip_prefixes_file.empty()){
            clickhouse.set_skip_prefixes(options.skip_prefixes_file);
        }

        std::ofstream ofstream;
        ofstream.open(options.output_file);

//        std::ostream & cout = std::cout;

//        clickhouse.next_round_csv(db_table, vantage_point_src_ip, options.snapshot, options.round, options.inf_born, options.sup_born,
//                                           ofstream);


        if (options.round == 1){
            clickhouse.next_max_ttl_traceroutes(options.db_table, vantage_point_src_ip, options, ofstream);
        }


        clickhouse.next_round_csv(options.db_table, vantage_point_src_ip, options,
                                  ofstream);
        ofstream.close();

        if (!options.skip_prefixes_file.empty()){
            clickhouse.write_skip_prefixes(options.skip_prefixes_file);
        }

    } else if (options.is_generate_snapshot){
//        clickhouse_t clickhouse(options);
//        std::ofstream ofstream;
//        ofstream.open(options.output_file);
//        clickhouse.next_stochastic_snapshot(options.snapshot_reference, options.db_table, vantage_point_src_ip,
//                options.inf_born, options.sup_born, options,
//                ofstream);

    }



//    analyze_t analyzer;
//    analyzer.next_round(argv[1], "resources/next_round.csv");
//
//    analyzer.count_unique(argv[1]);

}