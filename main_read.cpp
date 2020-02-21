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
    std::string db_host {"localhost"};
    std::string db_table{"heartbeat.probes"};
    // Declare the supported options.
    po::options_description desc("Options");
    desc.add_options()
            ("help,h", help_message.c_str())
            ("read,r", "Read a pcap file and generate the csv from the replies")
            ("generate,g", "Generate the next round of probing")
            ("generate-snapshot,G", "Generate the next snapshot based on a snapshot reference")
            ("input-file,i", po::value<std::string>(), "Pcap input file (only for read mode)")
            ("output-file,o", po::value<std::string>(), "CSV output file")
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
            ("snapshot-reference", po::value<int>(), "Number of the snapshot that should be taken in reference for a new stochastic snapshot.");




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
        db_host = vm["db-host"].as<std::string>();
    }

    if(vm.count("db-table")){
        db_table = vm["db-table"].as<std::string>();
    }

    if(vm.count("dport")){
        options.dport = vm["dport"].as<uint16_t>();
    }

    if(vm.count("inf-born")){
        options.inf_born = vm["inf-born"].as<uint32_t>();
    } else {
        options.inf_born = std::numeric_limits<uint32_t>::min();
    }
    if(vm.count("sup-born")){
        options.sup_born = vm["sup-born"].as<uint32_t>();
    } else {
        options.sup_born = std::numeric_limits<uint32_t>::max();
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

    if (options.is_read){
        reader_t reader {options};
        if (options.is_compute_rtt){
            reader.set_reference_time(options.start_time_file);
        }
        output_file_t of(options.output_file, options.round, options.snapshot);
        reader.output(options.input_file, 10000, of);

    }

    else if (options.is_generate){

        clickhouse_t clickhouse(db_host);
        if (!options.skip_prefixes_file.empty()){
            clickhouse.set_skip_prefixes(options.skip_prefixes_file);
        }

        std::ofstream ofstream;
        ofstream.open(options.output_file);

//        std::ostream & cout = std::cout;

//        clickhouse.next_round_csv(db_table, vantage_point_src_ip, options.snapshot, options.round, options.inf_born, options.sup_born,
//                                           ofstream);

        clickhouse.next_round_csv(db_table, vantage_point_src_ip, options,
                                  ofstream);
        ofstream.close();

        if (!options.skip_prefixes_file.empty()){
            clickhouse.write_skip_prefixes(options.skip_prefixes_file);
        }

    } else if (options.is_generate_snapshot){
        clickhouse_t clickhouse(db_host);
        std::ofstream ofstream;
        ofstream.open(options.output_file);
        clickhouse.next_stochastic_snapshot(options.snapshot_reference, db_table, vantage_point_src_ip,
                options.inf_born, options.sup_born, options,
                ofstream);

    }



//    analyze_t analyzer;
//    analyzer.next_round(argv[1], "resources/next_round.csv");
//
//    analyzer.count_unique(argv[1]);

}