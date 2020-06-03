//
// Created by System Administrator on 2019-01-29.
//

#ifndef HEARTBEAT_READER_T_HPP
#define HEARTBEAT_READER_T_HPP

#include <string>
#include <vector>
#include <probe_dto_t.hpp>
#include <tins/tins.h>
//#include <database_t.hpp>
#include <iostream>
#include <fstream>
#include <process_options_t.hpp>

struct output_file_t{
public:
    explicit output_file_t (const std::string & ofile, int round, int snapshot) : m_ofstream(), m_round(round), m_snapshot(snapshot){
        m_ofstream.open(ofile);

    }
    ~output_file_t(){
        m_ofstream.close();
    }
    void operator ()(const std::vector<probe_dto_t> & probes_dto) {

        for (const auto & probe_dto : probes_dto){

            m_ofstream.precision(1);
            // Compute the /24 prefix
            uint32_t prefix = (probe_dto.m_indirect_ip >> 8) << 8; // Get the 24 bits of the network.
            m_ofstream << std::fixed << probe_dto.m_source_ip << "," << prefix << "," << probe_dto.m_indirect_ip << "," <<
                       probe_dto.m_reply_ip <<","
                       << unsigned(probe_dto.m_proto) << ","
                       << probe_dto.m_sport <<"," << probe_dto.m_dport << "," <<
                       unsigned(probe_dto.m_ttl) << "," << unsigned(probe_dto.m_type) << "," << unsigned(probe_dto.m_code) <<
                       "," << probe_dto.m_rtt <<
                       "," << unsigned(probe_dto.m_reply_ttl) <<
                       "," << probe_dto.m_reply_size <<
                       // This was for versioned probe engine of Clickhouse.
//                       "," << m_round << ",1," << m_snapshot << "\n";
                       "," << m_round << "," << m_snapshot << "\n";
        }
    }
private:
    std::ofstream m_ofstream;
    int m_round;
    int m_snapshot;

};

class reader_t {
public:

    explicit reader_t(const process_options_t & options);


    template<typename OutputF>
    void output(const std::string & pcap_file, int batch_size, OutputF & output_f){
        using namespace Tins;
        std::vector<probe_dto_t> batch;
        batch.reserve(batch_size);

        long n_packets = 0;

        FileSniffer sniffer {pcap_file};


//    long total_packets = std::distance(sniffer.begin(), sniffer.end());
//    std::cout << total_packets << " packets to read.\n";

        auto handler = [this, &n_packets, &batch, &output_f, batch_size](Packet & packet) {
            ++n_packets;
            if (n_packets % 1000000 == 0){
                std::cout << n_packets << " packets read\n";
            }
//            if (n_packets < 600000000){
//                return true;
//            }
            auto probe_dto = read_packet(packet);

            // Check integrity of the probe
            if (probe_dto.m_dport != 0){
                batch.push_back(probe_dto);
            }
            if (batch.size() == batch_size){
                // Proceed to transaction.
                output_f(batch);
                batch.clear();
            }



            return true;
        };

        sniffer.sniff_loop(handler);
        output_f(batch);
        std::cout << n_packets << "Packets read\n";
    }

    void set_reference_time(const std::string & start_time_log_file);

private:
    probe_dto_t read_packet(const Tins::Packet &) const;
    double compute_rtt_from_tcp(uint32_t seq_number, double receive_time) const;
    double compute_rtt_from_udp(uint16_t checksum, double receive_time) const;
//    void insert_batch (const std::vector<probe_dto_t> &);
    process_options_t m_options;
//    database_t* m_db;
    std::vector<double> reference_times;

};


#endif //HEARTBEAT_READER_T_HPP
