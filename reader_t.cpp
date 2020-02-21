//
// Created by System Administrator on 2019-01-29.
//

#include <tins/tins.h>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <netinet/in.h>
#include <netinet/udp.h> // udphdr
#include <netinet/tcp.h> //tcphdr
#include <utils/network_utils_t.hpp>
#include <utils/bits_utils_t.hpp>

#include <sstream>

#include "reader_t.hpp"

using namespace Tins;
using namespace utils;
//using namespace pqxx;

namespace{
    uint32_t nb_packets = 0;
}

reader_t::reader_t(const process_options_t & options):
m_options{options},
reference_times{}
{

}

probe_dto_t reader_t::read_packet(const Packet & packet) const {
    nb_packets += 1;
    auto pdu = packet.pdu();
    auto ip = pdu->find_pdu<IP>();
    auto ip6 = pdu->find_pdu<IPv6>();

    auto is_v4 = ip != nullptr;
    auto is_v6 = ip6 != nullptr;

    if (is_v4){
        const IP * ip  = pdu->find_pdu<IP>();
        const ICMP * icmp  = pdu->find_pdu<ICMP>();
        const RawPDU * raw_inner = pdu->find_pdu<RawPDU>();
        const TCP * tcp = pdu->find_pdu<TCP>();


        if (icmp != nullptr && (icmp->type() == ICMP::TIME_EXCEEDED || icmp->type() == ICMP::DEST_UNREACHABLE)){
            if (raw_inner == nullptr){
                return probe_dto_t();
            }
            const uint8_t icmp_type = icmp->type();
            const uint8_t icmp_code = icmp->code();

//            const IP inner_ip = raw_inner->to<IP>();
            // Extract the protocol of the IP packet.
            // Libtins is not capable of building an incomplete TCP header so
            // If TCP and not long enough to build a complete TCP header, just pad with 0 values.
            uint8_t proto = raw_inner->payload()[9];
            // Copy the buffer
            auto padded_raw_inner = raw_inner->payload();
            if (proto == IPPROTO_TCP){
                int need_padding = sizeof(compact_ip_hdr) + sizeof(tcphdr) - padded_raw_inner.size();
                for (auto pad = 0; pad < need_padding; ++pad){
                    padded_raw_inner.push_back(0);
                }
                // Set the dataoffset to the min

                if (need_padding > 0){
                    // Create a fake TCP header so libtins can build the TCP inner pdu.
                    tcphdr * fake_tcp_header = reinterpret_cast<tcphdr*>(padded_raw_inner.data() + sizeof(compact_ip_hdr));
                    fake_tcp_header->th_off = 5;
                    fake_tcp_header->th_ack = 1;
                    fake_tcp_header->th_flags |= TH_ACK;
                    fake_tcp_header->th_win = htons(32767);
                    fake_tcp_header->th_urp = 0;
                }

            }

            IP inner_ip = IP(padded_raw_inner.data(), static_cast<uint32_t>(padded_raw_inner.size()));
            const auto ip_reply = ntohl(uint32_t (ip->src_addr()));
            const auto ip_dst = ntohl(uint32_t (ip->dst_addr()));
            const auto indirect_ip = ntohl(uint32_t (inner_ip.dst_addr()));
#ifndef NDEBUG
            if (icmp->type() == ICMP::DEST_UNREACHABLE){
//                std::cout << "Reached " << ip_dst << "\n";
            }
#endif
            const uint8_t reply_ttl = ip->ttl();
            const uint16_t reply_size = ip->tot_len();

            const uint8_t probe_ttl = inner_ip.id();
            // This field is useless
            const uint16_t probe_size = inner_ip.tot_len();
            // UDP specific
            const UDP * inner_udp = inner_ip.find_pdu<UDP>();
            const TCP * inner_tcp = inner_ip.find_pdu<TCP>();

            if (inner_udp != nullptr){
                const uint16_t sport = inner_udp->sport();
                const uint16_t dport = inner_udp->dport();
                const uint16_t checksum = Endian::host_to_be(inner_udp->checksum());

                double receive_time = static_cast<double>(std::chrono::microseconds(packet.timestamp()).count());

                double rtt = compute_rtt_from_udp(checksum, receive_time);
//                //DEBUG STUFF
//                if (indirect_ip == 41735346){
//                    std::cout << "Packet found for ttl: " << inner_ip.id() << "," << ip_dst
//                     << ","<< indirect_ip <<
//                    "," << ip_reply << "," << icmp->type() << "," <<sport << "," << dport << "\n";
//
//                }
                return probe_dto_t{ip_dst, indirect_ip, ip_reply, probe_size, probe_ttl, IPPROTO_ICMP,
                                   sport, dport, icmp_type, icmp_code, rtt,
                                   reply_ttl, reply_size};
    //                std::cout << sport << ", "  << dport << "\n";
            } else if (inner_tcp != nullptr) {
                const uint16_t sport = inner_tcp->sport();
                const uint16_t dport = inner_tcp->dport();

                double receive_time = static_cast<double>(std::chrono::microseconds(packet.timestamp()).count());
//                receive_time /= 1000;
//                std::cout << inner_ip.dst_addr() << std::endl;
                const uint32_t seq_no = inner_tcp->seq();
                double rtt = compute_rtt_from_tcp(seq_no, receive_time);
                if (rtt == 0){
                    // This is a probe received before the first timer;
                    return probe_dto_t();
                }

                return probe_dto_t{ip_dst, indirect_ip,
                                   ip_reply, probe_size, probe_ttl, IPPROTO_ICMP,
                                   sport, dport,
                                   icmp_type, icmp_code,
                                   rtt, reply_ttl, reply_size};
            } else {
                return probe_dto_t();
            }
        } else if (tcp != nullptr){

            const auto ip_reply = ntohl(uint32_t (ip->src_addr()));
            const auto ip_dst = ntohl(uint32_t (ip->dst_addr()));
            const auto indirect_ip = ip_reply;

            const uint8_t reply_ttl = ip->ttl();
            const uint16_t reply_size = ip->tot_len();

            // Decode the TCP ack to get the timestamp as well as the TTL.
            const uint32_t seq_number = tcp->ack_seq();
            // 27 bits for the timestamp.
            const uint8_t  probe_ttl  = static_cast<uint8_t>(n_last_bits(seq_number >> 27, 5));

            const uint16_t sport = tcp->sport();
            const uint16_t dport = tcp->dport();

            if (dport != m_options.sport){
                return probe_dto_t();
            }

            double receive_time = static_cast<double>(std::chrono::microseconds(packet.timestamp()).count());
            double rtt = compute_rtt_from_tcp(seq_number, receive_time);
            if (rtt == 0){
                // This is a probe received before the first timer;
                return probe_dto_t();
            }
            // This field is useless
            const uint16_t probe_size = 0;
            return probe_dto_t{ip_dst, indirect_ip,
                               ip_reply, probe_size, probe_ttl, IPPROTO_TCP,
                               dport, sport,
                               0, 0,
                               rtt, reply_ttl, reply_size};
        }
    }
    return probe_dto_t();
}

void reader_t::set_reference_time(const std::string & start_time_log_file) {
    std::ifstream f;
    f.open(start_time_log_file);
    std::string line;
    while(std::getline(f, line)){
        reference_times.push_back(std::strtod(line.c_str(), nullptr) * 1000);
        std::cout << "Setting reference time to " << line << " ms.\n";
    }
    f.close();

    std::sort(reference_times.begin(), reference_times.end(), [](double a, double b){
        return a > b;
    });
}

double reader_t::compute_rtt_from_tcp(uint32_t seq_number, double receive_time) const {

//    std::cout.precision(17);
//    std::cout << std::fixed << receive_time << " us " << nb_packets << std::endl;
    // Extract the 27 last bits in tens of ms
    double diff_time = n_last_bits(seq_number, 27);
    int reference_index = 0;
    for (auto reference_time : reference_times) {

        // extract the diff time from the seq_number, it is the 27 last bits.
        double send_time_candidate = reference_time + diff_time / 10;
        double rtt = ((receive_time) / 1000) - send_time_candidate;
        if (rtt < 0){
            reference_index += 1;
            continue;
        } else {
            return rtt;
        }
    }
    return 0;
}

double reader_t::compute_rtt_from_udp(uint16_t checksum, double receive_time) const {
    double diff_time = checksum;
    int reference_index = 0;
    for (auto reference_time : reference_times) {

        // extract the diff time from the seq_number, it is the 27 last bits.
        double send_time_candidate = reference_time + diff_time / 10;
        double rtt = ((receive_time) / 1000) - send_time_candidate;
        if (rtt < 0){
            reference_index += 1;
            continue;
        } else {
            return rtt;
        }
    }
    return 0;
}




