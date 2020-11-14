//
// Created by System Administrator on 29/05/2018.
//

#include "heartbeat_t.hpp"
#include <arpa/inet.h>
#include <cmath>
#include <thread>
#include <chrono>
#include <algorithm>
#include <random>
#include <iostream>
#include <ctime>


#include <tins/tins.h>
#include <cperm.h>

#include <sys/socket.h>

#ifdef USE_PF_RING
#include <pfring_sender_t.hpp>
#endif

#include "classic_sender_t.hpp"
#include "network_utils_t.hpp"
#include "parameters_utils_t.hpp"
#include "sniffer_t.hpp"

#include <unordered_map>
#include <fstream>
#include <sstream>
#include <unordered_set>



using namespace Tins;

using namespace utils;

namespace{
    /*
 * Case Sensitive Implementation of endsWith()
 * It checks if the string 'mainStr' ends with given string 'toMatch'
 */
    bool ends_with(const std::string &mainStr, const std::string &toMatch)
    {
        if(mainStr.size() >= toMatch.size() &&
           mainStr.compare(mainStr.size() - toMatch.size(), toMatch.size(), toMatch) == 0)
            return true;
        else
            return false;
    }
}

uint32_t host_offset_permutation[256] = {
    0, 128, 64, 192, 32, 160, 96, 224, 16, 144, 80, 208, 48, 176, 112, 240, 8, 136, 72, 200, 40, 168, 104, 232, 24, 152, 88, 216, 56, 184, 120, 248,
    4, 132, 68, 196, 36, 164, 100, 228, 20, 148, 84, 212, 52, 180, 116, 244, 12, 140, 76, 204, 44, 172, 108, 236, 28, 156, 92, 220, 60, 188, 124, 252,
    2, 130, 66, 194, 34, 162, 98, 226, 18, 146, 82, 210, 50, 178, 114, 242, 10, 138, 74, 202, 42, 170, 106, 234, 26, 154, 90, 218, 58, 186, 122, 250,
    6, 134, 70, 198, 38, 166, 102, 230, 22, 150, 86, 214, 54, 182, 118, 246, 14, 142, 78, 206, 46, 174, 110, 238, 30, 158, 94, 222, 62, 190, 126, 254,
    1, 129, 65, 193, 33, 161, 97, 225, 17, 145, 81, 209, 49, 177, 113, 241, 9, 137, 73, 201, 41, 169, 105, 233, 25, 153, 89, 217, 57, 185, 121, 249,
    5, 133, 69, 197, 37, 165, 101, 229, 21, 149, 85, 213, 53, 181, 117, 245, 13, 141, 77, 205, 45, 173, 109, 237, 29, 157, 93, 221, 61, 189, 125, 253,
    3, 131, 67, 195, 35, 163, 99, 227, 19, 147, 83, 211, 51, 179, 115, 243, 11, 139, 75, 203, 43, 171, 107, 235, 27, 155, 91, 219, 59, 187, 123, 251,
    7, 135, 71, 199, 39, 167, 103, 231, 23, 151, 87, 215, 55, 183, 119, 247, 15, 143, 79, 207, 47, 175, 111, 239, 31, 159, 95, 223, 63, 191, 127, 255
};

heartbeat_t::heartbeat_t(const std::string & interface, const std::string & hw_gateway, const probing_options_t & options):
        m_patricia_trie{32}, // Only IPv4
        m_patricia_trie_excluded{32},
        m_interface{interface},
        m_hw_gateway{hw_gateway},
        m_options{options}{

}

bool heartbeat_t::check_destination_ttl(uint32_t little_endian_addr, uint8_t ttl, uint32_t host_offset) {
    if (ttl < m_options.min_ttl){
        // Do not overload the gateway
        return false;
    }

    if (m_patricia_trie_excluded.get(htonl(little_endian_addr)) != nullptr){
        // Address is excluded
        return false;
    }

    if (m_options.is_from_bgp){
        auto asn = m_patricia_trie.get(htonl(little_endian_addr));
        if (asn == nullptr){
            // Destination not in routable space.
            return false;
        }
    }

    if (!(m_options.inf_born < little_endian_addr && little_endian_addr <= m_options.sup_born )){
        return false;
    }
    // Flow starting at 0
    if (ttl > m_options.max_ttl or ttl == 0 or host_offset >= m_options.n_destinations_per_24){
        return false;
    }

    return true;
}

void heartbeat_t::send_from_probes_file() {
    std::cout << "Sending a round of heartbeat from " << m_options.probes_file << "\n";

    IPv4Address source = m_interface.ipv4_address();


#ifdef USE_PF_RING
    pf_ring_sender_t sender{AF_INET, SOCK_DGRAM, m_options.proto, m_interface, m_interface.hw_address(), m_hw_gateway, m_options.pps};
#else
    classic_sender_t sender{AF_INET, SOCK_DGRAM, m_options.proto, source.to_string(), m_options.pps};
#endif

    if (m_options.is_record_timestamp){
        sender.set_start_time_log_file(m_options.start_time_log_file);
    }




    std::ifstream targets_file{m_options.probes_file};
    std::string line;
    char delimiter = ',';
//    uint32_t sender_ip = uint32_t (source);

    uint32_t sender_ip = uint32_t (m_interface.ipv4_address());

    uint64_t count = 0;
    auto start = std::chrono::high_resolution_clock::now();


    while (std::getline(targets_file, line)){



        uint32_t src_ip = 0;
        uint32_t dst_ip = 0;
        uint16_t sport = 0;
        uint16_t dport = 0;
        uint8_t  ttl = 0;


        std::stringstream stream_line(line);
        std::string token;
        int index = 0;
        bool is_ignore_line = false;
        while(std::getline(stream_line, token,delimiter)){
            auto token_uint = static_cast<uint32_t>(std::stoul(token));
            if (token_uint == 0){
                // 0 is an incorrect value for any field.
                is_ignore_line = true;
                break;
            }
            if (index == 0){
                if (token_uint != sender_ip){
                    is_ignore_line = true;
                    break;
                }
            } else if (index == 1){
                dst_ip = token_uint;
            } else if (index == 2){
                sport = static_cast<uint16_t>(token_uint);
            } else if (index == 3){
                dport = static_cast<uint16_t>(token_uint);
            } else if (index == 4){
                ttl = static_cast<uint8_t>(token_uint);
            }
            ++index;

        }
        if (is_ignore_line){
            continue;
        }

        // Avoid CEF drops on prefixes, patricia trie takes addresses in big endian
        if (m_patricia_trie_excluded.get(dst_ip) != nullptr){
//            std::cout << "Not sending to excluded: " << IPv4Address(addr) << "\n";
            continue;
        }

        ++count;
        if (count % 1000000 == 0){
            std::cout << "Packets sent: " <<  count << "\n";
        }
#ifndef NDEBUG
        if (count >= 1000000){
            std::cout << "Finish earlier due to partial snapshot\n";
            break;
        }
#endif
        sender.send(1, dst_ip, ttl, sport, dport);

    }


    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end-start;
    std::cout << "Sending MDAYarrp round took " << elapsed.count() << " ms\n";
}


void heartbeat_t::send_exhaustive() {

//    std::ofstream ofstream;
//    ofstream.open("resources/destinations");


    auto start = std::chrono::high_resolution_clock::now();

    uint16_t starting_sport = m_options.sport;
    uint16_t starting_dport = m_options.dport;
    IPv4Address source = m_interface.ipv4_address();

    std::cout << uint32_t (source) << "\n";

#ifdef USE_PF_RING
    pf_ring_sender_t sender{AF_INET, SOCK_DGRAM, m_options.proto, m_interface, m_interface.hw_address(), m_hw_gateway, m_options.pps};
#else
    classic_sender_t sender{AF_INET, SOCK_DGRAM, m_options.proto, source.to_string(), m_options.pps};
#endif

    if (m_options.is_record_timestamp){
        sender.set_start_time_log_file(m_options.start_time_log_file);
    }

    constexpr auto KEYLEN = 16;

    uint8_t  key[KEYLEN] = { 0 };
    uint32_t val         = 0;
    uint32_t addr        = 0;
    uint8_t  ttl         = 0;
    uint32_t host        = 0;





    auto n_packets_per_flow = 1;

    std::unordered_set<uint32_t> target_prefixes;

    auto n_skipped = 0;

    long i = 0;
    struct cperm_t* perm = cperm_create(UINT32_MAX, PERM_MODE_CYCLE,
                                        PERM_CIPHER_RC5, key, KEYLEN);


    char * p = nullptr;
    p = (char *) &val;
    while (PERM_END != cperm_next(perm, &val)) {

        addr = val & 0x00FFFFFF;// pick out 24 bits of network

        // use remaining 8 bits of perm as ttl

        /** Specific implementation to optimize the 32 bits
         *  24 bits for the network, 5 bits for TTL (up to 30) and 3 bits for the MDA destination based (7 at max) corresponding to at max
         *  0.05 failure probability.
         *  If 0.01 failure probability is needed, when TTL is 0 or 31, switch this bit to the flow id.
         */

        ttl = (val >> 24) & 0x0000001F; // pick 5 bits for the TTL

        uint32_t host_offset = val >> 29; // pick the 3 remaining bits for the offset.

        // Avoid CEF drops on prefixes, addresses are big endian, so convert it to little endian
        auto little_endian_addr = ntohl(addr);

        if (!check_destination_ttl(little_endian_addr, ttl, host_offset)){
#ifndef NDEBUG
            in_addr ip_addr;
            ip_addr.s_addr = addr;
            std::cerr << "Filtered IP address ttl host_offset: "
            <<  inet_ntoa(ip_addr) << " " << uint(ttl) << " "
            << host_offset << std::endl;
#endif
            continue;
        }

        // 20201112 Maxime: Reverse byte order in an attempt to distribute dest. addrs.
        // more evenly, and discover more routers close to the destination.
        if (m_options.experimental_host_offset) {
            host_offset = host_offset_permutation[host_offset];
        }

        auto last_byte = little_endian_addr >> 24;
        if (last_byte + host_offset <= 255){
            little_endian_addr += host_offset;
        } else {
            little_endian_addr -= host_offset;
        }

        addr = htonl(little_endian_addr);
        // Exclude addresses not in the range.

        sender.send(n_packets_per_flow, addr, ttl, starting_sport, starting_dport);
        ++i;
        if (i % 10000000 == 0){
            std::cout << "Packets sent: " <<  i << "\n";
        }
        if (i >= m_options.max_packets){
            std::cout << "Finish earlier due to partial snapshot\n";
            break;
        }
    }
    cperm_destroy(perm);

//    ofstream.close();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end-start;
    std::cout << "Sent " << i << " probes\n";
    std::cout << "Sending " << m_options.n_destinations_per_24 << " per /24 took " << elapsed.count() << " ms\n";
    std::cout << "Skipped probes: " << n_skipped << "\n";
    std::cout << "Distinct target prefixes: " << target_prefixes.size() << "\n";
}

void heartbeat_t::send_from_targets_file(uint8_t max_ttl) {

    // Read the targets file
    auto targets = targets_from_file();

    std::cout << targets.size() << " targets to probe" << std::endl;

    auto start = std::chrono::high_resolution_clock::now();

    uint16_t starting_sport = m_options.sport;
    uint16_t starting_dport = m_options.dport;
    IPv4Address source = m_interface.ipv4_address();

    std::cout << uint32_t (source) << "\n";

#ifdef USE_PF_RING
    pf_ring_sender_t sender{AF_INET, SOCK_DGRAM, m_options.proto, m_interface, m_interface.hw_address(), m_hw_gateway, m_options.pps};
#else
    classic_sender_t sender{AF_INET, SOCK_DGRAM, m_options.proto, source.to_string(), m_options.pps};
#endif

    if (m_options.is_record_timestamp){
        sender.set_start_time_log_file(m_options.start_time_log_file);
    }

    constexpr auto KEYLEN = 16;

    uint8_t  key[KEYLEN] = { 0 };
    uint32_t val         = 0;
    uint32_t addr        = 0;
    uint8_t  ttl         = 0;

    auto n_packets_per_flow = 1;

    auto n_skipped = 0;


    uint64_t i = 0;

    // Compute the number of bits needed for the target.

    auto n_targets = targets.size();
    std::size_t a  = 1;
    while (static_cast<size_t>(std::pow(2, a) <= n_targets)){
        a +=1;
    }

    std::cout << "Number of bits needeed to encode " << n_targets << " targets: " << a << "\n";
    std::cout << "Number of bits needeed to encode " << max_ttl << " ttls: " << 5 << "\n";
    std::cout << "Total number of bits needeed: " << max_ttl << " ttls: " << a + 5 << "\n";

    uint32_t permutation_size = static_cast<uint32_t >(std::pow(2, a + 5));
    if (a + 5 == 32){
        permutation_size = static_cast<uint32_t >(std::pow(2, a + 5) - 1);
    }
    cperm_t* perm = cperm_create(permutation_size, PERM_MODE_CYCLE,
                                        PERM_CIPHER_RC5, key, KEYLEN);


    char * p = nullptr;
    p = (char *) &val;


    while (PERM_END != cperm_next(perm, &val)) {
        uint32_t addr_index = val & ((1 << a) - 1);// pick out a bits of the index of the address in the targets

        ttl = static_cast<uint8_t>((val >> a) & ((1 << 5) - 1)); // pick out 5 bits for the TTL.

//            if (ttl < 28){
//                // Do not overload the gateway
//                continue;
//            }

        // If the index is greater than the target size, continue.
        if (addr_index >= targets.size()){
            continue;
        }
        // Avoid CEF drops on prefixes, addresses are big endian, so convert it to little endian
        auto little_endian_addr = targets[addr_index];

        if (!check_destination_ttl(little_endian_addr, ttl, 0)){
            continue;
        }

        addr = htonl(little_endian_addr);

        sender.send(n_packets_per_flow, addr, ttl, starting_sport, starting_dport);
        ++i;
        if (i % 1000000 == 0){
            std::cout << "Packets sent: " <<  i << "\n";
        }
        if (i >= m_options.max_packets){
            std::cout << "Finish earlier due to partial snapshot\n";
            break;
        }
    }
    cperm_destroy(perm);


//    ofstream.close();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end-start;
    std::cout << "Sent " << i << " probes\n";
    std::cout << "Sending took " << elapsed.count() << " ms\n";
    std::cout << "Skipped probes: " << n_skipped << "\n";
//    std::cout << "Distinct target prefixes: " << target_prefixes.size() << "\n";
}


void heartbeat_t::start() {

    // Init the exclusion patricia trie
    // Only v4 at the moment
    std::cout << "Populating exclusion prefix...\n";
    m_patricia_trie_excluded.populateBlock(AF_INET, m_options.exclusion_file.c_str());
    // Init patricia trie if only routable destinations is specified
    if (m_options.is_from_bgp){
        std::cout << "Populating routing space...\n";
        m_patricia_trie.populate(m_options.bgp_file.c_str());
    } else if(m_options.is_from_prefix_file){
        // Only IPv4
        std::cout << "Populating prefixes...\n";
        m_patricia_trie.populateBlock(AF_INET, m_options.prefix_file.c_str());
    }
    // Init sniffer
    // Sniffer must be started here because it starts a thread.
    sniffer_t sniffer{m_interface.name(), m_options, m_options.output_file};
    sniffer.start();
    if (m_options.is_send_from_probes_file){
        send_from_probes_file();
    } else if (m_options.is_send_from_targets_file){
//        send(30, 6, m_options.n_destinations_per_24);
        send_from_targets_file(30);
    } else {
        send_exhaustive();
    }

    // Allows sniffer to get the last flying responses. 60 seconds maximum waiting time.
    std::this_thread::sleep_for(std::chrono::milliseconds(20000));
    sniffer.stop();
}

std::vector<uint32_t> heartbeat_t::targets_from_file() {
    std::ifstream infile(m_options.targets_file);

    std::string line;
    sockaddr_in sa;

// store this IP address in sa:
//    Patricia trie {32};
    std::vector<uint32_t> targets;
    std::cout << "Populating targets..." << std::endl;
    while (std::getline(infile, line)){

//        if (ends_with(line, ".0")){
//            continue;
//        }
        inet_pton(AF_INET, line.c_str(), &(sa.sin_addr));
        // Little endian
        targets.push_back(ntohl(sa.sin_addr.s_addr));
//        line += "/24";
//        std::cout << line << "\n";
//        trie.add(line.c_str(), 1);
//        auto little_endian_ip = ntohl(sa.sin_addr.s_addr);
//        auto is_in_targets = (int *) trie.get(little_endian_ip);
//        if (is_in_targets == nullptr){
//            continue;
//        }
    }
    std::cout << "Finished populating targets..." << std::endl;
    infile.close();
    return targets;
}





