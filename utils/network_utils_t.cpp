//
// Created by System Administrator on 2019-03-18.
//

#include <cstdint>
#include <arpa/inet.h>
#include <iostream>
#include <tins/tins.h>



using namespace Tins;

namespace utils{


    // Excluded prefixes for avoir CEF drops at NPS

    std::vector<std::pair<uint32_t, uint32_t >> excluded_prefixes;


    bool is_excluded(uint32_t addr){
        for (const auto & prefix : excluded_prefixes){
            if (prefix.first <= addr && addr <= prefix.second){
                return true;
            }
        }
        return false;
    }



    void init_exclude(){

        //Prefixes extracted from https://en.wikipedia.org/wiki/Reserved_IP_addresses

        uint32_t software_first =        ntohl(uint32_t (IPv4Address("0.0.0.0")));
        uint32_t software_last =         ntohl(uint32_t (IPv4Address("0.255.255.255")));
        uint32_t private_network_first = ntohl(uint32_t (IPv4Address("10.0.0.0")));
        uint32_t private_network_last =  ntohl(uint32_t (IPv4Address("10.255.255.255")));
        uint32_t private_nat_network_first =ntohl(uint32_t (IPv4Address("100.64.0.0")));
        uint32_t private_nat_network_last = ntohl(uint32_t (IPv4Address("100.127.255.255")));
        uint32_t host_first =            ntohl(uint32_t (IPv4Address("127.0.0.0")));
        uint32_t host_last =             ntohl(uint32_t (IPv4Address("127.255.255.255")));
        uint32_t subnet_first =          ntohl(uint32_t (IPv4Address("169.254.0.0")));
        uint32_t subnet_last =           ntohl(uint32_t (IPv4Address("169.254.255.255")));
        uint32_t private2_network_first =ntohl(uint32_t (IPv4Address("172.16.0.0")));
        uint32_t private2_network_last =           ntohl(uint32_t (IPv4Address("172.31.255.255")));
        uint32_t private_ietf_first =          ntohl(uint32_t (IPv4Address("192.0.0.0")));
        uint32_t private_ietf_last =           ntohl(uint32_t (IPv4Address("192.0.0.255")));
        uint32_t private_testnet1_first =          ntohl(uint32_t (IPv4Address("192.0.2.0")));
        uint32_t private_testnet1_last =           ntohl(uint32_t (IPv4Address("192.0.2.255")));
        uint32_t internet_first =          ntohl(uint32_t (IPv4Address("192.88.99.0")));
        uint32_t internet_last =           ntohl(uint32_t (IPv4Address("192.88.99.255")));
        uint32_t private3_network_first =          ntohl(uint32_t (IPv4Address("192.168.0.0")));
        uint32_t private3_network_last =           ntohl(uint32_t (IPv4Address("192.168.255.255")));
        uint32_t private_inter_first =          ntohl(uint32_t (IPv4Address("198.18.0.0")));
        uint32_t private_inter_last =           ntohl(uint32_t (IPv4Address("198.19.255.255")));
        uint32_t private_testnet2_first =          ntohl(uint32_t (IPv4Address("198.51.100.0")));
        uint32_t private_testnet2_last =           ntohl(uint32_t (IPv4Address("198.51.100.255")));
        uint32_t private_testnet3_first =          ntohl(uint32_t (IPv4Address("203.0.113.0")));
        uint32_t private_testnet3_last =           ntohl(uint32_t (IPv4Address("203.0.113.255")));
        uint32_t multicast_first =          ntohl(uint32_t (IPv4Address("224.0.0.0")));
        uint32_t multicast_last =           ntohl(uint32_t (IPv4Address("239.255.255.255")));


        uint32_t future_internet_first = ntohl(uint32_t (IPv4Address("240.0.0.0")));
        uint32_t future_internet_last =  ntohl(uint32_t (IPv4Address("255.255.255.254")));


        // NPS complaint from Australia
        uint32_t black_list_au_first = ntohl(uint32_t (IPv4Address("203.122.238.0")));
        uint32_t black_list_au_last = ntohl(uint32_t (IPv4Address("203.122.238.7")));

        uint32_t black_list_au_2_first = ntohl(uint32_t (IPv4Address("59.167.84.176")));
        uint32_t black_list_au_2_last = ntohl(uint32_t (IPv4Address("59.167.84.183")));

        excluded_prefixes.emplace_back(std::make_pair(software_first, software_last));
        excluded_prefixes.emplace_back(std::make_pair(private_network_first, private_network_last));
        excluded_prefixes.emplace_back(std::make_pair(private_nat_network_first, private_nat_network_last));
        excluded_prefixes.emplace_back(std::make_pair(host_first, host_last));
        excluded_prefixes.emplace_back(std::make_pair(subnet_first, subnet_last));
        excluded_prefixes.emplace_back(std::make_pair(private2_network_first, private2_network_last));
        excluded_prefixes.emplace_back(std::make_pair(private_ietf_first, private_ietf_last));
        excluded_prefixes.emplace_back(std::make_pair(private_testnet1_first, private_testnet1_last));
        excluded_prefixes.emplace_back(std::make_pair(internet_first, internet_last));
        excluded_prefixes.emplace_back(std::make_pair(private3_network_first, private3_network_last));
        excluded_prefixes.emplace_back(std::make_pair(private_inter_first, private_inter_last));
        excluded_prefixes.emplace_back(std::make_pair(private_testnet2_first, private_testnet2_last));
        excluded_prefixes.emplace_back(std::make_pair(private_testnet3_first, private_testnet3_last));
        excluded_prefixes.emplace_back(std::make_pair(multicast_first, multicast_last));
        excluded_prefixes.emplace_back(std::make_pair(future_internet_first, future_internet_last));

        excluded_prefixes.emplace_back(std::make_pair(black_list_au_first, black_list_au_last));
        excluded_prefixes.emplace_back(std::make_pair(black_list_au_2_first, black_list_au_2_last));

        std::cout << "Excluded prefixes: \n";
        for (const auto & prefix : excluded_prefixes){
            std::cout << IPv4Address(htonl(prefix.first)) << " " << IPv4Address(htonl(prefix.second)) << "\n";
        }
    }

    uint16_t one_s_complement_bits32_sum_to_16(uint32_t sum){
        // Fold 32-bits sum into 16 bit
        sum = (sum >> 16) + (sum & 0xFFFF);
        // Keep only the 16 last bits.
        sum += (sum >> 16);
        return (unsigned short)(~sum);
    }

    uint32_t sum(uint16_t * buf, int nwords)
    {

        uint32_t sum;

        // Compute the sum
        for(sum=0; nwords>0; nwords-=2){
            sum += *buf++;
        }

        // If one 16-bits word remains left
        if(nwords){
            sum = sum + *(unsigned char*)buf;
        }


        return sum;
    }

    uint16_t csum(uint16_t * buf, int nwords)
    {

        std::cout << "nwords: " << nwords << "\n";

        uint32_t sum;

        // Compute the sum
        for(sum=0; nwords>0; nwords-=2){
            std::cout << *buf << "\n";
            sum += *buf++;
        }

        // If one 16-bits word remains left
        if(nwords){
            sum = sum + *(unsigned char*)buf;
        }


        // Fold 32-bits sum into 16 bit
        sum = (sum >> 16) + (sum & 0xFFFF);
        // Keep only the 16 last bits.
        sum += (sum >> 16);
        std::cout << "checksum: " << (unsigned short)(~sum) << "\n";
        return (unsigned short)(~sum);
    }

    /*
 * Checksum routine for Internet Protocol family headers (C Version)
 * Borrowed from DHCPd
 */
    uint32_t in_cksum(unsigned char *buf, unsigned nbytes, uint32_t sum) {
        uint32_t i;

        for (i = 0; i < (nbytes & ~1U); i += 2) {
            sum += (u_int16_t) ntohs(*((u_int16_t *)(buf + i)));

            if(sum > 0xFFFF)
                sum -= 0xFFFF;
        }

        if(i < nbytes) {
            sum += buf [i] << 8;
            if(sum > 0xFFFF)
                sum -= 0xFFFF;
        }
        return sum;
    }

    uint32_t wrapsum (uint32_t sum) {
        sum = ~sum & 0xFFFF;
        return htons(sum);
    }

    uint32_t closest_prefix(uint32_t inf_born, uint32_t prefix_mask) {

        uint32_t increment = (0xFFFFFFFF >> prefix_mask) + 1;
        // Find the first /prefix_mask prefix greater than inf_born.
        uint32_t i = 0;
        for (;; i+=increment){
            if (i > inf_born){
                break;
            }
        }
        return i;
    }

}
