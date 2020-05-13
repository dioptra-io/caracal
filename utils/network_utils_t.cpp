//
// Created by System Administrator on 2019-03-18.
//

#include <cstdint>
#include <arpa/inet.h>
#include <iostream>
#include <tins/tins.h>
#include <patricia.hpp>
#include <assert.h>
#include <sstream>
#include <fstream>

using namespace Tins;


namespace utils{



//    prefix_prefixlen_t read_prefix_line(const std::string & line){
//        // Parse the prefix line
//        std::stringstream line_stream;
//        std::vector<std::string> tokens;
//        std::string token;
//        while (std::getline(line_stream, token, '/')) {
//            tokens.push_back(token);
//        }
//        assert(tokens.size() == 2);
//        auto prefix = tokens[0];
//        auto prefix_len = tokens[1];
//
//        return std::make_pair(prefix, prefix_len);
//    }

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
