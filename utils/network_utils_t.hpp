//
// Created by System Administrator on 2019-03-18.
//


#include <cstdint>

#ifndef HEARTBEAT_NETWORK_UTILS_T_HPP
#define HEARTBEAT_NETWORK_UTILS_T_HPP


namespace utils {
    void init_exclude();
    bool is_excluded(uint32_t addr);

//    struct udphdr
//    {
//        uint16_t uh_sport;		/* source port */
//        uint16_t uh_dport;		/* destination port */
//        uint16_t uh_ulen;		/* udp length */
//        uint16_t uh_sum;		/* udp checksum */
//    };

    struct compact_ip_hdr {
        u_int32_t
                ip_hl:4,
                ip_v:4,
                ip_tos:8,
                ip_len:16;
        u_int16_t ip_id;
        u_int16_t ip_off;
        u_int8_t ip_ttl;
        u_int8_t ip_p;
        u_int16_t ip_sum;
        u_int32_t ip_src;
        u_int32_t ip_dst;
    };

    struct compact_ipv6_hdr {
        u_int32_t flow_lbl:24,
                priority:4,
                version:4;
        u_int16_t payload_len;
        u_int8_t nexthdr;
        u_int8_t hop_limit;
        u_int32_t saddr[4]; /* struct in6_addr */
        u_int32_t daddr[4]; /* struct in6_addr */
    };

    struct udphdr
    {
        __extension__ union
        {
            struct
            {
                uint16_t uh_sport;	/* source port */
                uint16_t uh_dport;	/* destination port */
                uint16_t uh_ulen;		/* udp length */
                uint16_t uh_sum;		/* udp checksum */
            };
            struct
            {
                uint16_t source;
                uint16_t dest;
                uint16_t len;
                uint16_t check;
            };
        };
    };

    typedef	uint32_t tcp_seq;

    struct tcphdr
    {
        __extension__ union
        {
            struct
            {
                uint16_t th_sport;	/* source port */
                uint16_t th_dport;	/* destination port */
                tcp_seq th_seq;		/* sequence number */
                tcp_seq th_ack;		/* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
                uint8_t th_x2:4;	/* (unused) */
                uint8_t th_off:4;	/* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
                uint8_t th_off:4;	/* data offset */
	uint8_t th_x2:4;	/* (unused) */
# endif
                uint8_t th_flags;
# define TH_FIN	0x01
# define TH_SYN	0x02
# define TH_RST	0x04
# define TH_PUSH	0x08
# define TH_ACK	0x10
# define TH_URG	0x20
                uint16_t th_win;	/* window */
                uint16_t th_sum;	/* checksum */
                uint16_t th_urp;	/* urgent pointer */
            };
            struct
            {
                uint16_t source;
                uint16_t dest;
                uint32_t seq;
                uint32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
                uint16_t res1:4;
                uint16_t doff:4;
                uint16_t fin:1;
                uint16_t syn:1;
                uint16_t rst:1;
                uint16_t psh:1;
                uint16_t ack:1;
                uint16_t urg:1;
                uint16_t res2:2;
# elif __BYTE_ORDER == __BIG_ENDIAN
                uint16_t doff:4;
	uint16_t res1:4;
	uint16_t res2:2;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
                uint16_t window;
                uint16_t check;
                uint16_t urg_ptr;
            };
        };
    };

    /*
	96 bit (12 bytes) pseudo header needed for udp header checksum calculation
*/
    struct pseudo_header
    {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t transport_length;
    };



    struct pseudo_header_udp
    {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t transport_length;

        uint16_t uh_sport;	/* source port */
        uint16_t uh_dport;	/* destination port */
        uint16_t uh_ulen;	/* udp length */
        uint16_t uh_sum;	/* udp checksum */

//        uint16_t payload; /* 2 bytes payload to adjust RTT*/
    };

    // Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
    /**
     * Compute the UDP/TCP checksum
     * @param buf
     * @param nwords
     * @return
     */
    uint16_t csum(uint16_t *buf, int nwords);

    /**
     * Compute the sum of 16 bits words.
     * @param buf
     * @param nwords
     * @return
     */
    uint32_t sum(uint16_t *buf, int nwords);

    /**
     * Compute one complement of 16-bit sum obtained from the 32-bit sum
     * @param sum
     * @return
     */
    uint16_t one_s_complement_bits32_sum_to_16(uint32_t sum);


    uint32_t in_cksum(unsigned char *buf, unsigned nbytes, uint32_t sum);

    uint32_t wrapsum(uint32_t sum);

    uint32_t closest_prefix(uint32_t inf_born, uint32_t prefix_mask);

}

#endif //HEARTBEAT_NETWORK_UTILS_T_HPP
