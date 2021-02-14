#include <arpa/inet.h>

#include <array>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include <dminer/builder.hpp>

using dminer::Packet;
using std::array;
using std::byte;

namespace Ethernet = dminer::Builder::Ethernet;
namespace ICMP = dminer::Builder::ICMP;
namespace IP = dminer::Builder::IP;
namespace TCP = dminer::Builder::TCP;
namespace UDP = dminer::Builder::UDP;

TEST_CASE("Builder") {
  in_addr src_addr{3789697};
  in_addr dst_addr{6543665};
  uint16_t flow_id = 24000;
  uint16_t src_port = 24000;
  uint16_t dst_port = 33434;
  uint8_t ttl = 8;
  uint16_t payload_len = 10;
  uint16_t timestamp_enc = 10;

  array<byte, 65536> buffer{};

  BENCHMARK("Builder::ICMP") {
    Packet packet{buffer, L2PROTO_ETHERNET, IPPROTO_IP, IPPROTO_ICMP,
                  payload_len};
    Ethernet::init(packet, true, {0}, {0});
    IP::init(packet, IPPROTO_ICMP, src_addr, dst_addr, ttl);
    ICMP::init(packet, flow_id, timestamp_enc);
    return packet;
  };

  BENCHMARK("Builder::TCP") {
    Packet packet{buffer, L2PROTO_ETHERNET, IPPROTO_IP, IPPROTO_ICMP,
                  payload_len};
    Ethernet::init(packet, true, {0}, {0});
    IP::init(packet, IPPROTO_TCP, src_addr, dst_addr, ttl);
    TCP::init(packet);
    TCP::set_ports(packet, src_port, dst_port);
    TCP::set_sequence(packet, timestamp_enc, ttl);
    TCP::set_checksum(packet);
    return packet;
  };

  BENCHMARK("Builder::UDP/v4") {
    Packet packet{buffer, L2PROTO_ETHERNET, IPPROTO_IP, IPPROTO_ICMP,
                  payload_len};
    Ethernet::init(packet, true, {0}, {0});
    IP::init(packet, IPPROTO_UDP, src_addr, dst_addr, ttl);
    UDP::set_length(packet);
    UDP::set_ports(packet, src_port, dst_port);
    UDP::set_checksum(packet, timestamp_enc);
    return packet;
  };
}
