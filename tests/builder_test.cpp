#include <arpa/inet.h>
#include <tins/tins.h>

extern "C" {
#include <netutils/checksum.h>
}

#include <array>
#include <catch2/catch.hpp>
#include <dminer/builder.hpp>
#include <dminer/timestamp.hpp>

using dminer::encode_timestamp;
using dminer::Builder::transport_checksum;

namespace ICMP = dminer::Builder::ICMP;
namespace IPv4 = dminer::Builder::IPv4;
namespace TCP = dminer::Builder::TCP;
namespace UDP = dminer::Builder::UDP;

bool validate_ip_checksum(uint8_t* buffer) {
  const auto ip_header = reinterpret_cast<ip*>(buffer);
  const uint16_t original = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  const uint16_t correct = ip_checksum(buffer, sizeof(ip));
  ip_header->ip_sum = original;
  return original == correct;
}

bool validate_icmp_checksum(uint8_t* buffer, const uint16_t payload_len) {
  const auto icmp_header = reinterpret_cast<icmphdr*>(buffer + sizeof(ip));
  const uint16_t original = icmp_header->checksum;
  icmp_header->checksum = 0;
  const uint16_t correct =
      ip_checksum(buffer + sizeof(ip), sizeof(icmphdr) + payload_len);
  icmp_header->checksum = original;
  return original == correct;
}

bool validate_tcp_checksum(uint8_t* buffer, const uint16_t payload_len) {
  const auto tcp_header = reinterpret_cast<tcphdr*>(buffer + sizeof(ip));
  const uint16_t original = tcp_header->th_sum;
  tcp_header->th_sum = 0;
  const uint16_t correct =
      transport_checksum(buffer, sizeof(tcphdr) + payload_len);
  tcp_header->th_sum = original;
  return original == correct;
}

bool validate_udp_checksum(uint8_t* buffer, const uint16_t payload_len) {
  const auto udp_header = reinterpret_cast<udphdr*>(buffer + sizeof(ip));
  const uint16_t original = udp_header->uh_sum;
  udp_header->uh_sum = 0;
  const uint16_t correct =
      transport_checksum(buffer, sizeof(udphdr) + payload_len);
  udp_header->uh_sum = original;
  return original == correct;
}

TEST_CASE("Builder::ICMP") {
  uint8_t buffer[65536] = {0};
  in_addr src_addr{3789697};
  in_addr dst_addr{6543665};
  uint16_t flow_id = 24000;
  uint8_t ttl = 8;
  uint16_t payload_len = 10;
  uint64_t timestamp = 123456;

  IPv4::init(buffer, IPPROTO_ICMP, src_addr, dst_addr, ttl, payload_len);
  ICMP::init(buffer, flow_id, timestamp);

  REQUIRE(validate_ip_checksum(buffer));
  REQUIRE(validate_icmp_checksum(buffer, payload_len));

  auto ip = Tins::IP(buffer, sizeof(iphdr) + sizeof(icmphdr) + payload_len);
  REQUIRE(uint32_t(ip.src_addr()) == src_addr.s_addr);
  REQUIRE(uint32_t(ip.dst_addr()) == dst_addr.s_addr);
  REQUIRE(ip.id() == ttl);
  REQUIRE(ip.ttl() == ttl);

  auto icmp = ip.rfind_pdu<Tins::ICMP>();
  REQUIRE(htons(icmp.id()) == flow_id);
  REQUIRE(htons(icmp.checksum()) == flow_id);
  REQUIRE(htons(icmp.sequence()) == encode_timestamp(timestamp));
}

TEST_CASE("Builder::TCP") {
  uint8_t buffer[65536] = {0};
  in_addr src_addr{3789697};
  in_addr dst_addr{6543665};
  uint16_t src_port = 24000;
  uint16_t dst_port = 33434;
  uint8_t ttl = 8;
  uint16_t payload_len = 10;
  uint64_t timestamp = 123456;

  IPv4::init(buffer, IPPROTO_TCP, src_addr, dst_addr, ttl, payload_len);
  TCP::init(buffer);
  TCP::set_ports(buffer, src_port, dst_port);
  TCP::set_sequence(buffer, timestamp, ttl);
  TCP::set_checksum(buffer, payload_len);

  REQUIRE(validate_ip_checksum(buffer));
  REQUIRE(validate_tcp_checksum(buffer, payload_len));

  auto ip = Tins::IP(buffer, sizeof(iphdr) + sizeof(tcphdr) + payload_len);
  REQUIRE(uint32_t(ip.src_addr()) == src_addr.s_addr);
  REQUIRE(uint32_t(ip.dst_addr()) == dst_addr.s_addr);
  REQUIRE(ip.id() == ttl);
  REQUIRE(ip.ttl() == ttl);

  auto tcp = ip.rfind_pdu<Tins::TCP>();
  REQUIRE(tcp.sport() == src_port);
  REQUIRE(tcp.dport() == dst_port);
  // TODO: Decode sequence and check TTL/timestamp.
}

TEST_CASE("Builder::UDP") {
  uint8_t buffer[65536] = {0};
  in_addr src_addr{3789697};
  in_addr dst_addr{6543665};
  uint16_t src_port = 24000;
  uint16_t dst_port = 33434;
  uint8_t ttl = 8;
  uint16_t payload_len = 10;
  uint64_t timestamp = 123456;

  IPv4::init(buffer, IPPROTO_UDP, src_addr, dst_addr, ttl, payload_len);
  UDP::set_length(buffer, payload_len);
  UDP::set_ports(buffer, src_port, dst_port);
  UDP::set_timestamp(buffer, payload_len, timestamp);

  REQUIRE(validate_ip_checksum(buffer));
  REQUIRE(validate_udp_checksum(buffer, payload_len));

  auto ip = Tins::IP(buffer, sizeof(iphdr) + sizeof(udphdr) + payload_len);
  REQUIRE(uint32_t(ip.src_addr()) == src_addr.s_addr);
  REQUIRE(uint32_t(ip.dst_addr()) == dst_addr.s_addr);
  REQUIRE(ip.id() == ttl);
  REQUIRE(ip.ttl() == ttl);

  auto udp = ip.rfind_pdu<Tins::UDP>();
  REQUIRE(udp.sport() == src_port);
  REQUIRE(udp.dport() == dst_port);
  REQUIRE(htons(udp.checksum()) == encode_timestamp(timestamp));
}
