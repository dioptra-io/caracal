#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <tins/tins.h>

extern "C" {
#include <netutils/checksum.h>
}

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <dminer/builder.hpp>
#include <dminer/constants.hpp>
#include <dminer/timestamp.hpp>

using dminer::Packet;
using dminer::Builder::transport_checksum;
using std::array;
using std::byte;

namespace Ethernet = dminer::Builder::Ethernet;
namespace ICMP = dminer::Builder::ICMP;
namespace IP = dminer::Builder::IP;
namespace UDP = dminer::Builder::UDP;
namespace Timestamp = dminer::Timestamp;

bool validate_ip_checksum(Packet buffer) {
  const auto ip_header = reinterpret_cast<ip*>(buffer.l3());
  const uint16_t original = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  const uint16_t correct = ip_checksum(buffer.l3(), sizeof(ip));
  ip_header->ip_sum = original;
  return original == correct;
}

bool validate_icmp_checksum(Packet buffer) {
  const auto icmp_header = reinterpret_cast<icmp*>(buffer.l4());
  const uint16_t original = icmp_header->icmp_cksum;
  icmp_header->icmp_cksum = 0;
  const uint16_t correct = ip_checksum(buffer.l4(), buffer.l4_size());
  icmp_header->icmp_cksum = original;
  return original == correct;
}

bool validate_udp_checksum(Packet buffer) {
  const auto udp_header = reinterpret_cast<udphdr*>(buffer.l4());
  const uint16_t original = udp_header->uh_sum;
  udp_header->uh_sum = 0;
  const uint16_t correct = transport_checksum(buffer);
  udp_header->uh_sum = original;
  return original == correct;
}

TEST_CASE("Builder::ICMP") {
  in_addr src_addr{3789697};
  in_addr dst_addr{6543665};
  uint16_t flow_id = 24000;
  uint8_t ttl = 8;
  uint16_t payload_len = 10;
  uint16_t timestamp_enc = Timestamp::encode(123456);

  array<byte, 65536> buffer{};
  Packet packet{buffer, L2PROTO_ETHERNET, IPPROTO_IP, IPPROTO_ICMP,
                payload_len};

  Ethernet::init(packet, true, {0}, {0});
  IP::init(packet, IPPROTO_ICMP, src_addr, dst_addr, ttl);
  ICMP::init(packet, flow_id, timestamp_enc);

  REQUIRE(validate_ip_checksum(packet));
  REQUIRE(validate_icmp_checksum(packet));

  auto ip = Tins::IP(reinterpret_cast<uint8_t*>(packet.l3()), packet.l3_size());
  REQUIRE(uint32_t(ip.src_addr()) == src_addr.s_addr);
  REQUIRE(uint32_t(ip.dst_addr()) == dst_addr.s_addr);
  REQUIRE(ip.id() == ttl);
  REQUIRE(ip.ttl() == ttl);

  auto icmp = ip.rfind_pdu<Tins::ICMP>();
  REQUIRE(icmp.checksum() == flow_id);
  REQUIRE(icmp.id() == flow_id);
  REQUIRE(icmp.sequence() == timestamp_enc);
}

TEST_CASE("Builder::UDP/v4") {
  in_addr src_addr{3789697};
  in_addr dst_addr{6543665};
  uint16_t src_port = 24000;
  uint16_t dst_port = 33434;
  uint8_t ttl = 8;
  uint16_t payload_len = 10;
  uint16_t timestamp_enc = Timestamp::encode(123456);

  array<byte, 65536> buffer{};
  Packet packet{buffer, L2PROTO_ETHERNET, IPPROTO_IP, IPPROTO_UDP, payload_len};

  Ethernet::init(packet, true, {0}, {0});
  IP::init(packet, IPPROTO_UDP, src_addr, dst_addr, ttl);
  UDP::set_length(packet);
  UDP::set_ports(packet, src_port, dst_port);
  UDP::set_checksum(packet, timestamp_enc);

  REQUIRE(validate_ip_checksum(packet));
  REQUIRE(validate_udp_checksum(packet));

  auto ip = Tins::IP(reinterpret_cast<uint8_t*>(packet.l3()), packet.l3_size());
  REQUIRE(uint32_t(ip.src_addr()) == src_addr.s_addr);
  REQUIRE(uint32_t(ip.dst_addr()) == dst_addr.s_addr);
  REQUIRE(ip.id() == ttl);
  REQUIRE(ip.ttl() == ttl);

  auto udp = ip.rfind_pdu<Tins::UDP>();
  REQUIRE(udp.sport() == src_port);
  REQUIRE(udp.dport() == dst_port);
  REQUIRE(udp.checksum() == timestamp_enc);
}

TEST_CASE("Builder::UDP/v6") {
  in6_addr src_addr = in6addr_any;
  in6_addr dst_addr = in6addr_loopback;
  uint16_t src_port = 24000;
  uint16_t dst_port = 33434;
  uint8_t ttl = 8;
  uint16_t payload_len = 10;
  uint16_t timestamp_enc = Timestamp::encode(123456);

  array<byte, 65536> buffer{};
  Packet packet{buffer, L2PROTO_ETHERNET, IPPROTO_IPV6, IPPROTO_UDP,
                payload_len};

  Ethernet::init(packet, true, {0}, {0});
  IP::init(packet, IPPROTO_UDP, src_addr, dst_addr, ttl);
  UDP::set_length(packet);
  UDP::set_ports(packet, src_port, dst_port);
  UDP::set_checksum(packet, timestamp_enc);

  REQUIRE(validate_udp_checksum(packet));

  auto ip =
      Tins::IPv6(reinterpret_cast<uint8_t*>(packet.l3()), packet.l3_size());
  // TODO:
  // REQUIRE(ip.src_addr().to_string() uint32_t(ip.src_addr()) ==
  // src_addr.s_addr); REQUIRE(uint32_t(ip.dst_addr()) == dst_addr.s_addr);
  // ip.id
  // REQUIRE(int(ip.flow_label()) == ttl);
  REQUIRE(ip.hop_limit() == ttl);

  auto udp = ip.rfind_pdu<Tins::UDP>();
  REQUIRE(udp.sport() == src_port);
  REQUIRE(udp.dport() == dst_port);
  REQUIRE(udp.checksum() == timestamp_enc);
}
