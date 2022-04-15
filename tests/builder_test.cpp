#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <tins/tins.h>

// Must be included after netinet/ip.h on macOS.
#include <netinet/icmp6.h>

#include <array>
#include <caracal/builder.hpp>
#include <caracal/checksum.hpp>
#include <caracal/constants.hpp>
#include <caracal/protocols.hpp>
#include <caracal/timestamp.hpp>
#include <caracal/utilities.hpp>
#include <catch2/catch.hpp>

using caracal::Packet;
using caracal::Builder::transport_checksum;
using caracal::Utilities::format_addr;
using caracal::Utilities::parse_addr;

using std::array;
using std::byte;

namespace Checksum = caracal::Checksum;
namespace Ethernet = caracal::Builder::Ethernet;
namespace ICMP = caracal::Builder::ICMP;
namespace ICMPv6 = caracal::Builder::ICMPv6;
namespace IPv4 = caracal::Builder::IPv4;
namespace IPv6 = caracal::Builder::IPv6;
namespace UDP = caracal::Builder::UDP;
namespace Protocols = caracal::Protocols;
namespace Timestamp = caracal::Timestamp;

bool validate_ip_checksum(Packet buffer) {
  const auto ip_header = reinterpret_cast<ip*>(buffer.l3());
  const uint16_t original = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  const uint16_t correct = Checksum::ip_checksum(buffer.l3(), sizeof(ip));
  ip_header->ip_sum = original;
  return original == correct;
}

bool validate_icmp_checksum(Packet buffer) {
  const auto icmp_header = reinterpret_cast<icmp*>(buffer.l4());
  const uint16_t original = icmp_header->icmp_cksum;
  icmp_header->icmp_cksum = 0;
  const uint16_t correct = Checksum::ip_checksum(buffer.l4(), buffer.l4_size());
  icmp_header->icmp_cksum = original;
  return original == correct;
}

bool validate_icmp6_checksum(Packet buffer) {
  const auto icmp6_header = reinterpret_cast<icmp6_hdr*>(buffer.l4());
  const uint16_t original = icmp6_header->icmp6_cksum;
  icmp6_header->icmp6_cksum = 0;
  const uint16_t correct = transport_checksum(buffer);
  icmp6_header->icmp6_cksum = original;
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
  uint16_t probe_id = 46837;
  uint8_t ttl = 8;
  uint16_t payload_len = 10;
  uint16_t timestamp_enc = Timestamp::encode(123456);

  array<byte, 65536> buffer{};
  Packet packet{buffer.data(),           buffer.size(),
                Protocols::L2::Ethernet, Protocols::L3::IPv4,
                Protocols::L4::ICMP,     payload_len};

  Ethernet::init(packet, {0}, {0});
  IPv4::init(packet, src_addr, dst_addr, ttl, probe_id);
  ICMP::init(packet, flow_id, timestamp_enc);

  REQUIRE(validate_ip_checksum(packet));
  REQUIRE(validate_icmp_checksum(packet));

  auto ip = Tins::IP(reinterpret_cast<uint8_t*>(packet.l3()), packet.l3_size());
  REQUIRE(uint32_t(ip.src_addr()) == src_addr.s_addr);
  REQUIRE(uint32_t(ip.dst_addr()) == dst_addr.s_addr);
  REQUIRE(ip.id() == probe_id);
  REQUIRE(ip.ttl() == ttl);

  auto icmp = ip.rfind_pdu<Tins::ICMP>();
  REQUIRE(icmp.checksum() == flow_id);
  REQUIRE(icmp.id() == flow_id);
  REQUIRE(icmp.sequence() == timestamp_enc);

  BENCHMARK("Builder::ICMP") {
    Packet packet{buffer.data(),           buffer.size(),
                  Protocols::L2::Ethernet, Protocols::L3::IPv4,
                  Protocols::L4::ICMP,     payload_len};
    Ethernet::init(packet, {0}, {0});
    IPv4::init(packet, src_addr, dst_addr, ttl, probe_id);
    ICMP::init(packet, flow_id, timestamp_enc);
    return packet;
  };
}

TEST_CASE("Builder::ICMPv6") {
  in6_addr src_addr{}, dst_addr{};
  parse_addr("2a04:8ec0:0:164:620c:e59a:daf8:21e9", src_addr);
  parse_addr("2001:4860:4860::8888", dst_addr);
  uint16_t flow_id = 24000;
  uint8_t ttl = 8;
  uint16_t payload_len = 10;
  uint16_t timestamp_enc = Timestamp::encode(123456);

  array<byte, 65536> buffer{};
  Packet packet{buffer.data(),           buffer.size(),
                Protocols::L2::Ethernet, Protocols::L3::IPv6,
                Protocols::L4::ICMPv6,   payload_len};

  Ethernet::init(packet, {0}, {0});
  IPv6::init(packet, src_addr, dst_addr, ttl);
  ICMPv6::init(packet, flow_id, timestamp_enc);

  REQUIRE(validate_icmp6_checksum(packet));

  auto ip6 =
      Tins::IPv6(reinterpret_cast<uint8_t*>(packet.l3()), packet.l3_size());
  in6_addr new_src_addr{}, new_dst_addr{};
  ip6.src_addr().copy(new_src_addr.s6_addr);
  ip6.dst_addr().copy(new_dst_addr.s6_addr);
  REQUIRE(IN6_ARE_ADDR_EQUAL(&new_src_addr, &src_addr));
  REQUIRE(IN6_ARE_ADDR_EQUAL(&new_dst_addr, &dst_addr));
  REQUIRE(ip6.hop_limit() == ttl);

  auto icmp6 = ip6.rfind_pdu<Tins::ICMPv6>();
  REQUIRE(icmp6.checksum() == flow_id);
  REQUIRE(icmp6.identifier() == flow_id);
  REQUIRE(icmp6.sequence() == timestamp_enc);
}

TEST_CASE("Builder::UDP/v4") {
  in_addr src_addr{3789697};
  in_addr dst_addr{6543665};
  uint16_t src_port = 24000;
  uint16_t dst_port = 33434;
  uint16_t probe_id = 46837;
  uint8_t ttl = 8;
  uint16_t payload_len = 10;
  uint16_t timestamp_enc = Timestamp::encode(123456);

  array<byte, 65536> buffer{};
  Packet packet{buffer.data(),           buffer.size(),
                Protocols::L2::Ethernet, Protocols::L3::IPv4,
                Protocols::L4::UDP,      payload_len};

  Ethernet::init(packet, {0}, {0});
  IPv4::init(packet, src_addr, dst_addr, ttl, probe_id);
  UDP::init(packet, timestamp_enc, src_port, dst_port);

  REQUIRE(validate_ip_checksum(packet));
  REQUIRE(validate_udp_checksum(packet));

  auto ip = Tins::IP(reinterpret_cast<uint8_t*>(packet.l3()), packet.l3_size());
  REQUIRE(uint32_t(ip.src_addr()) == src_addr.s_addr);
  REQUIRE(uint32_t(ip.dst_addr()) == dst_addr.s_addr);
  REQUIRE(ip.id() == probe_id);
  REQUIRE(ip.ttl() == ttl);

  auto udp = ip.rfind_pdu<Tins::UDP>();
  REQUIRE(udp.sport() == src_port);
  REQUIRE(udp.dport() == dst_port);
  REQUIRE(udp.checksum() == timestamp_enc);

  BENCHMARK("Builder::UDP/v4") {
    Packet packet{buffer.data(),           buffer.size(),
                  Protocols::L2::Ethernet, Protocols::L3::IPv4,
                  Protocols::L4::UDP,      payload_len};
    Ethernet::init(packet, {0}, {0});
    IPv4::init(packet, src_addr, dst_addr, ttl, probe_id);
    UDP::init(packet, timestamp_enc, src_port, dst_port);
    return packet;
  };
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
  Packet packet{buffer.data(),           buffer.size(),
                Protocols::L2::Ethernet, Protocols::L3::IPv6,
                Protocols::L4::UDP,      payload_len};

  Ethernet::init(packet, {0}, {0});
  IPv6::init(packet, src_addr, dst_addr, ttl);
  UDP::init(packet, timestamp_enc, src_port, dst_port);

  REQUIRE(validate_udp_checksum(packet));

  auto ip6 =
      Tins::IPv6(reinterpret_cast<uint8_t*>(packet.l3()), packet.l3_size());
  in6_addr new_src_addr{}, new_dst_addr{};
  ip6.src_addr().copy(new_src_addr.s6_addr);
  ip6.dst_addr().copy(new_dst_addr.s6_addr);
  REQUIRE(IN6_ARE_ADDR_EQUAL(&new_src_addr, &src_addr));
  REQUIRE(IN6_ARE_ADDR_EQUAL(&new_dst_addr, &dst_addr));
  REQUIRE(ip6.hop_limit() == ttl);

  auto udp = ip6.rfind_pdu<Tins::UDP>();
  REQUIRE(udp.sport() == src_port);
  REQUIRE(udp.dport() == dst_port);
  REQUIRE(udp.checksum() == timestamp_enc);
}
