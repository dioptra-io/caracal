#include <tins/tins.h>

#include <caracal/parser.hpp>
#include <caracal/utilities.hpp>
#include <catch2/catch.hpp>
#include <filesystem>
#include <string>
#include <vector>

using caracal::Parser::build_inner;
using caracal::Parser::parse;
using caracal::Utilities::format_addr;

namespace fs = std::filesystem;

static auto data = fs::path{__FILE__}.parent_path() / ".." / "data";

inline auto parse_file(const std::string& file) {
  Tins::FileSniffer sniffer{file};
  std::vector<caracal::Reply> res;

  auto handler = [&res](Tins::Packet& packet) {
    auto reply = parse(packet);
    if (reply) {
      res.push_back(reply.value());
    }
    return true;
  };

  sniffer.sniff_loop(handler);
  return res;
}

// TODO: Test is_valid() (needs new captures).

// Replies to ICMP probes.
TEST_CASE("Parser::parse/ICMP") {
  SECTION("ICMP TTL Exceeded") {
    auto res = parse_file(data / "icmp-icmp-ttl-exceeded.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(reply.capture_timestamp == 1613155623845580);
    REQUIRE(format_addr(reply.reply_src_addr) == "72.14.204.68");
    REQUIRE(format_addr(reply.reply_dst_addr) == "192.168.1.5");
    REQUIRE(reply.reply_size == 56);
    REQUIRE(reply.reply_ttl == 250);
    REQUIRE(reply.reply_protocol == IPPROTO_ICMP);
    REQUIRE(reply.reply_icmp_type == 11);
    REQUIRE(reply.reply_icmp_code == 0);
    REQUIRE(reply.reply_mpls_labels.empty());
    REQUIRE(format_addr(reply.probe_dst_addr) == "8.8.8.8");
    REQUIRE(reply.probe_size == 36);
    REQUIRE(reply.probe_ttl == 6);
    REQUIRE(reply.probe_protocol == IPPROTO_ICMP);
    REQUIRE(reply.probe_src_port == 24000);
    REQUIRE(reply.probe_dst_port == 0);
    REQUIRE(reply.quoted_ttl == 1);
    REQUIRE(reply.rtt == 66);
    REQUIRE(!reply.is_destination_unreachable());
    REQUIRE(!reply.is_echo_reply());
    REQUIRE(reply.is_time_exceeded());
  }

  SECTION("ICMP TTL Exceeded with MPLS Extensions") {
    auto res = parse_file(data / "icmp-icmp-ttl-exceeded-mpls.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(reply.capture_timestamp == 1638522471773669);
    REQUIRE(format_addr(reply.reply_src_addr) == "12.122.28.42");
    REQUIRE(format_addr(reply.reply_dst_addr) == "132.227.123.8");
    REQUIRE(reply.reply_size == 172);
    REQUIRE(reply.reply_ttl == 239);
    REQUIRE(reply.reply_protocol == IPPROTO_ICMP);
    REQUIRE(reply.reply_icmp_type == 11);
    REQUIRE(reply.reply_icmp_code == 0);
    REQUIRE(reply.reply_mpls_labels.size() == 2);
    REQUIRE(reply.reply_mpls_labels.at(0) == std::tuple{29657, 0, 0, 1});
    REQUIRE(reply.reply_mpls_labels.at(1) == std::tuple{25437, 0, 1, 1});
    REQUIRE(format_addr(reply.probe_dst_addr) == "65.83.239.127");
    REQUIRE(reply.probe_size == 42);
    REQUIRE(reply.probe_ttl == 12);
    REQUIRE(reply.probe_protocol == IPPROTO_ICMP);
    REQUIRE(reply.probe_src_port == 24000);
    REQUIRE(reply.probe_dst_port == 0);
    // The sequence number in the inner ICMP header of this reply
    // is different from the one in the probe packet, so we cannot
    // recover the RTT.
    // REQUIRE(reply.rtt == 553);
    REQUIRE(reply.quoted_ttl == 2);
    REQUIRE(!reply.is_destination_unreachable());
    REQUIRE(!reply.is_echo_reply());
    REQUIRE(reply.is_time_exceeded());
  }

  SECTION("ICMP Echo Reply") {
    auto res = parse_file(data / "icmp-icmp-echo-reply.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(reply.capture_timestamp == 1613155697130290);
    REQUIRE(format_addr(reply.reply_src_addr) == "8.8.8.8");
    REQUIRE(format_addr(reply.reply_dst_addr) == "192.168.1.5");
    REQUIRE(reply.reply_size == 40);
    REQUIRE(reply.reply_ttl == 117);
    REQUIRE(reply.reply_protocol == IPPROTO_ICMP);
    REQUIRE(reply.reply_icmp_type == 0);
    REQUIRE(reply.reply_icmp_code == 0);
    REQUIRE(reply.reply_mpls_labels.empty());
    REQUIRE(format_addr(reply.probe_dst_addr) == "8.8.8.8");
    REQUIRE(reply.probe_size == 0);
    REQUIRE(reply.probe_ttl == 10);
    REQUIRE(reply.probe_protocol == IPPROTO_ICMP);
    REQUIRE(reply.probe_src_port == 24000);
    REQUIRE(reply.probe_dst_port == 0);
    REQUIRE(reply.quoted_ttl == 0);
    REQUIRE(reply.rtt == 69);
    REQUIRE(!reply.is_destination_unreachable());
    REQUIRE(reply.is_echo_reply());
    REQUIRE(!reply.is_time_exceeded());
  }
}

TEST_CASE("Parser::parse/ICMPv6") {
  SECTION("ICMPv6 TTL Exceeded") {
    auto res = parse_file(data / "icmp6-icmp6-ttl-exceeded.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(reply.capture_timestamp == 1615987564867543);
    REQUIRE(format_addr(reply.reply_src_addr) == "2a04:8ec0:0:a::1:119");
    REQUIRE(format_addr(reply.reply_dst_addr) ==
            "2a04:8ec0:0:164:620c:e59a:daf8:21e9");
    REQUIRE(reply.reply_size == 60);
    REQUIRE(reply.reply_ttl == 63);
    REQUIRE(reply.reply_protocol == IPPROTO_ICMPV6);
    REQUIRE(reply.reply_icmp_type == 3);
    REQUIRE(reply.reply_icmp_code == 0);
    REQUIRE(reply.reply_mpls_labels.empty());
    REQUIRE(format_addr(reply.probe_dst_addr) == "2001:4860:4860::8888");
    REQUIRE(reply.probe_size == 12);
    REQUIRE(reply.probe_ttl == 2);
    REQUIRE(reply.probe_protocol == IPPROTO_ICMPV6);
    REQUIRE(reply.probe_src_port == 24000);
    REQUIRE(reply.probe_dst_port == 0);
    REQUIRE(reply.quoted_ttl == 1);
    REQUIRE(reply.rtt == 6);
    REQUIRE(!reply.is_destination_unreachable());
    REQUIRE(!reply.is_echo_reply());
    REQUIRE(reply.is_time_exceeded());
  }

  SECTION("ICMPv6 Echo Reply") {
    auto res = parse_file(data / "icmp6-icmp6-echo-reply.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(reply.capture_timestamp == 1615987338565191);
    REQUIRE(format_addr(reply.reply_src_addr) == "2001:4860:4860::8888");
    REQUIRE(format_addr(reply.reply_dst_addr) ==
            "2a04:8ec0:0:164:620c:e59a:daf8:21e9");
    REQUIRE(reply.reply_size == 18);
    REQUIRE(reply.reply_ttl == 118);
    REQUIRE(reply.reply_protocol == IPPROTO_ICMPV6);
    REQUIRE(reply.reply_icmp_type == 129);
    REQUIRE(reply.reply_icmp_code == 0);
    REQUIRE(reply.reply_mpls_labels.empty());
    REQUIRE(format_addr(reply.probe_dst_addr) == "2001:4860:4860::8888");
    REQUIRE(reply.probe_size == 0);
    REQUIRE(reply.probe_ttl == 8);
    REQUIRE(reply.probe_protocol == IPPROTO_ICMPV6);
    REQUIRE(reply.probe_src_port == 24000);
    REQUIRE(reply.probe_dst_port == 0);
    REQUIRE(reply.quoted_ttl == 0);
    REQUIRE(reply.rtt == 13);
    REQUIRE(!reply.is_destination_unreachable());
    REQUIRE(reply.is_echo_reply());
    REQUIRE(!reply.is_time_exceeded());
  }
}

// Replies to UDP probes.
TEST_CASE("Parser::parse/UDP") {
  SECTION("ICMP TTL Exceeded") {
    auto res = parse_file(data / "udp-icmp-ttl-exceeded.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(reply.capture_timestamp == 1613155487934429);
    REQUIRE(format_addr(reply.reply_src_addr) == "72.14.204.68");
    REQUIRE(format_addr(reply.reply_dst_addr) == "192.168.1.5");
    REQUIRE(reply.reply_size == 56);
    REQUIRE(reply.reply_ttl == 250);
    REQUIRE(reply.reply_protocol == IPPROTO_ICMP);
    REQUIRE(reply.reply_icmp_type == 11);
    REQUIRE(reply.reply_icmp_code == 0);
    REQUIRE(reply.reply_mpls_labels.empty());
    REQUIRE(format_addr(reply.probe_dst_addr) == "8.8.8.8");
    REQUIRE(reply.probe_size == 36);
    REQUIRE(reply.probe_ttl == 6);
    REQUIRE(reply.probe_protocol == IPPROTO_UDP);
    REQUIRE(reply.probe_src_port == 24000);
    REQUIRE(reply.probe_dst_port == 33434);
    REQUIRE(reply.quoted_ttl == 1);
    REQUIRE(reply.rtt == 83);
    REQUIRE(!reply.is_destination_unreachable());
    REQUIRE(!reply.is_echo_reply());
    REQUIRE(reply.is_time_exceeded());
  }

  SECTION("ICMPv6 TTL Exceeded") {
    auto res = parse_file(data / "udp-icmp6-ttl-exceeded.pcap");
    REQUIRE(res.size() == 1);

    auto reply = res[0];
    REQUIRE(reply.capture_timestamp == 1615987632702320);
    REQUIRE(format_addr(reply.reply_src_addr) == "2a04:8ec0:0:a::1:119");
    REQUIRE(format_addr(reply.reply_dst_addr) ==
            "2a04:8ec0:0:164:620c:e59a:daf8:21e9");
    REQUIRE(reply.reply_size == 60);
    REQUIRE(reply.reply_ttl == 63);
    REQUIRE(reply.reply_protocol == IPPROTO_ICMPV6);
    REQUIRE(reply.reply_icmp_type == 3);
    REQUIRE(reply.reply_icmp_code == 0);
    REQUIRE(reply.reply_mpls_labels.empty());
    REQUIRE(format_addr(reply.probe_dst_addr) == "2001:4860:4860::8888");
    REQUIRE(reply.probe_size == 12);
    REQUIRE(reply.probe_ttl == 2);
    REQUIRE(reply.probe_protocol == IPPROTO_UDP);
    REQUIRE(reply.probe_src_port == 24000);
    REQUIRE(reply.probe_dst_port == 33434);
    REQUIRE(reply.quoted_ttl == 1);
    REQUIRE(reply.rtt == 6);
    REQUIRE(!reply.is_destination_unreachable());
    REQUIRE(!reply.is_echo_reply());
    REQUIRE(reply.is_time_exceeded());
  }
}

// Non-IP data.
TEST_CASE("Parser::parse/Invalid") {
  SECTION("Non-IP") {
    auto res = parse_file(data / "arp.pcap");
    REQUIRE(res.empty());
  }
  SECTION("Null PDU") {
    uint8_t invalid_data[4] = {0x00, 0x01, 0x02, 0x03};
    Tins::RawPDU invalid_pdu = Tins::RawPDU(&invalid_data[0], 4);
    REQUIRE(!build_inner<Tins::IP>(nullptr));
    REQUIRE(!build_inner<Tins::IP>(&invalid_pdu));
    REQUIRE(!parse(Tins::Packet{}));
  }
}
