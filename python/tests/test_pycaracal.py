import logging
from ipaddress import IPv6Address
from pathlib import Path

from pycaracal import Probe, log_to_stderr, prober, set_log_format, set_log_level


def test_probe():
    p1 = Probe("8.8.4.4", 24000, 33434, 32, "udp", 0)
    p2 = Probe("::ffff:8.8.4.4", 24000, 33434, 32, "udp", 0)
    p3 = Probe("::ffff:8.8.4.4", 24000, 33434, 32, "icmp", 0)
    p4 = Probe(int(IPv6Address("::ffff:8.8.4.4")), 24000, 33434, 32, "icmp", 0)
    assert (
        str(p1)
        == "Probe(dst_addr=8.8.4.4 src_port=24000 dst_port=33434 ttl=32 protocol=udp wait_us=0)"
    )
    assert p1 == p2
    assert p2 != p3
    assert p3 == p4
    assert p1.dst_addr == "8.8.4.4"
    assert p1.src_port == 24000
    assert p1.dst_port == 33434
    assert p1.protocol == "udp"


def test_prober():
    config = prober.Config()
    config.set_output_file_csv("zzz_output.csv")
    config.set_sniffer_wait_time(1)
    probes = [
        Probe("8.8.4.4", 24000, 33434, 32, "icmp", 0),
        Probe("8.8.4.4", 24000, 33434, 32, "udp", 0),
        Probe("8.8.8.8", 24000, 33434, 32, "icmp", 0),
        Probe("8.8.8.8", 24000, 33434, 32, "udp", 0),
    ]
    log_to_stderr()
    set_log_level(logging.DEBUG)
    set_log_format("[%Y-%m-%d %H:%M:%S.%e] [%l] [caracal] %v")
    prober_stats, sniffer_stats, pcap_stats = prober.probe(config, [])
    assert prober_stats.read == 0
    assert pcap_stats.received >= sniffer_stats.received_count
    assert pcap_stats.dropped == 0
    assert pcap_stats.interface_dropped == 0
    prober_stats, sniffer_stats, pcap_stats = prober.probe(config, probes)
    assert prober_stats.read == 4
    assert prober_stats.sent == 4
    assert pcap_stats.received >= sniffer_stats.received_count
    assert pcap_stats.dropped == 0
    assert pcap_stats.interface_dropped == 0
    # This is flaky on GitHub Actions...
    # assert sniffer_stats.received_count >= 1
    input_file = Path("zzz_input.csv")
    input_file.write_text(
        """
8.8.4.4,24000,33434,32,icmp
8.8.4.4,24000,33434,32,udp
8.8.8.8,24000,33434,32,icmp
8.8.8.8,24000,33434,32,udp
    """.strip()
    )
    prober_stats, sniffer_stats, pcap_stats = prober.probe(config, str(input_file))
    assert prober_stats.read == 4
    assert prober_stats.sent == 4
    assert pcap_stats.received >= sniffer_stats.received_count
    assert pcap_stats.dropped == 0
    assert pcap_stats.interface_dropped == 0
