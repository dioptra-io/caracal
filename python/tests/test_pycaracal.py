import logging
from pathlib import Path

from pycaracal import Probe, log_to_stderr, prober, protocols, set_log_level


def test_probe():
    p1 = Probe("8.8.4.4", 24000, 33434, 32, protocols.L4.UDP)
    p2 = Probe("::ffff:8.8.4.4", 24000, 33434, 32, protocols.L4.UDP)
    p3 = Probe("::ffff:8.8.4.4", 24000, 33434, 32, protocols.L4.ICMP)
    assert (
        str(p1)
        == "Probe(dst_addr=8.8.4.4 src_port=24000 dst_port=33434 ttl=32 protocol=udp)"
    )
    assert p1 == p2 != p3


def test_protocol_from_string():
    assert protocols.l4_from_string("udp") == protocols.L4.UDP
    assert protocols.l4_from_string("icmp") == protocols.L4.ICMP
    assert protocols.l4_from_string("icmp6") == protocols.L4.ICMPv6


def test_prober():
    config = prober.Config()
    config.set_output_file_csv("zzz_output.csv")
    config.set_sniffer_wait_time(1)
    probes = [
        Probe("8.8.4.4", 24000, 33434, 32, protocols.L4.ICMP),
        Probe("8.8.4.4", 24000, 33434, 32, protocols.L4.UDP),
        Probe("8.8.8.8", 24000, 33434, 32, protocols.L4.ICMP),
        Probe("8.8.8.8", 24000, 33434, 32, protocols.L4.UDP),
    ]
    log_to_stderr()
    set_log_level(logging.DEBUG)
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
