import logging
from ipaddress import ip_address
from pathlib import Path

from pycaracal import Probe, cast_addr, make_probe, prober, protocols, set_log_level


def test_probe():
    p1 = Probe(ip_address("8.8.4.4"), 24000, 33434, 32, protocols.L4.UDP)
    p2 = Probe(ip_address("::ffff:8.8.4.4"), 24000, 33434, 32, protocols.L4.UDP)
    p3 = Probe(int(ip_address("::ffff:8.8.4.4")), 24000, 33434, 32, protocols.L4.UDP)
    p4 = make_probe(cast_addr(ip_address("8.8.4.4")), 24000, 33434, 32, "udp")
    p5 = make_probe(cast_addr(ip_address("::ffff:8.8.4.4")), 24000, 33434, 32, "udp")
    p6 = make_probe(
        cast_addr(int(ip_address("::ffff:8.8.4.4"))), 24000, 33434, 32, "udp"
    )
    assert p1 == p2 == p3 == p4 == p5 == p6
    assert p1.dst_addr == ip_address("::ffff:8.8.4.4")
    assert p1.src_port == 24000
    assert p1.dst_port == 33434
    assert p1.ttl == 32
    assert p1.protocol == protocols.l4_from_string("udp")


def test_prober():
    config = prober.Config()
    config.set_output_file_csv("zzz_output.csv")
    config.set_sniffer_wait_time(1)
    probes = [
        Probe(ip_address("8.8.4.4"), 24000, 33434, 32, protocols.L4.ICMP),
        Probe(ip_address("8.8.4.4"), 24000, 33434, 32, protocols.L4.UDP),
        Probe(ip_address("8.8.4.4"), 24000, 33434, 32, protocols.L4.ICMP),
        Probe(ip_address("8.8.8.8"), 24000, 33434, 32, protocols.L4.UDP),
    ]
    set_log_level(logging.DEBUG)
    prober_stats, sniffer_stats = prober.probe(config, [])
    assert prober_stats.read == 0
    prober_stats, sniffer_stats = prober.probe(config, probes)
    assert prober_stats.read == 4
    assert prober_stats.sent == 4
    # This is flaky on GitHub Actions...
    # assert sniffer_stats.received_count >= 1
    input_file = Path("zzz_input.csv")
    input_file.write_text("\n".join(probe.to_csv() for probe in probes))
    prober_stats, sniffer_stats = prober.probe(config, str(input_file))
    assert prober_stats.read == 4
    assert prober_stats.sent == 4
