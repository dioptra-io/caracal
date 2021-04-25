import logging
from ipaddress import ip_address

from pycaracal import Probe, prober, protocols, set_log_level


def test_probe():
    p1 = Probe(ip_address("8.8.4.4"), 24000, 33434, 32, protocols.L4.UDP)
    p2 = Probe(ip_address("::ffff:8.8.4.4"), 24000, 33434, 32, protocols.L4.UDP)
    p3 = Probe(int(ip_address("::ffff:8.8.4.4")), 24000, 33434, 32, protocols.L4.UDP)
    assert p1 == p2 == p3
    assert p1.dst_addr == ip_address("::ffff:8.8.4.4")
    assert p1.src_port == 24000
    assert p1.dst_port == 33434
    assert p1.ttl == 32
    assert p1.protocol == protocols.l4_from_string("udp")


def test_prober():
    config = prober.Config()
    config.set_output_file_csv("out.csv")
    config.set_sniffer_wait_time(0)
    probes = [
        Probe(ip_address("8.8.4.4"), 24000, 33434, 32, protocols.L4.ICMP),
        Probe(ip_address("8.8.8.8"), 24000, 33434, 32, protocols.L4.UDP),
        Probe(ip_address("8.8.8.8"), 24000, 33434, 32, protocols.L4.UDP),
    ]
    set_log_level(logging.DEBUG)
    prober_stats, sniffer_stats = prober.probe(config, probes)
    # TODO: Fix the last probe...
    assert prober_stats.read == 2


def test_logging():
    # TODO
    pass
