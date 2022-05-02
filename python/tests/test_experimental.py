import logging

from pycaracal import Probe, experimental, set_log_level, utilities


def test_prober():
    prober = experimental.Prober(
        utilities.get_default_interface(), 100, 1024 * 1024, 1, True
    )
    probes = [
        Probe("8.8.4.4", 24000, 33434, 32, "icmp", 0),
        Probe("8.8.4.4", 24000, 33434, 32, "udp", 0),
    ]
    set_log_level(logging.DEBUG)
    replies = prober.probe(probes, 1000)
    assert isinstance(replies, list)
