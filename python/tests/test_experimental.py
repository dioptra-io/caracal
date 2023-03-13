import logging

from pycaracal import Probe, prober, experimental, set_log_level, utilities


def test_prober():
    config = prober.Config()
    config.set_interface(utilities.get_default_interface())
    config.set_probing_rate(100)
    config.set_caracal_id(1)
    config.set_integrity_check(True)
    prober_exp = experimental.Prober(
        config, 1024 * 1024
    )
    probes = [
        Probe("8.8.4.4", 24000, 33434, 32, "icmp"),
        Probe("8.8.4.4", 24000, 33434, 32, "udp"),
    ]
    set_log_level(logging.DEBUG)
    replies = prober_exp.probe(probes, 1000)
    assert isinstance(replies, list)
