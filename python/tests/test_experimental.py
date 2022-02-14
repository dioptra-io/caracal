import logging
from ipaddress import ip_address

from pycaracal import Probe, experimental, protocols, set_log_level, utilities


def test_prober():
    prober = experimental.Prober(
        utilities.get_default_interface(), 100, 1024 * 1024, 1, True
    )
    probes = [
        Probe(ip_address("8.8.4.4"), 24000, 33434, 32, protocols.L4.ICMP),
        Probe(ip_address("8.8.4.4"), 24000, 33434, 32, protocols.L4.UDP),
    ]
    set_log_level(logging.DEBUG)
    replies = prober.probe(probes, 0)
    assert isinstance(replies, list)
