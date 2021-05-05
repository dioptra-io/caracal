import logging
from ipaddress import ip_address

import pytest
from pycaracal import Probe, prober, protocols, set_log_level


@pytest.mark.asyncio
async def test_probe_async():
    # We observed some segfaults when pycaracal is called from async code
    # and log messages are emitted by the C++ code. Let's ensure that it
    # doesn't happen anymore.
    def gen():
        for _ in range(10_000):
            yield Probe(ip_address("127.0.0.1"), 24000, 33434, 32, protocols.L4.ICMP)

    logging.basicConfig(level=logging.DEBUG)
    set_log_level(logging.DEBUG)

    # TODO: Find the proper interface on GitHub actions
    # config = prober.Config()
    # config.set_interface("lo0")
    # config.set_probing_rate(10_000)
    # config.set_sniffer_wait_time(1)
    # prober.probe(config, gen())
