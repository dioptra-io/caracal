from ipaddress import IPv4Address, IPv6Address

from ._pycaracal import *


def cast_addr(addr):
    if isinstance(addr, int):
        return addr.to_bytes(16, "big")
    if isinstance(addr, IPv6Address):
        return int(addr).to_bytes(16, "big")
    if isinstance(addr, IPv4Address):
        return (int(addr) + 0xFFFF00000000).to_bytes(16, "big")
