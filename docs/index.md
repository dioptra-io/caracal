# Introduction

Caracal is a stateless ICMP/UDP IPv4/v6 Paris traceroute and ping engine written in modern C++ with Python bindings.
It runs on BSD, Linux and macOS, on x86-64 and ARM64 systems.

Caracal reads probe specifications, sends the corresponding probe packets at the specified rate, parse the eventual replies and outputs them in CSV format.

## Features

- **Constant flow-id:** Caracal doesn't vary the flow identifier for two probes with the same specification, making it suitable to discover load-balanced paths on the Internet.
- **Fast:** Caracal uses the standard socket API, yet on a 2020 M1 MacBook Air it can send 1.3M packets per second. See [profiling](dev.md) for a discussion of possible performance improvements.
- **Stateless:** classical probing tools such as traceroute needs to remember which probes they have sent, in order to match the replies (e.g. to know the TTL of the probe). Caracal takes inspiration from [yarrp](https://github.com/cmand/yarrp) and encodes the probe information in the section of the probe packet that is included back in ICMP messages. Thus, it doesn't need to remember each probe sent, allowing it to send millions of probes per second with a minimal memory footprint.

## Installation

### Docker

The easiest way to run Caracal is through Docker:
```bash
docker run ghcr.io/dioptra-io/caracal --help
```

On macOS, please use [colima](https://github.com/abiosoft/colima) instead of Docker for Mac which mangles the IP header.

### Nix

If you're using the [Nix](https://nixos.org) package manager, you can use the following command:
```bash
nix run github:dioptra-io/caracal -- --help
```
