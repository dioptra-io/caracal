# Diamond-Miner Prober :gem:

[![CI](https://img.shields.io/github/workflow/status/dioptra-io/diamond-miner-prober/CI?logo=github)](https://github.com/dioptra-io/diamond-miner-prober/actions?query=workflow%3ACI)
[![codecov](https://img.shields.io/codecov/c/github/dioptra-io/diamond-miner-prober?logo=codecov&logoColor=white)](https://codecov.io/gh/dioptra-io/diamond-miner-prober)
[![Documentation](https://img.shields.io/badge/documentation-online-blue.svg?logo=read-the-docs&logoColor=white)](https://dioptra-io.github.io/diamond-miner-prober/)
[![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/matthieugouel/diamond-miner-prober?logo=docker&logoColor=white)](https://hub.docker.com/r/matthieugouel/diamond-miner-prober)

This is the prober component of [Diamond-Miner](https://www.usenix.org/conference/nsdi20/presentation/vermeulen). It is
a stateless ICMP/UDP IPv4/v6 Paris traceroute engine written in modern C++ and targeting a probing rate of 100k+ packets per second.

## Quickstart

```bash
docker run matthieugouel/diamond-miner-prober --help
```

:warning: You may get incorrect results on Docker on macOS.
Docker and/or macOS seems to rewrite some fields of the IP header that we use to encode probe informations.

### Building from source

This program compiles only on Linux, where it uses [`AF_PACKET`](https://man7.org/linux/man-pages/man7/packet.7.html) to send raw packets,
and on macOS, where it uses [`AF_NDRV`](http://newosxbook.com/bonus/vol1ch16.html).
It runs on x86-64 and ARM systems.

Note that it has been specifically designed for Linux,
so you may get inferior performance on macOS (especially due to syscall costs).

```bash
# macOS
brew install cmake gcovr boost

# Ubuntu 21.04+
# (We require GCC 10+ for C++20 support)
apt-get install build-essential cmake gcovr libboost-program-options-dev \
    libelf1 libpcap-dev zlib1g-dev
```

```bash
git clone --recursive git@github.com:dioptra-io/diamond-miner-prober.git
cd diamond-miner-prober
mkdir build && cd build
cmake .. && cmake --build .
```

#### Options

Option  | Default  | Description
:-------|:---------|:------------
`CMAKE_BUILD_TYPE` | `Debug` | Set to `Release` for a production build.
`WITH_COVERAGE` | `OFF` | Whether to enable code coverage report or not.
`WITH_SANITIZER` | `OFF` | Whether to enable compiler sanitizers or not.

Use `-DOPTION=Value` to set an option.
For example: `cmake -DCMAKE_BUILD_TYPE=Release ..`

#### Targets

Target | Description
:------|:-----------
`diamond-miner-prober` | Prober
`diamond-miner-reader` | PCAP parser
`diamond-miner-tests`  | Unit tests
`diamond-miner-bench`  | Performance tests

To build a specific target, use `cmake --build . --target TARGET`.

## Citation

```bibtex
@inproceedings {DiamondMiner2020,
author = {Kevin Vermeulen and Justin P. Rohrer and Robert Beverly and Olivier Fourmaux and Timur Friedman},
title = {Diamond-Miner: Comprehensive Discovery of the Internet{\textquoteright}s Topology Diamonds },
booktitle = {17th {USENIX} Symposium on Networked Systems Design and Implementation ({NSDI} 20)},
year = {2020},
isbn = {978-1-939133-13-7},
address = {Santa Clara, CA},
pages = {479--493},
url = {https://www.usenix.org/conference/nsdi20/presentation/vermeulen},
publisher = {{USENIX} Association},
month = feb,
}
```

### TODO

- add a license (caution: patricia is under GPLv3)
