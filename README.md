# Diamond-Miner Prober :gem:

[![CI](https://github.com/dioptra-io/diamond-miner-prober/workflows/CI/badge.svg)](https://github.com/dioptra-io/diamond-miner-prober/actions?query=workflow%3ACI)
[![codecov](https://codecov.io/gh/dioptra-io/diamond-miner-prober/branch/master/graph/badge.svg?token=NJUZI5GM34)](https://codecov.io/gh/dioptra-io/diamond-miner-prober)
[![Documentation](https://img.shields.io/badge/docs-online-blue.svg)](https://dioptra-io.github.io/diamond-miner-prober/)
[![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/matthieugouel/diamond-miner-prober?logo=docker)](https://hub.docker.com/r/matthieugouel/diamond-miner-prober)

This is the prober component of [Diamond-Miner](https://www.usenix.org/conference/nsdi20/presentation/vermeulen). It is
a stateless ICMP/UDP/TCP traceroute engine written in C++ and targeting a probing rate of 100k+ packets per second.

## Quickstart

```bash
docker run matthieugouel/diamond-miner-prober --help
```

### Building from source

This program should compile on macOS, but it has been tuned for Linux, so do not expect to achieve a high throughput on
macOS.

```bash
# Ubuntu 21.04+
# (We require GCC 10+ for C++20 support)
apt-get install build-essential cmake gcovr libboost-log-dev libboost-program-options-dev \
    libelf1 libpcap-dev libtins-dev pkg-config zlib1g-dev
# macOS
brew install boost cmake gcovr libtins pkg-config
```

```bash
git clone --recursive git@github.com:dioptra-io/diamond-miner-prober.git
cd diamond-miner-prober
mkdir build && cd build
cmake .. && cmake --build .
```

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

- IPv6 support
- add a license (caution: patricia is under GPLv3)
