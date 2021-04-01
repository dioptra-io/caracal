# Diamond-Miner Prober :gem:

[![CI](https://img.shields.io/github/workflow/status/dioptra-io/diamond-miner-prober/CI?logo=github)](https://github.com/dioptra-io/diamond-miner-prober/actions?query=workflow%3ACI)
[![codecov](https://img.shields.io/codecov/c/github/dioptra-io/diamond-miner-prober?logo=codecov&logoColor=white)](https://codecov.io/gh/dioptra-io/diamond-miner-prober)
[![Documentation](https://img.shields.io/badge/documentation-online-blue.svg?logo=read-the-docs&logoColor=white)](https://dioptra-io.github.io/diamond-miner-prober/)
[![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/dioptraio/diamond-miner-prober?logo=docker&logoColor=white)](https://hub.docker.com/r/dioptraio/diamond-miner-prober/tags)
[![Docker Image Version (latest semver)](https://img.shields.io/docker/v/dioptraio/diamond-miner-prober?color=blue&label=image%20version&logo=docker&logoColor=white&sort=semver)](https://hub.docker.com/r/dioptraio/diamond-miner-prober/tags)

This is the prober component of [Diamond-Miner](https://www.usenix.org/conference/nsdi20/presentation/vermeulen). It is
a stateless ICMP/UDP IPv4/v6 Paris traceroute engine written in modern C++ achieving probing rates of 1M+ packets per second.

![Demonstration of the prober usage](data/cast.svg)

_NOTE: In this screencast, IPv6 addresses from replies are printed as 0.0.0.0, this will be fixed in a future version._

## Quickstart

```bash
docker run dioptraio/diamond-miner-prober --help
```

:warning: You may get incorrect results on Docker on macOS.
Docker and/or macOS seems to rewrite some fields of the IP header that we use to encode probe informations.

## NSDI 2020 paper

Diamond-Miner has been presented and published at [NSDI 2020](https://www.usenix.org/conference/nsdi20/presentation/vermeulen).
Since then, the code has been refactored and separated in the [diamond-miner-core](https://github.com/dioptra-io/diamond-miner-core) and [diamond-miner-prober](https://github.com/dioptra-io/diamond-miner-prober) repositories.
The code as it was at the time of the publication is available in the [`nsdi2020`](https://github.com/dioptra-io/diamond-miner-prober/releases/tag/nsdi2020) tag.

## Development

### Prerequisites

This program compiles on Linux, where it uses [`AF_PACKET`](https://man7.org/linux/man-pages/man7/packet.7.html) to send raw packets,
and on macOS, where it uses [`AF_NDRV`](http://newosxbook.com/bonus/vol1ch16.html).
It runs on x86-64 and ARM64 systems.

#### Build tools

To build this project, CMake, Conan, and a compiler implementing C++20 are required.
Optionnally, Doxygen can be used to generate the API documentation, and Gcovr to compute the test coverage.

```bash
# macOS
brew install cmake conan doxygen gcovr graphviz

# Ubuntu 20.04
add-apt-repository -u ppa:ubuntu-toolchain-r/ppa
apt install build-essential cmake doxygen gcovr graphviz gcc-10 g++-10
pip install conan

# Ubuntu 21.04+
apt install build-essential cmake doxygen gcovr graphviz
pip install conan
```

#### External dependencies

All the runtime dependencies are statically linked: they are either fetched with [Conan](https://conan.io) if available, or built from the sources in [`/extern`](/extern)).
The only exceptions are libc and libstdc++ which are dynamically linked.

### Building from source

```bash
git clone --recursive git@github.com:dioptra-io/diamond-miner-prober.git
cd diamond-miner-prober
mkdir build && cd build
conan install .. -s libtins:compiler.cppstd=11 ..
cmake .. && cmake --build .
```

#### Options

Option             | Default  | Description
:------------------|:---------|:------------
`CMAKE_BUILD_TYPE` | `Debug`  | Set to `Release` for a production build.
`WITH_COVERAGE`    | `OFF`    | Whether to enable code coverage report or not.
`WITH_LTO`         | `OFF`    | Whether to enable link time optimization or not.
`WITH_SANITIZER`   | `OFF`    | Whether to enable compiler sanitizers or not.

Use `-DOPTION=Value` to set an option.
For example: `cmake -DCMAKE_BUILD_TYPE=Release ..`

#### Targets

Target                 | Description
:----------------------|:-----------
`diamond-miner-prober` | Prober
`diamond-miner-reader` | PCAP parser
`diamond-miner-tests`  | Unit and performance tests

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

## Dependencies

This software is released under the MIT license, in accordance with the license of its dependencies.

Name                                             | License                                                               | Usage
-------------------------------------------------|-----------------------------------------------------------------------|------
[Boost](https://www.boost.org)                   | [Boost Software License 1.0](https://opensource.org/licenses/BSL-1.0) | Boost::program_options for CLI arguments parsing
[Catch2](https://github.com/catchorg/Catch2)     | [Boost Software License 1.0](https://opensource.org/licenses/BSL-1.0) | Unit tests and benchmarks
[libnetutils](https://android.googlesource.com/platform/system/core/+/master/libnetutils) | [Apache 2.0](https://opensource.org/licenses/Apache-2.0) | IP checksum computation
[liblpm](https://github.com/rmind/liblpm)        | [2-clause BSD](https://opensource.org/licenses/BSD-2-Clause)          | Longest-prefix matching
[libtins](https://github.com/mfontanini/libtins) | [2-clause BSD](https://opensource.org/licenses/BSD-2-Clause)          | Packet parsing
[spdlog](https://github.com/gabime/spdlog)       | [MIT](https://opensource.org/licenses/MIT)                            | Logging
