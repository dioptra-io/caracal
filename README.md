# Caracal

[![CI](https://img.shields.io/github/workflow/status/dioptra-io/caracal/CI?logo=github)](https://github.com/dioptra-io/caracal/actions?query=workflow%3ACI)
[![codecov](https://img.shields.io/codecov/c/github/dioptra-io/caracal?logo=codecov&logoColor=white)](https://codecov.io/gh/dioptra-io/caracal)
[![Documentation](https://img.shields.io/badge/documentation-online-blue.svg?logo=read-the-docs&logoColor=white)](https://dioptra-io.github.io/caracal/)
[![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/dioptraio/caracal?logo=docker&logoColor=white)](https://hub.docker.com/r/dioptraio/caracal/tags)
[![Docker Image Version (latest semver)](https://img.shields.io/docker/v/dioptraio/caracal?color=blue&label=image%20version&logo=docker&logoColor=white&sort=semver)](https://hub.docker.com/r/dioptraio/caracal/tags)

Caracal is a stateless ICMP/UDP IPv4/v6 Paris traceroute and ping engine written in modern C++ achieving probing rates of 1M+ packets per second.

![Demonstration of the prober usage](data/cast.svg)

## Quickstart

```bash
docker run dioptraio/caracal --help
```

:warning: You may get incorrect results on Docker on macOS.
Docker and/or macOS seems to rewrite some fields of the IP header that we use to encode probe informations.

## NSDI 2020 paper

Diamond-Miner has been presented and published at [NSDI 2020](https://www.usenix.org/conference/nsdi20/presentation/vermeulen).
Since then, the code has been refactored and separated in the [diamond-miner-core](https://github.com/dioptra-io/diamond-miner-core) and [caracal](https://github.com/dioptra-io/caracal) repositories.
The code as it was at the time of the publication is available in the [`nsdi2020`](https://github.com/dioptra-io/caracal/releases/tag/nsdi2020) tag.

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
apt install build-essential cmake doxygen gcovr git graphviz gcc-10 g++-10 python3-pip
pip3 install conan

# Ubuntu 21.04+
apt install build-essential cmake doxygen git gcovr graphviz python3-pip
pip3 install conan
```

#### External dependencies

All the runtime dependencies are statically linked: they are either fetched with [Conan](https://conan.io) if available, or built from the sources in [`/extern`](/extern)).
The only exceptions are libc and libstdc++ which are dynamically linked.

### Building from source

```bash
git clone --recursive git@github.com:dioptra-io/caracal.git
cd caracal
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
`caracal-bin`          | Prober
`caracal-read`         | PCAP parser
`caracal-test`         | Unit and performance tests

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
