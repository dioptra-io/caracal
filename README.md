# Caracal

[![CI](https://img.shields.io/github/workflow/status/dioptra-io/caracal/CI?logo=github)](https://github.com/dioptra-io/caracal/actions?query=workflow%3ACI)
[![codecov](https://img.shields.io/codecov/c/github/dioptra-io/caracal?logo=codecov&logoColor=white)](https://codecov.io/gh/dioptra-io/caracal)
[![Documentation](https://img.shields.io/badge/documentation-online-blue.svg?logo=read-the-docs&logoColor=white)](https://dioptra-io.github.io/caracal/)
[![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/dioptraio/caracal?logo=docker&logoColor=white)](https://hub.docker.com/r/dioptraio/caracal/tags)
[![Docker Image Version (latest semver)](https://img.shields.io/docker/v/dioptraio/caracal?color=blue&label=image%20version&logo=docker&logoColor=white&sort=semver)](https://hub.docker.com/r/dioptraio/caracal/tags)

Caracal is a stateless ICMP/UDP IPv4/v6 Paris traceroute and ping engine written in modern C++ achieving probing rates of 1M+ packets per second.
It runs on Linux and macOS, on x86-64 and ARM64 systems.

![Demonstration of the prober usage](data/cast.svg)

## Quickstart

The easiest way to run Caracal is through Docker:
```bash
docker run dioptraio/caracal --help
```

If you're running an ARM64 system, you will need to [build the image yourself](#docker-image).
If you're using macOS (Intel or ARM), we recommend to [build the native executable](#building-from-source) as Docker for Mac seems to rewrite some fields of the IP header that we use to encode probe informations.

## Features

- **Constant flow-id:** Caracal doesn't vary the flow identifier for two probes with the same specification, making it suitable to discover load-balanced paths on the Internet.
- **Fast:** Caracal uses the standard socket API, yet on a 2020 M1 MacBook Air it can send 1.3M packets per second. Work is underway to use [`PACKET_TX_RING`](https://www.kernel.org/doc/html/latest/networking/packet_mmap.html) on Linux to go above 1M packets per second. We do not plan to use [`PF_RING`](https://www.ntop.org/products/packet-capture/pf_ring/) as the standard version doesn't improve packet sending speed, and the Zero Copy (ZC) version is not free.
- **Stateless:** classical probing tools such as traceroute needs to remember which probes they have sent, in order to match the replies (e.g. to know the TTL of the probe). Caracal takes inspiration from [yarrp](https://github.com/cmand/yarrp) and encodes the probe information in the section of the probe packet that is included back in ICMP messages. Thus it doesn't need to remember each probe sent, allowing it to send millions of probes per second with a minimal memory footprint.

## Usage

Caracal reads probe specifications from the standard input or, if specified with `-i/--input-file`, from a file with one probe per line.
The specification is `dst_addr,src_port,dst_port,ttl,protocol`, where `dst_addr` can be an IPv4 address in dotted notation (e.g. `8.8.8.8`), an IPv4-mapped IPv6 address (e.g. `::ffff:8.8.8.8`) or an IPv6 address (e.g. `2001:4860:4860::8888`), and `protocol` is `icmp`, `icmp6` or `udp`.
For UDP probes, the ports are encoded directly in the UDP header. For ICMP probes, the source port is encoded in the ICMP checksum (which varies the flow-id).

For example, to probe Google DNS servers at TTL 32:
```csv
8.8.8.8,24000,33434,32,icmp
8.8.4.4,24000,33434,32,icmp
2001:4860:4860::8888,24000,33434,32,icmp
2001:4860:4860::8844,24000,33434,32,icmp
```
```bash
# Standard input
cat probes.txt | caracal
# File input
caracal -i probes.txt
```

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

# Ubuntu 20.04+
apt install build-essential cmake doxygen gcovr git graphviz python3-pip
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
cmake -DCMAKE_BUILD_TYPE=Debug .. && cmake --build .
```

#### Options

Option             | Default  | Description
:------------------|:---------|:------------
`CMAKE_BUILD_TYPE` | `Debug`  | Set to `Release` for a production build.
`WITH_CONAN`       | `ON`     | Whether to run `conan install` on configure or not.
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
`caracal-docs`         | API documentation
`_pycaracal`            | Python interface

To build a specific target, use `cmake --build . --target TARGET`.

### Docker image

To build the Docker image, simply run:
```bash
git clone --recursive git@github.com:dioptra-io/caracal.git
cd caracal
docker build -t caracal .
```

### Python interface

Caracal provides an experiment Python interface.
It is currently only used for internal projects, and we do not recommend its general use.
The extension is built using [pybind11](https://github.com/pybind/pybind11), [scikit-build](https://github.com/scikit-build/scikit-build).

To build the shared extension, use the `_pycaracal` target:
```bash
cmake --build . --target _pycaracal
# This will build _pycaracal.cpython-39-darwin.so, to test it:
python -c 'import _pycaracal'
```

To build the Python package (this will automatically build the `_pycaracal` target):
```bash
python3 -m pip install --upgrade build
python3 -m build
# The source distribution and the wheels are in dist/
```

To run the tests (this will automatically build and install the package in a virtualenv):
```bash
python3 -m pip install --upgrade tox
python3 -m tox
```

Running the tests with tox can be quite slow as tox is re-installing all the build dependencies in a temporary directory.
For quick testing, another solution is to symlink the shared library:
```bash
# Assuming the CMake build directory is build/
# In the repository root:
ln -s $(pwd)/build/_pycaracal*.so python/pycaracal/
# In python/ (must be run with python3 -m):
python3 -m pytest
```

The CI pipeline is managed by [cibuildwheel](https://github.com/joerick/cibuildwheel) in the [pypy.yml](.github/workflows/pypi.yml) workflow.
We build x86_64 Linux wheels for Python 3.8+, as well as universal (ARM64 + x86_64) macOS wheels for Python 3.9+.


## NSDI 2020 paper

Diamond-Miner has been presented and published at [NSDI 2020](https://www.usenix.org/conference/nsdi20/presentation/vermeulen).
Since then, the code has been refactored and separated in the [diamond-miner](https://github.com/dioptra-io/diamond-miner) and [caracal](https://github.com/dioptra-io/caracal) repositories.
The code as it was at the time of the publication is available in the [`nsdi2020`](https://github.com/dioptra-io/caracal/releases/tag/nsdi2020) tag.

## Authors

Caracal is developed and maintained by the [Dioptra team](https://dioptra.io) at Sorbonne Université in Paris, France.
The initial version has been written by [Kévin Vermeulen](https://github.com/kvermeul), with subsequents refactoring and improvements by [Maxime Mouchet](https://github.com/maxmouchet) and [Matthieu Gouel](https://github.com/matthieugouel).

## License & Dependencies

This software is released under the [MIT license](/LICENSE), in accordance with the license of its dependencies.

Name                                             | License                                                               | Usage
-------------------------------------------------|-----------------------------------------------------------------------|------
[Catch2](https://github.com/catchorg/Catch2)     | [Boost Software License 1.0](https://opensource.org/licenses/BSL-1.0) | Unit tests and benchmarks
[cxxopts](https://github.com/jarro2783/cxxopts)  | [MIT](https://opensource.org/licenses/MIT) | CLI arguments parsing
[libnetutils](https://android.googlesource.com/platform/system/core/+/master/libnetutils) | [Apache 2.0](https://opensource.org/licenses/Apache-2.0) | IP checksum computation
[liblpm](https://github.com/rmind/liblpm)        | [2-clause BSD](https://opensource.org/licenses/BSD-2-Clause)          | Longest-prefix matching
[libtins](https://github.com/mfontanini/libtins) | [2-clause BSD](https://opensource.org/licenses/BSD-2-Clause)          | Packet parsing
[pybind11](https://github.com/pybind/pybind11)   | [3-clause BSD](https://opensource.org/licenses/BSD-3-Clause)          | Python interface
[spdlog](https://github.com/gabime/spdlog)       | [MIT](https://opensource.org/licenses/MIT)                            | Logging
