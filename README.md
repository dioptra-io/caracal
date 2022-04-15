# :cat: Caracal

[![Coverage](https://img.shields.io/codecov/c/github/dioptra-io/caracal?logo=codecov&logoColor=white)](https://codecov.io/gh/dioptra-io/caracal)
[![Docker Status](https://img.shields.io/github/workflow/status/dioptra-io/caracal/Docker?logo=github&label=docker)](https://github.com/dioptra-io/caracal/actions/workflows/docker.yml)
[![PyPI Status](https://img.shields.io/github/workflow/status/dioptra-io/caracal/PyPI?logo=github&label=pypi)](https://github.com/dioptra-io/caracal/actions/workflows/pypi.yml)
[![Tests Status](https://img.shields.io/github/workflow/status/dioptra-io/caracal/Tests?logo=github&label=tests)](https://github.com/dioptra-io/caracal/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/pycaracal?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/pycaracal/)

Caracal is a stateless ICMP/UDP IPv4/v6 Paris traceroute and ping engine written in modern C++ with Python bindings.
It runs on BSD, Linux and macOS, on x86-64 and ARM64 systems.


Caracal reads probe specifications, sends the corresponding probe packets at the specified rate, parse the eventual replies and outputs them in CSV format.

![Demonstration of the prober usage](data/cast.svg)

## Quickstart

### Docker

The easiest way to run Caracal is through Docker:
```bash
docker run ghcr.io/dioptra-io/caracal --help
```

If you're using macOS, we recommend to [build the native executable](#building-from-source) as Docker for Mac
seems to rewrite the IP header fields where we encode probe information.

### Nix

If you're using the [Nix](https://nixos.org) package manager, you can use the following command:
```bash
nix run github:dioptra-io/caracal -- --help
```

## Features

- **Constant flow-id:** Caracal doesn't vary the flow identifier for two probes with the same specification, making it suitable to discover load-balanced paths on the Internet.
- **Fast:** Caracal uses the standard socket API, yet on a 2020 M1 MacBook Air it can send 1.3M packets per second. See [Potential optimizations](#potential-optimizations) for a discussion of possible performance improvements.
- **Stateless:** classical probing tools such as traceroute needs to remember which probes they have sent, in order to match the replies (e.g. to know the TTL of the probe). Caracal takes inspiration from [yarrp](https://github.com/cmand/yarrp) and encodes the probe information in the section of the probe packet that is included back in ICMP messages. Thus, it doesn't need to remember each probe sent, allowing it to send millions of probes per second with a minimal memory footprint.

## Usage

Caracal reads probe specifications from the standard input or, if specified with `-i/--input-file`, from a file with one probe per line.  
It outputs the replies in CSV format on the standard output or, if specified with `-o/--output-file-csv`, to a file with one reply per line.
If the file name ends with `.zst` the output will be compressed on-the-fly with [Zstandard](https://facebook.github.io/zstd/).  
In addition, if `--output-file-pcap` is specified, the raw captured frames will be written to the specified file in PCAP format.  
Log messages are printed on the standard error stream.

The specification is `dst_addr,src_port,dst_port,ttl,protocol`, where `dst_addr` can be an IPv4 address in dotted notation (e.g. `8.8.8.8`),
an IPv4-mapped IPv6 address (e.g. `::ffff:8.8.8.8`) or an IPv6 address (e.g. `2001:4860:4860::8888`), and `protocol` is `icmp`, `icmp6` or `udp`.  
For UDP probes, the ports are encoded directly in the UDP header. For ICMP probes, the source port is encoded in the ICMP checksum (which varies the flow-id).

For example, to probe Google DNS servers at TTL 32:
```csv
8.8.8.8,24000,33434,32,icmp
8.8.4.4,24000,33434,32,icmp
2001:4860:4860::8888,24000,33434,32,icmp
2001:4860:4860::8844,24000,33434,32,icmp
```
```bash
# Standard input/output
cat probes.txt | caracal > replies.csv
# File input/output
caracal -i probes.txt -o replies.csv
```

### Integration with standard tools

It is easy to integrate caracal with standard UNIX tools by taking advantage of the standard input/output.
For example, to store the replies in a SQLite database:
```bash
echo "8.8.8.8,24000,33434,64,icmp" | caracal | sqlite3 caracal.db ".import --csv /dev/stdin replies"
sqlite3 -header caracal.db "SELECT * FROM replies"
# capture_timestamp|probe_protocol|probe_src_addr|probe_dst_addr|probe_src_port|probe_dst_port|probe_ttl|quoted_ttl|reply_src_addr|reply_protocol|reply_icmp_type|reply_icmp_code|reply_ttl|reply_size|reply_mpls_labels|rtt|round
# 1638618261|1|::ffff:10.17.0.137|::|24000|0|64|0|::ffff:8.8.8.8|1|0|0|107|94|[]|564|1
```

### Reply integrity

Caracal encodes in the ID field of the IP header the following checksum: `ip_checksum(caracal_id, dst_addr, src_port, ttl)`.
This allows caracal to check that the reply it gets corresponds (excluding checksum collisions) to valid probes.

By default, replies for which the checksum in the ID field is invalid are dropped, this can be overridden with the
`--no-integrity-check` flag.
Furthermore, the `caracal_id` value can be changed with the `--caracal-id` option.

Invalid replies are never dropped from the PCAP file (`--output-file-pcap`), which can be useful for debugging.

## Development

### Prerequisites

This program compiles on Linux, where it uses [`AF_PACKET`](https://man7.org/linux/man-pages/man7/packet.7.html) to send raw packets,
and on macOS, where it uses [`AF_NDRV`](http://newosxbook.com/bonus/vol1ch16.html).
It runs on x86-64 and ARM64 systems.

In all the section below, we assume that you have downloaded a copy of the repository:
```bash
git clone --recursive https://github.com/dioptra-io/caracal.git
cd caracal
```

#### Build tools

To build this project, CMake, Conan, and a compiler implementing C++20 are required.
Optionally, Gcovr can be used to compute the test coverage.

```bash
# macOS
brew install cmake conan gcovr graphviz

# Ubuntu 20.04+
apt install build-essential cmake gcovr git graphviz python3-dev python3-pip
pip3 install conan

# Executables installed by Python are not in the path by default on Ubuntu.
# If `conan` is not found, run:
export PATH="${HOME}/.local/bin:${PATH}"
```

#### External dependencies

All the runtime dependencies are statically linked: they are either fetched with [Conan](https://conan.io) if available,
or built from the sources in [`/extern`](/extern).
The only exceptions are libc and libstdc++ which are dynamically linked.

### Building from source

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
```

#### Options

Option             | Default  | Description
:------------------|:---------|:------------
`CMAKE_BUILD_TYPE` | `Debug`  | Set to `Release` for a production build.
`WITH_CONAN`       | `ON`     | Whether to run `conan install` on configure or not.
`WITH_BINARY`      | `ON`     | Whether to enable the `caracal-bin` target or not.
`WITH_PYTHON`      | `ON`     | Whether to enable the `_pycaracal` target or not.
`WITH_TESTS`       | `ON`     | Whether to enable the `caracal-test` target or not.

Use `-DOPTION=Value` to set an option.
For example: `cmake -DCMAKE_BUILD_TYPE=Release ..`

#### Targets

Target          | Output                    | Description
:---------------|:--------------------------|:-----------
`caracal-bin`   | `caracal`                 | Prober
`caracal-test`  | `caracal-test`            | Unit and performance tests
`_pycaracal`    | ` _pycaracal*.so`         | Python interface

To build a specific target, use `cmake --build . --target TARGET`.

### :whale2: Docker image

To build the Docker image, simply run:
```bash
docker build -t caracal .
```

### :snake: Python interface

Caracal provides an experiment Python interface.
It is currently only used for internal projects, and we do not recommend its general use.
The extension is built using [pybind11](https://github.com/pybind/pybind11), [scikit-build](https://github.com/scikit-build/scikit-build).

To build the shared extension, use the `_pycaracal` target:
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build . --target _pycaracal
# This will build _pycaracal*.so, to test it:
python -c 'import _pycaracal'
```

To build the Python package (this will automatically build the `_pycaracal` target):
```bash
python3 -m pip install --upgrade build
python3 -m build
# The source distribution and the wheels are in dist/
```

To run the tests:
```bash
# Assuming the CMake build directory is build/
# In the repository root:
ln -s $(pwd)/build/_pycaracal*.so python/pycaracal/
# In python/ (must be run with python3 -m):
python3 -m pytest
```

The CI pipeline is managed by [cibuildwheel](https://github.com/joerick/cibuildwheel) in the [pypy.yml](.github/workflows/pypi.yml) workflow.
We build x86_64 Linux wheels for Python 3.8+, as well as universal (ARM64 + x86_64) macOS wheels for Python 3.9+.

## Potential optimizations

Caracal is easily profiled using [perf](http://www.brendangregg.com/perf.html) on Linux.
Currently, the main bottleneck is the socket, as demonstrated below.

```bash
# Generate 1M probes towards TEST-NET-1
yes "192.0.2.1,24000,33434,32,icmp" | head -n 1000000 > probes.txt
sudo perf record -g ./caracal --rate-limiting-method=none -i probes.txt
sudo perf report
# +   68.09%    12.33%  caracal  libpthread-2.31.so   [.] __libc_sendto
# +   56.63%     0.00%  caracal  [kernel.kallsyms]    [k] entry_SYSCALL_64_after_hwframe
# +   56.24%     4.51%  caracal  [kernel.kallsyms]    [k] do_syscall_64
# +   51.10%     0.38%  caracal  [kernel.kallsyms]    [k] __x64_sys_sendto
# +   50.49%     0.52%  caracal  [kernel.kallsyms]    [k] __sys_sendto
# +   47.37%     0.18%  caracal  [kernel.kallsyms]    [k] sock_sendmsg
# +   46.13%     0.39%  caracal  [kernel.kallsyms]    [k] packet_sendmsg
# +   45.36%     1.16%  caracal  [kernel.kallsyms]    [k] packet_snd
# +   30.83%     0.34%  caracal  [kernel.kallsyms]    [k] dev_queue_xmit
# +   30.22%     1.19%  caracal  [kernel.kallsyms]    [k] __dev_queue_xmit
# +   23.42%     0.27%  caracal  [kernel.kallsyms]    [k] sch_direct_xmit
# +   15.59%     0.49%  caracal  [kernel.kallsyms]    [k] dev_hard_start_xmit
# ...
```

A version using `TX_RING` on Linux is available in the [`ring_socket_v2`](https://github.com/dioptra-io/caracal/tree/ring_socket_v2)
branch, but it doesn't show any noticeable performance improvement.
To increase the probing rate, we would potentially need to resort to a zero-copy solution such as
[PF_RING ZC](https://www.ntop.org/products/packet-capture/pf_ring/pf_ring-zc-zero-copy/).

## Authors

Caracal is developed and maintained by the [Dioptra group](https://dioptra.io) at Sorbonne Université in Paris, France.
The initial version has been written by [Kévin Vermeulen](https://github.com/kvermeul), with subsequents refactoring and improvements by [Maxime Mouchet](https://github.com/maxmouchet) and [Matthieu Gouel](https://github.com/matthieugouel).

## License & Dependencies

This software is released under the [MIT license](/LICENSE), in accordance with the license of its dependencies.

Name                                             | License                                                               | Usage
-------------------------------------------------|-----------------------------------------------------------------------|------
[Boost](https://www.boost.org)                   | [Boost Software License 1.0](https://opensource.org/licenses/BSL-1.0) | Boost::iostreams from compression and decompression
[Catch2](https://github.com/catchorg/Catch2)     | [Boost Software License 1.0](https://opensource.org/licenses/BSL-1.0) | Unit tests and benchmarks
[cxxopts](https://github.com/jarro2783/cxxopts)  | [MIT](https://opensource.org/licenses/MIT)                            | CLI arguments parsing
[liblpm](https://github.com/rmind/liblpm)        | [2-clause BSD](https://opensource.org/licenses/BSD-2-Clause)          | Longest-prefix matching
[libtins](https://github.com/mfontanini/libtins) | [2-clause BSD](https://opensource.org/licenses/BSD-2-Clause)          | Packet parsing
[pybind11](https://github.com/pybind/pybind11)   | [3-clause BSD](https://opensource.org/licenses/BSD-3-Clause)          | Python interface
[spdlog](https://github.com/gabime/spdlog)       | [MIT](https://opensource.org/licenses/MIT)                            | Logging
