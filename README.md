# :cat: Caracal

[![Coverage](https://img.shields.io/codecov/c/github/dioptra-io/caracal?logo=codecov&logoColor=white)](https://codecov.io/gh/dioptra-io/caracal)
[![Documentation](https://img.shields.io/badge/documentation-online-blue.svg?logo=read-the-docs&logoColor=white)](https://dioptra-io.github.io/caracal/)
[![Docker Status](https://img.shields.io/github/actions/workflow/status/dioptra-io/caracal/docker.yml?branch=main&logo=github&label=docker)](https://github.com/dioptra-io/caracal/actions/workflows/docker.yml)
[![PyPI Status](https://img.shields.io/github/actions/workflow/status/dioptra-io/caracal/pypi.yml?branch=main&logo=github&label=pypi)](https://github.com/dioptra-io/caracal/actions/workflows/pypi.yml)
[![Tests Status](https://img.shields.io/github/actions/workflow/status/dioptra-io/caracal/tests.yml?branch=main&logo=github&label=tests)](https://github.com/dioptra-io/caracal/actions/workflows/tests.yml)
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

On macOS, please use [colima](https://github.com/abiosoft/colima) instead of Docker for Mac which mangles the IP header.

### Nix

If you're using the [Nix](https://nixos.org) package manager, you can use the following command:
```bash
nix run github:dioptra-io/caracal -- --help
```

## Documentation

Please refer to the [documentation](https://dioptra-io.github.io/caracal/) for more information.

## Authors

Caracal is developed and maintained by the [Dioptra group](https://dioptra.io) at Sorbonne Université in Paris, France.
The initial version has been written by [Kévin Vermeulen](https://github.com/kvermeul), with subsequents refactoring and improvements by [Maxime Mouchet](https://github.com/maxmouchet) and [Matthieu Gouel](https://github.com/matthieugouel).

## License & Dependencies

This software is released under the [MIT license](/LICENSE), in accordance with the license of its dependencies.

Name                                             | License                                                               | Usage
-------------------------------------------------|-----------------------------------------------------------------------|------
[bxzstr](https://github.com/tmaklin/bxzstr)                   | [Mozilla Public License 2.0 (MPL-2.0)](https://opensource.org/licenses/MPL-2.0) | Compression and decompression
[Catch2](https://github.com/catchorg/Catch2)     | [Boost Software License 1.0](https://opensource.org/licenses/BSL-1.0) | Unit tests and benchmarks
[cxxopts](https://github.com/jarro2783/cxxopts)  | [MIT](https://opensource.org/licenses/MIT)                            | CLI arguments parsing
[liblpm](https://github.com/rmind/liblpm)        | [2-clause BSD](https://opensource.org/licenses/BSD-2-Clause)          | Longest-prefix matching
[libtins](https://github.com/mfontanini/libtins) | [2-clause BSD](https://opensource.org/licenses/BSD-2-Clause)          | Packet parsing
[pybind11](https://github.com/pybind/pybind11)   | [3-clause BSD](https://opensource.org/licenses/BSD-3-Clause)          | Python interface
[spdlog](https://github.com/gabime/spdlog)       | [MIT](https://opensource.org/licenses/MIT)                            | Logging
