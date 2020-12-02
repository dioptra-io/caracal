# Diamond-Miner Prober :gem:

![CI](https://github.com/dioptra-io/diamond-miner-prober/workflows/CI/badge.svg)
[![codecov](https://codecov.io/gh/dioptra-io/diamond-miner-prober/branch/master/graph/badge.svg?token=NJUZI5GM34)](https://codecov.io/gh/dioptra-io/diamond-miner-prober)

**Repositories:** [diamond-miner-core](https://github.com/dioptra-io/diamond-miner-core) •
[diamond-miner-prober](https://github.com/dioptra-io/diamond-miner-prober) •
[diamond-miner-reader](https://github.com/dioptra-io/diamond-miner-reader)

## Quickstart

```bash
docker run matthieugouel/diamond-miner-prober --help
```

### Building from source

```bash
# Ubuntu: see the Dockerfile for the build dependencies.
# macOS:
brew install boost cmake gcovr libtins pkg-config
```

```bash
git clone --recursive git@github.com:dioptra-io/diamond-miner-prober.git
cd diamond-miner-prober
```

```bash
mkdir build && cd build
# Debug build
cmake .. && cmake --build .
# Release build
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_PF_RING=ON .. && cmake --build .
# (Optional) Installation
cmake --install .
```

### TODO
- add a license (caution: libcperm is under GPLv3)
