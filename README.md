# Diamond-Miner Prober :gem:

![CI](https://github.com/dioptra-io/diamond-miner-prober/workflows/CI/badge.svg)
[![codecov](https://codecov.io/gh/dioptra-io/diamond-miner-prober/branch/master/graph/badge.svg?token=NJUZI5GM34)](https://codecov.io/gh/dioptra-io/diamond-miner-prober)

**Repositories:** [diamond-miner-core](https://github.com/dioptra-io/diamond-miner-core) •
[diamond-miner-prober](https://github.com/dioptra-io/diamond-miner-prober) •
[diamond-miner-reader](https://github.com/dioptra-io/diamond-miner-reader)

## Quickstart

```bash
git clone --recursive git@github.com:dioptra-io/diamond-miner-prober.git
cd diamond-miner-prober
docker build -t diamond-miner-prober .
docker run diamond-miner-prober --help
```

### Building from source

```bash
# Ubuntu
apt-get install cmake libboost-program-options-dev libpcap-dev libtins-dev pkg-config zlib1g-dev
# macOS
brew install boost cmake libtins pkg-config
```

```bash
mkdir build && cd build
# Debug build
cmake .. && cmake --build .
# Release build
cmake -DWITH_PF_RING=ON -DCMAKE_BUILD_TYPE=Release .. && cmake --build .
# (Optional) Installation
cmake --install .
# (Optional) Packaging
cpack
```

### Development

```bash
clang-format --style=Google -i src/*
cpplint --filter=-build/c++11,-legal/copyright src/*
```

### TODO
- add a license (caution: libcperm is under GPLv3)
- add CLI flag to disable/enable PF_RING sender (if WITH_PF_RING)
