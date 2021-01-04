# Diamond-Miner Prober :gem:

![CI](https://github.com/dioptra-io/diamond-miner-prober/workflows/CI/badge.svg)
[![codecov](https://codecov.io/gh/dioptra-io/diamond-miner-prober/branch/master/graph/badge.svg?token=NJUZI5GM34)](https://codecov.io/gh/dioptra-io/diamond-miner-prober)
![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/matthieugouel/diamond-miner-prober?logo=docker)

## Quickstart

```bash
docker run matthieugouel/diamond-miner-prober --help
```

### Building from source

```bash
# Ubuntu
apt-get install build-essential cmake gcovr libboost-log-dev libboost-program-options-dev \
    libelf1 libpcap-dev libtins-dev pkg-config zlib1g-dev
# macOS
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
cmake -DCMAKE_BUILD_TYPE=Release && cmake --build .
# (Optional) Installation
cmake --install .
```

### TODO
- add a license (caution: libcperm and patricia are under GPLv3)
