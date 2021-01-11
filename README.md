# Diamond-Miner Prober :gem:

![CI](https://github.com/dioptra-io/diamond-miner-prober/workflows/CI/badge.svg)
[![codecov](https://codecov.io/gh/dioptra-io/diamond-miner-prober/branch/master/graph/badge.svg?token=NJUZI5GM34)](https://codecov.io/gh/dioptra-io/diamond-miner-prober)
![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/matthieugouel/diamond-miner-prober?logo=docker)

## Quickstart

```bash
docker run matthieugouel/diamond-miner-prober --help
```

### Building from source

This program should compile on macOS, but it has been tuned for Linux, so do not expect to achieve a high throughput on macOS.

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
mkdir build && cd build
cmake .. && cmake --build .
```

### TODO
- add a license (caution: patricia is under GPLv3)
