# Diamond-Miner Prober :gem:

![CI](https://github.com/dioptra-io/diamond-miner-prober/workflows/CI/badge.svg)

```bash
mkdir build && cd build
# Debug build
cmake .. && cmake --build .
# Release build
cmake -DUSE_PF_RING=ON -DCMAKE_BUILD_TYPE=Release .. && cmake --build .
```

```bash
clang-format --style=Google -i src/*
cpplint --filter=-build/c++11,-legal/copyright src/*
```

### TODO
- libcperm (GPLv3) license incompatibility.
- cmake -RELEASE?
- cmake project name and version (C headers)
- cpack / cmake install
- code format / linting
- proper file headers
