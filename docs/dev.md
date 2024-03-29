# Development

## Prerequisites

Caracal targets x86-64/ARM64 Linux/macOS systems.

In all the sections below, we assume that you have downloaded a copy of the repository:
```bash
git clone https://github.com/dioptra-io/caracal.git
cd caracal
```

### Build tools

To build this project, CMake, Conan, and a compiler implementing C++20 are required.
Optionally, Gcovr can be used to compute the test coverage.

```bash
# macOS
brew install cmake conan gcovr

# Ubuntu 20.04+
apt install build-essential cmake gcovr git pipx
pipx install conan
```

### External dependencies

All the runtime dependencies are statically linked: they are either fetched with [Conan](https://conan.io) if available,
or built from the sources in [`/extern`](https://github.com/dioptra-io/caracal/tree/main/extern).
The only exceptions are libc and libstdc++ which are dynamically linked.

## Building from source

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_BINARY=ON -DWITH_CONAN=ON ..
cmake --build .
```

### Options

Option             | Default  | Description
:------------------|:---------|:------------
`CMAKE_BUILD_TYPE` | `Debug`  | Set to `Release` for a production build.
`WITH_CONAN`       | `OFF`     | Whether to run `conan install` on configure or not.
`WITH_BINARY`      | `OFF`     | Whether to enable the `caracal-bin` target or not.
`WITH_TESTS`       | `OFF`     | Whether to enable the `caracal-test` target or not.

Use `-DOPTION=Value` to set an option.
For example: `cmake -DCMAKE_BUILD_TYPE=Release ..`

### Targets

Target          | Output                    | Description
:---------------|:--------------------------|:-----------
`caracal-bin`   | `caracal`                 | Prober
`caracal-test`  | `caracal-test`            | Unit and performance tests

To build a specific target, use `cmake --build . --target TARGET`.

## Docker image

To build the Docker image, simply run:
```bash
docker build -t caracal .
```

## Profiling

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
