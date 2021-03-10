# Builder
FROM ubuntu:20.04 as builder

ENV CC=gcc-10 CXX=g++-10
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y -q --no-install-recommends \
    software-properties-common && \
    rm -rf /var/lib/apt/lists/*

RUN add-apt-repository -u ppa:ubuntu-toolchain-r/ppa && \
    apt-get install -y -q --no-install-recommends \
        gcc-10 g++-10 && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && \
    apt-get install -y -q --no-install-recommends \
        build-essential \
        cmake \
        doxygen \
        gcovr \
        graphviz \
        libboost-program-options1.71-dev \
        libelf1 \
        libpcap0.8-dev \
        zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . /tmp

WORKDIR /tmp/build/debug
RUN cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_COVERAGE=ON -DWITH_SANITIZER=ON ../.. && \
    cmake --build . --target diamond-miner-tests --parallel 8 && \
    cmake --build . --target diamond-miner-docs

WORKDIR /tmp/build/release
RUN cmake -DCMAKE_BUILD_TYPE=Release -DWITH_LTO=ON ../.. && \
    cmake --build . --target diamond-miner-prober --parallel 8

# Main
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y -q --no-install-recommends \
        libboost-program-options1.71.0 \
        libc-bin \
        libelf1 \
        libpcap0.8 \
        zlib1g && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /tmp/build/release/diamond-miner-prober /usr/bin/diamond-miner-prober
ENTRYPOINT ["diamond-miner-prober"]
