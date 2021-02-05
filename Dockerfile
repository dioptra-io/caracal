# Builder
FROM ubuntu:21.04 as builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y -q --no-install-recommends \
        build-essential \
        cmake \
        gcovr \
        libboost-program-options1.74-dev \
        libelf1 \
        libpcap0.8-dev \
        pkg-config \
        zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

ADD . /tmp

RUN mkdir -p /tmp/build/debug && \
    cd /tmp/build/debug && \
    cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_COVERAGE=ON -DWITH_SANITIZER=ON ../.. && \
    cmake --build . --target diamond-miner-tests --parallel 8

RUN mkdir -p /tmp/build/release && \
    cd /tmp/build/release && \
    cmake -DCMAKE_BUILD_TYPE=Release ../.. && \
    cmake --build . --target diamond-miner-prober --parallel 8

# Main
FROM ubuntu:21.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y -q --no-install-recommends \
        libboost-program-options1.74.0 \
        libelf1 \
        libpcap0.8 \
        zlib1g && \
    rm -rf /var/lib/apt/lists/* && \
    # Remove unneeded files
    rm -rf /usr/include && \
    rm -rf /usr/src && \
    rm -rf /usr/share/doc

COPY --from=builder /tmp/build/release/diamond-miner-prober /usr/bin/diamond-miner-prober
ENTRYPOINT ["diamond-miner-prober"]
