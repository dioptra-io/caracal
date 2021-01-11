# Builder
FROM ubuntu:20.04 as builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y -q --no-install-recommends \
        build-essential \
        cmake \
        gcovr \
        libboost-log1.71-dev \
        libboost-program-options1.71-dev \
        libelf1 \
        libpcap0.8-dev \
        libtins-dev \
        pkg-config \
        zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

ADD . /tmp

RUN mkdir -p /tmp/build/debug && \
    cd /tmp/build/debug && \
    cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_TESTS=ON ../.. && \
    cmake --build . --parallel 8

RUN mkdir -p /tmp/build/release && \
    cd /tmp/build/release && \
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ../.. && \
    cmake --build . --parallel 8

# Main
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y -q --no-install-recommends \
        libboost-log1.71.0 \
        libboost-program-options1.71.0 \
        libelf1 \
        libpcap0.8 \
        libtins4.0 \
        zlib1g && \
    rm -rf /var/lib/apt/lists/* && \
    # Remove unneeded files
    rm -rf /usr/include && \
    rm -rf /usr/src && \
    rm -rf /usr/share/doc

COPY --from=builder /tmp/build/release/diamond-miner-prober /usr/bin/diamond-miner-prober
ENTRYPOINT ["diamond-miner-prober"]
