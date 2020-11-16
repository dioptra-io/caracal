# Builder
FROM ubuntu:20.04 as builder

ENV DEBIAN_FRONTEND=noninteractive

# TODO: Use stable builds?
RUN apt-get update && \
    apt-get install -y -q gnupg lsb-release wget && \
    wget -q http://apt.ntop.org/20.04/all/apt-ntop.deb && dpkg -i apt-ntop.deb && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && \
    apt-get install -y -q --no-install-recommends \
        build-essential \
        cmake \
        libboost-log1.71-dev \
        libboost-program-options1.71-dev \
        libpcap0.8-dev \
        libtins-dev \
        pfring \
        pfring-dkms \
        pkg-config \
        zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

ADD . /tmp

RUN mkdir /tmp/build && \
    cd /tmp/build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DWITH_PF_RING=ON .. && \
    cmake --build . --parallel 4

# Main
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y -q gnupg lsb-release wget && \
    wget -q http://apt.ntop.org/20.04/all/apt-ntop.deb && dpkg -i apt-ntop.deb && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && \
    apt-get install -y -q --no-install-recommends \
        libboost-log1.71.0 \
        libboost-program-options1.71.0 \
        libelf1 \
        libpcap0.8 \
        libtins4.0 \
        pfring \
        zlib1g && \
    rm -rf /var/lib/apt/lists/* && \
    # Remove unneeded sources installed by pfring
    rm -rf /usr/include && \
    rm -rf /usr/src && \
    rm -rf /usr/share/doc

COPY --from=builder /tmp/build/diamond-miner-prober /app/diamond-miner-prober
COPY --from=builder /tmp/build/diamond-miner-prober-tests /app/diamond-miner-prober-tests

ENTRYPOINT ["/app/diamond-miner-prober"]
