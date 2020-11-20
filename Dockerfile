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
        gcovr \
        libboost-log1.71-dev \
        libboost-program-options1.71-dev \
        libpcap0.8-dev \
        libtins-dev \
        pfring \
        pfring-dkms \
        pkg-config \
        zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# Clash between PF_RING `likely` macro and Boost::DateTime
RUN sed -i'bak' 's/static bool likely/static bool is_likely/g' \
    /usr/include/boost/date_time/special_values_parser.hpp && \
    sed -i'bak' 's/svp_type::likely/svp_type::is_likely/g' \
    /usr/include/boost/date_time/time_parsing.hpp

ADD . /tmp

RUN mkdir -p /tmp/build/debug && \
    cd /tmp/build/debug && \
    export CXXFLAGS="-fsanitize=undefined" && \
    # export CXXFLAGS="-fsanitize=address -fsanitize=undefined" && \
    cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_PF_RING=ON -DWITH_TESTS=ON ../.. && \
    cmake --build . --parallel 8

RUN mkdir -p /tmp/build/release && \
    cd /tmp/build/release && \
    cmake -DCMAKE_BUILD_TYPE=Release -DWITH_PF_RING=ON ../.. && \
    cmake --build . --parallel 8

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

COPY --from=builder /tmp/build/release/diamond-miner-prober /app/diamond-miner-prober
ENTRYPOINT ["/app/diamond-miner-prober"]
