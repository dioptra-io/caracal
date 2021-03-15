# Builder
FROM ubuntu:20.10 as builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y -q --no-install-recommends \
        build-essential \
        cmake \
        doxygen \
        gcovr \
        graphviz \
        python3-pip && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install conan && \
    conan profile new default --detect && \
    conan profile update settings.compiler.libcxx=libstdc++11 default

# Pre-build/fetch dependencies from conan
COPY conanfile.txt /tmp/conanfile.txt
RUN conan install --build=missing /tmp

# Build the rest of the project
COPY . /tmp

# Temporary hack until libtins 4.3 is available in Conan-Center.
RUN apt-get update && \
    apt-get install -y -q --no-install-recommends \
        libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/build-debug
RUN conan install .. && \
    cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_COVERAGE=ON -DWITH_SANITIZER=ON .. && \
    cmake --build . --target diamond-miner-tests --parallel 8 && \
    cmake --build . --target diamond-miner-docs

WORKDIR /tmp/build-release
RUN conan install .. && \
    cmake -DCMAKE_BUILD_TYPE=Release -DWITH_LTO=ON .. && \
    cmake --build . --target diamond-miner-prober --parallel 8

# Main
FROM ubuntu:20.10
COPY --from=builder /tmp/build-release/diamond-miner-prober /usr/bin/diamond-miner-prober
ENTRYPOINT ["diamond-miner-prober"]
