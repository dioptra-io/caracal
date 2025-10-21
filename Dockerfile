# Builder
FROM ubuntu:22.04 as builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install --no-install-recommends --quiet --yes \
    build-essential \
    cmake \
    ninja-build \
    python3-pip && \
    rm --force --recursive /var/lib/apt/lists/*

# hadolint ignore=DL3059
RUN python3 -m pip install --no-cache-dir "conan>=1.35,<2.0"

WORKDIR /tmp
COPY . .

# Run Conan install first to generate toolchain and install dependencies
RUN conan install . --build=missing -g CMakeToolchain -s compiler=gcc -s compiler.version=10 -s compiler.cppstd=20 -s build_type=Release

# Run CMake configure and build, passing the Conan toolchain explicitly
RUN cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake \
    -DWITH_BINARY=ON && \
    cmake --build build --target caracal-bin

# Main
FROM ubuntu:22.04
COPY --from=builder /tmp/build/caracal /usr/bin/caracal
ENTRYPOINT ["caracal"]
