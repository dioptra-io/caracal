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
RUN python3 -m pip install --no-cache-dir build conan>=1.35

WORKDIR /tmp
COPY . .

RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DWITH_PYTHON=OFF -DWITH_TESTS=OFF && \
    cmake --build build --target caracal-bin

# Main
FROM ubuntu:22.04
COPY --from=builder /tmp/build/caracal /usr/bin/caracal
ENTRYPOINT ["caracal"]
