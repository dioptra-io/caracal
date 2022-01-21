# Builder
FROM ubuntu:20.04 as builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install --no-install-recommends --quiet --yes \
        build-essential \
        cmake \
        git \
        python3-dev \
        python3-pip && \
    rm --force --recursive /var/lib/apt/lists/*

# hadolint ignore=DL3059
RUN python3 -m pip install --no-cache-dir build conan>=1.35

COPY . /tmp

WORKDIR /tmp/build-release
RUN cmake -DCMAKE_BUILD_TYPE=Release -DWITH_LTO=ON .. && \
    cmake --build . --target caracal-bin --parallel 8

# Main
FROM ubuntu:20.04
COPY --from=builder /tmp/build-release/caracal /usr/bin/caracal
ENTRYPOINT ["caracal"]
