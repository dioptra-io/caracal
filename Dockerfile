# Builder
FROM ubuntu:20.04 as builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y -q --no-install-recommends \
        build-essential \
        cmake \
        doxygen \
        gcovr \
        git \
        graphviz \
        python3-dev \
        python3-pip && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir build conan>=1.35

COPY . /tmp

WORKDIR /tmp/build-debug
RUN cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_COVERAGE=ON -DWITH_SANITIZER=ON .. && \
    cmake --build . --target caracal-bin --parallel 8 && \
    cmake --build . --target caracal-docs

WORKDIR /tmp/build-release
RUN cmake -DCMAKE_BUILD_TYPE=Release -DWITH_LTO=ON .. && \
    cmake --build . --target caracal-bin --parallel 8

# Main
FROM ubuntu:20.04
COPY --from=builder /tmp/build-release/caracal /usr/bin/caracal
ENTRYPOINT ["caracal"]
