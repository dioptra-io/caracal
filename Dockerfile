FROM alpine:3 AS builder
ENV LDFLAGS=-static

# hadolint ignore=DL3018
RUN apk add --no-cache bash binutils cmake git gcc g++ linux-headers make ninja py3-pip && \
    python3 -m pip install --no-cache-dir build conan>=1.35

WORKDIR /tmp
COPY . .

RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DWITH_PYTHON=OFF -DWITH_TESTS=OFF && \
    cmake --build build --target caracal-bin && \
    strip build/caracal

FROM scratch
COPY --from=builder /tmp/build/caracal /usr/bin/caracal
ENTRYPOINT ["caracal"]
