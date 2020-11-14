FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y -q gnupg lsb-release wget && \
    wget -q http://apt.ntop.org/20.04/all/apt-ntop.deb && dpkg -i apt-ntop.deb && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && \
    apt-get install -y -q --no-install-recommends \
        build-essential \
        cmake \
        gdb \
        libboost-log1.71-dev \
        libboost-program-options1.71-dev \
        libpcap0.8-dev \
        libtins-dev \
        pfring \
        pfring-dkms \
        pkg-config \
        zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*
