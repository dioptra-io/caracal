FROM ubuntu:bionic
WORKDIR /root/

RUN apt-get update
RUN apt-get -y install vim python3 python3-pip gnupg gcc g++ cmake libboost-all-dev git autoconf automake build-essential
RUN apt-get clean
RUN apt-get update
RUN apt-get -y install nginx

# PF RING
RUN apt-get update && \
    apt-get -y -q install wget lsb-release && \
    wget -q http://apt.ntop.org/16.04/all/apt-ntop.deb && dpkg -i apt-ntop.deb && \
    apt-get clean all && \
    apt-get update && \
    apt-get -y install pfring


# Libcperm
RUN git clone https://github.com/lancealt/libcperm.git
RUN cd libcperm && \
    ./autogen.sh && \
    ./configure && \
    make -j8 && \
    make install

# Clickhouse
RUN git clone https://github.com/artpaul/clickhouse-cpp.git
RUN cd clickhouse-cpp && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make -j8

#
#RUN git clone git@gitlab.planet-lab.eu:kevin/Heartbeat.git

# Libtins
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libpcap-dev libssl-dev

RUN git clone https://github.com/mfontanini/libtins.git
RUN cd libtins && \
    mkdir build && \
    cd build && \
    cmake .. -DLIBTINS_ENABLE_CXX11=1 && \
    make -j8 && \
    make install

RUN ldconfig

# Utilities
RUN apt-get install -y gdb traceroute rsync

ARG repository="deb http://repo.yandex.ru/clickhouse/deb/stable/ main/"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        apt-transport-https \
        dirmngr \
        gnupg \
    && mkdir -p /etc/apt/sources.list.d \
    && apt-key adv --keyserver keyserver.ubuntu.com --recv E0C56BD4 \
    && echo $repository > /etc/apt/sources.list.d/clickhouse.list \
    && apt-get update \
    && env DEBIAN_FRONTEND=noninteractive \
        apt-get install --allow-unauthenticated --yes --no-install-recommends \
            clickhouse-client \
            clickhouse-common-static \
            locales \
            tzdata \
    && rm -rf /var/lib/apt/lists/* /var/cache/debconf \
    && apt-get clean



RUN pip3 install paramiko
RUN pip3 install --pre scapy[complete]


RUN git clone https://github.com/alexandres/terashuf.git

RUN cd terashuf && make -j8 && cd ..

RUN export TMPDIR=/heartbeat/cartography/resources/ && export MEMORY=24


RUN mkdir .ssh/ && mkdir Heartbeat/
ADD .ssh/ .ssh/
ADD Heartbeat/ Heartbeat/
RUN mkdir Heartbeat/resources/

WORKDIR /root/Heartbeat

RUN mkdir build && \
    cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DPROBER=1 -DCENTRAL=1  && \
    make -j8

WORKDIR /root/

RUN mkdir Heartbeat-py/
ADD Heartbeat-py/ Heartbeat-py/
RUN rm -f /var/www/html/*
ADD index.html /var/www/html/index.html

WORKDIR /root/Heartbeat-py

ENTRYPOINT ["python3", "-u", "StochasticHeartbeat.py"]
CMD ["--help"]
