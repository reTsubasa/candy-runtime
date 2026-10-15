FROM rust:1.88-bookworm
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=3 -o Acquire::https::Timeout=30 update \
    && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 -o Acquire::https::Timeout=30 install -y --no-install-recommends \
       clang cmake libclang-dev ninja-build pkg-config libssl-dev \
       iproute2 iptables iperf3 iputils-ping jq python3 openssl sysstat ethtool \
    && rm -rf /var/lib/apt/lists/*
