# syntax=docker/dockerfile:1

FROM rust:1.88-bullseye AS builder
WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends libclang-dev python3-pip \
    && pip3 install --no-cache-dir "cmake>=3.22,<4" \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY apps ./apps
COPY vendor ./vendor

RUN cargo build --release -p serverd-linux

FROM debian:bookworm-slim AS runtime
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin candy \
    && mkdir -p /etc/candy \
    && chown candy:candy /etc/candy
COPY --from=builder /workspace/target/release/serverd-linux /usr/local/bin/serverd-linux
VOLUME ["/etc/candy"]
USER candy
EXPOSE 8443/udp
ENTRYPOINT ["/usr/local/bin/serverd-linux"]
CMD ["--config", "/etc/candy/server.toml"]
