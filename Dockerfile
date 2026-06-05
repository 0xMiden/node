# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.93
ARG DEBIAN_RELEASE=bookworm
ARG BIN
ARG PORT

FROM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS chef
# Install build dependencies. RocksDB is compiled from source by librocksdb-sys.
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y --no-install-recommends \
        llvm \
        clang \
        libclang-dev \
        cmake \
        pkg-config \
        libssl-dev \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG BIN
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies while preserving Cargo artifacts across layer invalidations.
#
# Cache Cargo's git DB, but leave checkout worktrees ephemeral; shared checkout
# caches are fragile when concurrent CI builds race or a build is interrupted.
RUN --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=locked,target=/usr/local/cargo/git/db \
    --mount=type=cache,sharing=locked,target=/app/target \
    cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=locked,target=/usr/local/cargo/git/db \
    --mount=type=cache,sharing=locked,target=/app/target \
    cargo build --release --locked --bin ${BIN} && \
    mkdir -p /app/bin && \
    cp /app/target/release/${BIN} /app/bin/${BIN}

# Baseline runtime image with runtime dependencies installed.
FROM debian:${DEBIAN_RELEASE}-slim AS runtime-base
RUN apt-get update && \
    apt-get -y upgrade && \
    && rm -rf /var/lib/apt/lists/*

FROM runtime-base AS runtime
ARG BIN
ARG PORT
COPY --from=builder /app/bin/${BIN} /usr/local/bin/${BIN}
LABEL org.opencontainers.image.authors=devops@miden.team \
    org.opencontainers.image.url=https://0xMiden.github.io/ \
    org.opencontainers.image.documentation=https://github.com/0xMiden/node \
    org.opencontainers.image.source=https://github.com/0xMiden/node \
    org.opencontainers.image.vendor=Miden \
    org.opencontainers.image.licenses=MIT
ARG CREATED
ARG VERSION
ARG COMMIT
LABEL org.opencontainers.image.created=$CREATED \
    org.opencontainers.image.version=$VERSION \
    org.opencontainers.image.revision=$COMMIT
EXPOSE ${PORT}
# Use exec to replace the shell so the binary runs as PID 1.
ENV MIDEN_BIN=${BIN}
CMD ["/bin/sh", "-c", "exec /usr/local/bin/$MIDEN_BIN"]
