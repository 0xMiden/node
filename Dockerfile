# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.98.1
ARG DEBIAN_RELEASE=trixie
ARG BIN
ARG PORT

FROM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS build-base
ARG TARGETARCH
# Code generation requires rustfmt.
RUN rustup component add rustfmt
# Install build dependencies. RocksDB is compiled from source by librocksdb-sys.
#
# Require a CA bundle that distrusts the compromised eMudhra certificate authorities.
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y --no-install-recommends \
        llvm \
        clang \
        libclang-dev \
        cmake \
        pkg-config \
        libssl-dev \
        curl \
        ca-certificates && \
    dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" \
        ge 20250419+deb13u1 && \
    rm -rf /var/lib/apt/lists/*

ENV CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_RELEASE_DEBUG=line-tables-only
WORKDIR /app

FROM build-base AS builder
ARG CARGO_BUILD_JOBS
ARG TARGETARCH
COPY Cargo.toml Cargo.lock ./
COPY .cargo/config.toml .cargo/config.toml
COPY bin/ bin/
COPY crates/ crates/
COPY proto/ proto/
# Cargo loads each workspace member before it selects the requested binaries.
COPY xtask/Cargo.toml xtask/Cargo.toml
COPY xtask/src/main.rs xtask/src/main.rs
COPY scripts/build-container-binaries.sh scripts/build-container-binaries.sh
RUN --mount=type=cache,sharing=locked,id=cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=locked,id=cargo-git-${TARGETARCH},target=/usr/local/cargo/git/db \
    bash scripts/build-container-binaries.sh && rm -rf /app/target

# Baseline runtime image with runtime dependencies installed.
#
# Require a CA bundle that distrusts the compromised eMudhra certificate authorities.
FROM debian:${DEBIAN_RELEASE}-slim AS runtime-base
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y --no-install-recommends \
        ca-certificates && \
    dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" \
        ge 20250419+deb13u1 && \
    rm -rf /var/lib/apt/lists/*
# Unprivileged runtime user. `/data` is created here so a first-use named
# volume mounted at `/data` inherits this ownership (Docker copies the image
# directory into a new named volume). Without that, the volume is root:root
# and the process cannot write.
RUN groupadd --gid 10001 miden && \
    useradd --uid 10001 --gid miden --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin miden && \
    mkdir -p /data && \
    chown miden:miden /data

FROM runtime-base AS runtime-common
ARG BIN
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
# Use exec to replace the shell so the binary runs as PID 1.
ENV MIDEN_BIN=${BIN}
CMD ["/bin/sh", "-c", "exec /usr/local/bin/$MIDEN_BIN"]
USER miden

# Command-line tools do not listen on a port.
FROM runtime-common AS runtime-tool

# Keep the default final target for the network's long-running services.
FROM runtime-common AS runtime
ARG PORT
EXPOSE ${PORT}
