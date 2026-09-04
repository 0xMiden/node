# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.98.1
ARG DEBIAN_RELEASE=trixie
ARG KACHE_VERSION=0.16.0
ARG BIN
ARG PORT

FROM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS build-base
ARG KACHE_VERSION
ARG TARGETARCH
# Used by our codegen code.
RUN rustup component add rustfmt
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
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Verify the release archive before Kache becomes a compiler wrapper.
RUN case "${TARGETARCH}" in \
        amd64) \
            KACHE_ARCH=x86_64; \
            KACHE_SHA256=caee657c662379475af2a0a7611ad32a6d053822036c1ec191bb8fd1c826d54b \
            ;; \
        arm64) \
            KACHE_ARCH=aarch64; \
            KACHE_SHA256=6eabb67867022eecdbfffe43c16e75b5c5b561983742bda3c900a4cb4c50e4a7 \
            ;; \
        *) \
            echo "Unsupported target architecture: ${TARGETARCH}" >&2; \
            exit 1 \
            ;; \
    esac && \
    KACHE_ARCHIVE="kache-${KACHE_ARCH}-unknown-linux-musl.tar.gz" && \
    curl --fail --location --silent --show-error \
        "https://github.com/kunobi-ninja/kache/releases/download/v${KACHE_VERSION}/${KACHE_ARCHIVE}" \
        --output "/tmp/${KACHE_ARCHIVE}" && \
    printf '%s  %s\n' "${KACHE_SHA256}" "/tmp/${KACHE_ARCHIVE}" | \
        sha256sum --check --strict && \
    tar -xzf "/tmp/${KACHE_ARCHIVE}" -C /usr/local/bin kache && \
    rm "/tmp/${KACHE_ARCHIVE}"

# These flags are stable build inputs. Kache must classify them before it can
# cache native objects from RocksDB and the other C and C++ dependencies.
RUN printf '%s\n' \
        '[cc]' \
        'extra_allowlist_flags = [' \
        '    "-fmerge-all-constants",' \
        '    "-mno-omit-leaf-frame-pointer",' \
        ']' \
        > /etc/kache.toml

ENV CARGO_INCREMENTAL=0 \
    RUSTC_WRAPPER=kache \
    CC="kache cc" \
    CXX="kache c++" \
    CC_KNOWN_WRAPPER_CUSTOM=kache \
    KACHE_BASE_DIR=/app \
    KACHE_CACHE_DIR=/var/cache/kache \
    KACHE_CONFIG=/etc/kache.toml \
    KACHE_AUTO_GC=true \
    KACHE_MAX_SIZE=30GiB \
    KACHE_RUNTIME_DIR=/tmp/kache-runtime
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
# Kache stores compiler outputs by content. The target directory stays local to
# this build and does not depend on source timestamps from another checkout.
# The locks prevent concurrent builds from writing to the same cache mounts.
#
# An interrupted build can leave a partially extracted crate in the cached
# registry (source dir present, `.cargo-ok` missing or empty). Cargo never
# recovers from this, so drop any such partial extraction before building.
# Use at most one Cargo job per 2 GiB of memory. Set CARGO_BUILD_JOBS to
# override the calculated limit.
RUN --mount=type=cache,sharing=locked,id=cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=locked,id=cargo-git-${TARGETARCH},target=/usr/local/cargo/git/db \
    --mount=type=cache,sharing=locked,id=kache-v1-${TARGETARCH},target=/var/cache/kache \
    if [ -d /usr/local/cargo/registry/src ]; then \
        find /usr/local/cargo/registry/src -mindepth 2 -maxdepth 2 -type d \
            '!' -exec test -s '{}/.cargo-ok' ';' -exec rm -rf '{}' +; \
    fi && \
    JOBS="${CARGO_BUILD_JOBS:-$(awk -v ncpu="$(nproc)" \
        '/MemTotal/ { j = int($2 / (2 * 1024 * 1024)); if (j < 1) j = 1; if (j > ncpu) j = ncpu; print j }' \
        /proc/meminfo)}" && \
    cargo build --release --locked --jobs "${JOBS}" \
        --bin miden-node \
        --bin miden-validator \
        --bin miden-note-transport \
        --bin miden-ntx-builder \
        --bin miden-network-monitor \
        --bin miden-remote-prover \
        --bin miden-benchmark && \
    mkdir -p /app/bin && \
    cp /app/target/release/miden-node \
        /app/target/release/miden-validator \
        /app/target/release/miden-note-transport \
        /app/target/release/miden-ntx-builder \
        /app/target/release/miden-network-monitor \
        /app/target/release/miden-remote-prover \
        /app/target/release/miden-benchmark \
        /app/bin/ && \
    kache report --format github --output /app/kache-report.md && \
    rm -rf /app/target && \
    kache gc

FROM scratch AS build-report
COPY --from=builder /app/kache-report.md /kache-report.md

# Baseline runtime image with runtime dependencies installed.
FROM debian:${DEBIAN_RELEASE}-slim AS runtime-base
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y --no-install-recommends \
        ca-certificates && \
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
