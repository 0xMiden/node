FROM rust:1.93-slim-bookworm AS chef
# Install build dependencies. RocksDB is compiled from source by librocksdb-sys.
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y \
        llvm \
        clang \
        libclang-dev \
        cmake \
        pkg-config \
        libssl-dev \
        libsqlite3-dev \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --release --locked --bin miden-validator

# Base line runtime image with runtime dependencies installed.
FROM debian:bookworm-slim AS runtime-base
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y --no-install-recommends sqlite3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

FROM runtime-base AS runtime
COPY --from=builder /app/target/release/miden-validator /usr/local/bin/miden-validator
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

# Validator port is configurable via --url; 50101 is the default used in docker-compose.
EXPOSE 50101
CMD ["miden-validator"]
