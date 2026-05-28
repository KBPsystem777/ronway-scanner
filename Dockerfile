# syntax=docker/dockerfile:1

# ─── Builder ──────────────────────────────────────────────────────────────
# SQLite is compiled from source by sqlx's bundled libsqlite3-sys. The
# official Rust image already ships gcc/cc, so no extra build packages are
# needed. (No OpenSSL either — the scanner is rustls-only.)
FROM rust:1-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release --bin ronway

# ─── Runtime ──────────────────────────────────────────────────────────────
FROM debian:bookworm-slim
# ca-certificates lets the HTTP probe validate public TLS roots.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/ronway /usr/local/bin/ronway

# Scan history is written here — mount a volume at /data to keep it across
# container restarts/redeploys.
ENV RONWAY_DB_PATH=/data/ronway.db \
    RUST_LOG=ronway_scanner=info
VOLUME ["/data"]
EXPOSE 3001

ENTRYPOINT ["ronway"]
CMD ["serve", "--port", "3001"]
