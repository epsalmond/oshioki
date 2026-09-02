ARG RUST_IMAGE=rust:1.85-bookworm
FROM ${RUST_IMAGE} AS builder
WORKDIR /build
COPY . ./
RUN cargo build --locked --release --workspace \
 && cd target/release \
 && sha256sum oshioki oshioki-agent oshioki-server liboshioki_plugin.so > SHA256SUMS

FROM debian:bookworm-slim AS server
RUN apt-get update \
 && apt-get install --yes --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system oshioki \
 && useradd --system --gid oshioki --home-dir /var/lib/oshioki --create-home oshioki \
 && install -d -o oshioki -g oshioki -m 0750 /state
COPY --from=builder /build/target/release/oshioki-server /usr/local/bin/
USER oshioki
ENV OSHIOKI_STATE_PATH=/state/state.sqlite3 \
    OSHIOKI_LISTEN=0.0.0.0:8443
VOLUME ["/state"]
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/oshioki-server"]

FROM mcr.microsoft.com/playwright:v1.62.1-noble AS e2e
USER root
RUN apt-get update \
 && apt-get install --yes --no-install-recommends curl file openssl python3-cryptography sudo \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY --from=builder /build/target/release/oshioki /work/target/release/
COPY --from=builder /build/target/release/oshioki-agent /work/target/release/
COPY --from=builder /build/target/release/liboshioki_plugin.so /work/target/release/
COPY --from=builder /build/target/release/SHA256SUMS /work/target/release/
COPY scripts/ /work/scripts/
COPY server/web/package.json server/web/package-lock.json /work/server/web/
RUN cd /work/server/web && npm ci
COPY server/web/ /work/server/web/
ENTRYPOINT ["/work/scripts/run-compose-e2e"]
