ARG RUST_IMAGE=rust:1.85-bookworm
FROM ${RUST_IMAGE} AS builder
WORKDIR /build
COPY . ./
RUN cargo build --locked --release --workspace \
 && cd target/release \
 && sha256sum sudo-approve sudo-approve-server libplugin.so > SHA256SUMS

FROM debian:bookworm-slim AS server
RUN apt-get update \
 && apt-get install --yes --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system sudo-approve \
 && useradd --system --gid sudo-approve --home-dir /var/lib/sudo-approve --create-home sudo-approve \
 && install -d -o sudo-approve -g sudo-approve -m 0750 /state
COPY --from=builder /build/target/release/sudo-approve-server /usr/local/bin/
USER sudo-approve
ENV SUDO_APPROVE_STATE_PATH=/state/state.sqlite3 \
    SUDO_APPROVE_LISTEN=0.0.0.0:8443
VOLUME ["/state"]
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/sudo-approve-server"]

FROM mcr.microsoft.com/playwright:v1.62.1-noble AS e2e
USER root
RUN apt-get update \
 && apt-get install --yes --no-install-recommends curl file openssl python3-cryptography sudo \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY --from=builder /build/target/release/sudo-approve /work/target/release/
COPY --from=builder /build/target/release/libplugin.so /work/target/release/
COPY --from=builder /build/target/release/SHA256SUMS /work/target/release/
COPY scripts/ /work/scripts/
COPY server/web/package.json server/web/package-lock.json /work/server/web/
RUN cd /work/server/web && npm ci
COPY server/web/ /work/server/web/
ENTRYPOINT ["/work/scripts/run-compose-e2e"]
