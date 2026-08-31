ARG RUST_TOOLCHAIN_IMAGE=registry.internal.psalmond.com/ci-rust:sha-7747cd60
FROM ${RUST_TOOLCHAIN_IMAGE} AS builder
WORKDIR /build
COPY . ./
RUN cargo build --locked --release --workspace \
 && cd target/release \
 && sha256sum management-plane-sudo-approve management-plane-sudo-approve-server libplugin.so > SHA256SUMS

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime-linux
ARG OCI_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/epsalmond/management-plane" \
      org.opencontainers.image.revision="${OCI_REVISION}" \
      org.opencontainers.image.title="management-plane sudo approval server"
RUN groupadd --system sudo-approve \
 && useradd --system --gid sudo-approve --home-dir /var/lib/sudo-approve --create-home sudo-approve \
 && mkdir -p /opt/sudo-approve/bin /opt/sudo-approve/libexec/sudo /opt/sudo-approve/dist/v1/darwin-arm64 \
 && chown -R sudo-approve:sudo-approve /var/lib/sudo-approve
COPY --from=builder /build/target/release/management-plane-sudo-approve-server /opt/sudo-approve/bin/
COPY --from=builder /build/target/release/management-plane-sudo-approve /opt/sudo-approve/bin/
COPY --from=builder /build/target/release/libplugin.so /opt/sudo-approve/libexec/sudo/approval_exec.so
COPY --from=builder /build/target/release/SHA256SUMS /opt/sudo-approve/
COPY --from=builder /etc/ssl/certs/ /etc/ssl/certs/
USER sudo-approve
ENV SUDO_APPROVE_STATE_PATH=/var/lib/sudo-approve/state.sqlite3 \
    SUDO_APPROVE_DARWIN_DIST=/opt/sudo-approve/dist/v1/darwin-arm64 \
    SUDO_APPROVE_LISTEN=0.0.0.0:8443
EXPOSE 8443
ENTRYPOINT ["/opt/sudo-approve/bin/management-plane-sudo-approve-server"]

FROM runtime-linux AS runtime
ARG DARWIN_ARTIFACT_DIGEST
LABEL com.psalmond.sudo-approve.darwin-artifact-digest="${DARWIN_ARTIFACT_DIGEST}"
COPY dist/v1/darwin-arm64/ /opt/sudo-approve/dist/v1/darwin-arm64/
