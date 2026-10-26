# syntax=docker/dockerfile:1

# Builder: Rust 1.94 on Debian bookworm, pinned by digest.
FROM rust:1.94-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# The vendored-openssl feature compiles OpenSSL from source and links it
# statically, so the runtime image needs no system libssl. The cache mounts
# keep the registry and target directory between builds; the binary is
# copied out because the target mount is not part of the layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p warden-broker --features vendored-openssl \
    && install -D target/release/warden-server /out/warden-server
# Data directory for the database and audit log, owned by the runtime user.
RUN install -d -o 65532 -g 65532 -m 0700 /out/data

# Runtime: distroless, no shell, non-root (uid 65532), pinned by digest.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=builder /out/warden-server /warden-server
COPY --from=builder --chown=65532:65532 /out/data /data
VOLUME ["/data"]
USER nonroot
# There is no shell or curl in this image, so there is no HEALTHCHECK here:
# configure the orchestrator to run `/warden-server healthcheck` instead.
ENTRYPOINT ["/warden-server"]
CMD ["serve"]
