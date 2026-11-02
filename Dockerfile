# No `# syntax=` line: the Dockerfile frontend built into BuildKit covers
# everything used here, so no unpinned frontend image is pulled at build time.

# Builder: Rust 1.99 on Debian bookworm, pinned by digest.
FROM rust:1.99-bookworm@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS builder
WORKDIR /src
# Dependencies build in their own layer, from the manifests and Cargo.lock
# only, so the build cache reuses it until Cargo.lock changes. Each crate gets
# empty sources for this step. The vendored-openssl feature compiles OpenSSL
# from source and links it statically, so the runtime image needs no system
# libssl.
COPY Cargo.toml Cargo.lock ./
COPY crates/proto/Cargo.toml crates/proto/
COPY crates/broker/Cargo.toml crates/broker/build.rs crates/broker/
COPY crates/cli/Cargo.toml crates/cli/
# Cargo needs every workspace member's manifest to load the workspace. The demo
# stays this empty placeholder: .dockerignore keeps its sources out of the build
# context, and nothing here builds it (scripts/check-demo-not-shipped.sh).
COPY crates/demo/Cargo.toml crates/demo/
RUN mkdir -p crates/proto/src crates/broker/src crates/cli/src crates/demo/src \
    && : > crates/proto/src/lib.rs \
    && : > crates/broker/src/lib.rs \
    && echo 'fn main() {}' > crates/broker/src/main.rs \
    && echo 'fn main() {}' > crates/cli/src/main.rs \
    && echo 'fn main() {}' > crates/demo/src/main.rs \
    && cargo build --release --locked -p warden-broker --features vendored-openssl
COPY crates ./crates
# The placeholder build is removed first, so the real sources always compile,
# whatever their timestamps.
RUN cargo clean --release -p warden-broker -p warden-broker-proto \
    && cargo build --release --locked -p warden-broker --features vendored-openssl \
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
