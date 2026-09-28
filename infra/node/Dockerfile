# CipherMesh compute node.
#
# Multi-stage: build with protoc + rust in the first stage, run from a slim image. The node is a
# stateless watcher/prover/re-executor configured entirely by environment variables (CM_*), so a
# single image serves sequencer-attached workers, dispute re-executors, and provers.
FROM rust:1.94 AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

# Cache dependencies before the source, so unrelated edits do not rebuild the world.
COPY node/Cargo.toml node/Cargo.lock ./
COPY node/build.rs node/proto ./proto/
RUN mkdir -p src && echo "" > src/lib.rs \
  && cargo build --release --bin ciphermesh-node \
  && rm -f src/lib.rs

COPY node/ .
RUN cargo build --release --bin ciphermesh-node

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/ciphermesh-node /usr/local/bin/ciphermesh-node

EXPOSE 7331
ENTRYPOINT ["ciphermesh-node"]
