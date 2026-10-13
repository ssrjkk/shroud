# Shroud compute node.
#
# Multi-stage: build with protoc + rust in the first stage, run from a slim image. The node folds
# the `CipherTask` event log and runs the finalize/settle/dispute/payment path, optionally serving
# the peer mesh; it is configured entirely through `CM_*` environment variables, so one image
# serves sequencer-attached workers and dispute re-executors alike. FHE execution and the STARK
# prover are not compiled in, so a default build does not pull the `tfhe`/`winterfell` stack (see
# the `prover` feature in Cargo.toml).
FROM rust:1.98 AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

# Compile the dependency tree once, before the real source, so unrelated edits do not rebuild the
# world. Both a stub lib and a stub bin are required: Cargo.toml declares a `[[bin]]` at
# src/main.rs, and `cargo build` fails outright when a declared target's source file is missing —
# a stub lib.rs alone is not enough.
COPY node/Cargo.toml node/Cargo.lock ./
COPY node/build.rs ./
COPY node/proto ./proto/
RUN mkdir -p src \
  && touch src/lib.rs \
  && printf 'fn main() {}\n' > src/main.rs \
  && cargo build --release \
  && rm -rf src

COPY node/ .
RUN cargo build --release --bin shroud-node

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/shroud-node /usr/local/bin/shroud-node

EXPOSE 7331
ENTRYPOINT ["shroud-node"]
