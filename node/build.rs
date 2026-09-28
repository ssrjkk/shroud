//! Generate the gRPC client/server for the peer mesh.
//!
//! Generation is unconditional rather than gated on the `grpc-server` feature. `build.rs`
//! cannot read the crate's own features through `cfg!`, only through `CARGO_FEATURE_*` in the
//! environment, and getting that wrong fails in a way that is very hard to read. Generating a
//! small amount of code that nobody calls is the cheaper mistake.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/mesh.proto";

    // Both paths are inputs; without these a stale generated file survives an edited .proto.
    println!("cargo:rerun-if-changed={proto}");
    println!("cargo:rerun-if-changed=build.rs");

    // Build scripts see features as environment variables, not as `cfg` flags.
    let want_server = std::env::var("CARGO_FEATURE_GRPC_SERVER").is_ok();
    println!("cargo:warning=building mesh codegen (server={want_server})");

    tonic_build::configure()
        .build_client(true)
        .build_server(want_server)
        .compile_protos(&[proto], &["proto"])?;

    Ok(())
}
