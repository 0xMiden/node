# Miden proto build

This crate contains Protobuf files defining the Miden node gRPC API. The files are exposed via FileDescriptorSets to
simplify generation of Rust bindings.

It also contains the raw Protobuf files in the proto directory to be used for binding generation in other languages.

## Usage

To generate Miden node gRPC bindings in Rust, you'll need to add a `build.rs` file to your project. The example below
generates the RPC component bindings and writes them into the `src/generated` directory of your project.

```rust
use std::{fs, path::PathBuf, env};
use miden_node_proto_build::rpc_api_descriptor;
use anyhow::{Context, Result};

fn main() -> Result<()> {
    let crate_root: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
    let dst_dir = crate_root.join("src").join("generated");

    let _ = fs::remove_dir_all(&dst_dir);
    fs::create_dir(&dst_dir).unwrap();

    let file_descriptors = rpc_api_descriptor();

    let mut prost_config = prost_build::Config::new();
    prost_config.skip_debug(["AccountId", "Digest"]);

    tonic_build::configure()
        .out_dir(dst_dir)
        .build_server(false) // this setting generates only the client side of the rpc api
        .compile_fds_with_config(prost_config, file_descriptors)
        .context("compiling protobufs")?;

    Ok(())
}
```

### Enabling TLS for the RPC Client

To connect to the official RPC API, you need to enable TLS in your gRPC client. The easiest way to do this is by
enabling the `tls-native-roots` feature in the `tonic` crate. This ensures that your client automatically uses
system-native certificate roots without requiring additional configuration.

## Crate features

- `internal`: exposes Protobuf file descriptors for the internal components of the node. This is _not_ intended for
general use.

## License

This project is [MIT licensed](../../LICENSE).
