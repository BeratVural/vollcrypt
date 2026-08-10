# Vendored containerd-client provenance

- Upstream: `containerd/rust-extensions`, crate `containerd-client` 0.9.0
- Crates.io checksum: `814eedf2860b6df6e8002f917a0fbabf53bace3d3d9d2c2022661ae55a6ab6e4`
- License: Apache-2.0; the full text is retained as `LICENSE-APACHE`.
- Local change: `build.rs` selects `protoc-bin-vendored` 3.2 through
  `prost-build::Config::protoc_executable` so builds do not depend on a system
  `protoc` installation. Protocol definitions and generated API behavior are
  otherwise unchanged.

Review and refresh this snapshot explicitly when upgrading containerd API
bindings. Do not replace it from a floating branch or at runtime.
