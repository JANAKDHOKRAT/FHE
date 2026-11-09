#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
: "${OPENFHE_DIR:?Set OPENFHE_DIR to OpenFHE 1.3.1}"
export LD_LIBRARY_PATH="$OPENFHE_DIR/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-2}"
(cd port && python3 -m unittest -v)
cargo fmt --manifest-path port/pine-circuit/Cargo.toml -- --check
cargo clippy --release --locked --manifest-path port/pine-circuit/Cargo.toml --all-targets -- -D warnings
cargo test --release --locked --manifest-path port/pine-circuit/Cargo.toml -- --test-threads=1
