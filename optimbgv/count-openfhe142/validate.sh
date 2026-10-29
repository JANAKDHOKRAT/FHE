#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
cd "$root"
source /workspace/fhe-deps/paper-env.sh
export OPENFHE_DIR=/workspace/fhe-deps/install-1.4.2
export LD_LIBRARY_PATH="$OPENFHE_DIR/lib"
export CARGO_TARGET_DIR=/workspace/fhe-build/count-port142
export OMP_NUM_THREADS=1 OMP_THREAD_LIMIT=1 RUST_TEST_THREADS=1
cargo test --release --locked --manifest-path openfhe-tbgv-rs/Cargo.toml -- --test-threads=2
cargo test --release --locked --manifest-path fhe-prio3/Cargo.toml -- --test-threads=1
cargo test --release --locked --manifest-path fhe-paper-core/Cargo.toml --test count142 --test count_algebra --test count_boundary_attacks --test count_scope -- --test-threads=1
