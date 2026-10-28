#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
source /workspace/fhe-deps/paper-env.sh
export OPENFHE_DIR=/workspace/fhe-deps/install-1.4.2 LD_LIBRARY_PATH=/workspace/fhe-deps/install-1.4.2/lib CARGO_TARGET_DIR=/workspace/fhe-build/count-port142
export OMP_NUM_THREADS=1 OMP_THREAD_LIMIT=1
cargo build --release --locked --manifest-path "$root/Cargo.toml"
c++ -std=c++17 -O3 -DMATHBACKEND=4 -I"$OPENFHE_DIR/include/openfhe" -I"$OPENFHE_DIR/include/openfhe/core" -I"$OPENFHE_DIR/include/openfhe/binfhe" "$root/boolean_count.cpp" -L"$OPENFHE_DIR/lib" -lOPENFHEbinfhe -lOPENFHEcore -o /workspace/fhe-validation/count-openfhe142-2026-10-28/boolean-count
