#!/usr/bin/env bash
# Source this file. Install the external OpenFHE 1.4.2 SDK first.
optimbgv_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${OPENFHE_DIR:?Set OPENFHE_DIR to your OpenFHE 1.4.2 installation prefix}"
export OPENFHE_DIR
export LD_LIBRARY_PATH="$OPENFHE_DIR/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export CARGO_TARGET_DIR="${OPTIMBGV_TARGET_DIR:-$optimbgv_root/.build/cargo}"
export OPTIMBGV_BOOLEAN_BINARY="$optimbgv_root/.build/boolean-cost"
export OMP_NUM_THREADS=1 OMP_THREAD_LIMIT=1 RUST_TEST_THREADS=1
export OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
