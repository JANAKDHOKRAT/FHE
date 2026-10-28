#!/bin/bash
# Source this file; original1.3.1 environment remains untouched.
source /workspace/fhe-deps/paper-env.sh
export OPENFHE_DIR=/workspace/fhe-deps/install-1.4.2
export LD_LIBRARY_PATH="$OPENFHE_DIR/lib"
export CARGO_TARGET_DIR=/workspace/fhe-build/count-port142
export OMP_NUM_THREADS=1 OMP_THREAD_LIMIT=1 RUST_TEST_THREADS=1
