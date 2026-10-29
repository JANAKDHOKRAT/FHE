#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
source "$root/../count-openfhe142/activate.sh"
cargo build --release --offline --locked --manifest-path "$root/Cargo.toml"
c++ -std=c++17 -O3 -DMATHBACKEND=4 -I"$OPENFHE_DIR/include/openfhe" -I"$OPENFHE_DIR/include/openfhe/core" -I"$OPENFHE_DIR/include/openfhe/binfhe" "$root/boolean_cost.cpp" -L"$OPENFHE_DIR/lib" -lOPENFHEbinfhe -lOPENFHEcore -o /workspace/fhe-validation/full-cost142/boolean-cost
