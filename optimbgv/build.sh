#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
source "$root/activate.sh"
mkdir -p "$root/.build"
# --locked preserves dependency versions; fresh machines may download crates.
cargo build --release --locked --manifest-path "$root/full-cost142/Cargo.toml"
cargo build --release --locked --manifest-path "$root/redesign-small-prime142/Cargo.toml"
c++ -std=c++17 -O3 -DMATHBACKEND=4 -I"$OPENFHE_DIR/include/openfhe" -I"$OPENFHE_DIR/include/openfhe/core" -I"$OPENFHE_DIR/include/openfhe/binfhe" "$root/full-cost142/boolean_cost.cpp" -L"$OPENFHE_DIR/lib" -lOPENFHEbinfhe -lOPENFHEcore -o "$OPTIMBGV_BOOLEAN_BINARY"
