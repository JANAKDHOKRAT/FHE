#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
source "$root/../count-openfhe142/activate.sh"
cargo build --release --offline --locked --manifest-path "$root/Cargo.toml"
