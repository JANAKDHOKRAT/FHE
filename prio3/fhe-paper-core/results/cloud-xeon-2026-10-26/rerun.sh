#!/usr/bin/env bash
set -euo pipefail

# Requires Rust plus the pinned OpenFHE 1.3.1 and its runtime library path.
# See the crate README and the repository CI build configuration.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
crate_dir=$(cd -- "$script_dir/../.." && pwd)
result_dir=${1:-$(mktemp -d "${TMPDIR:-/tmp}/paper-core-sumvec.XXXXXX")}
mkdir -p -- "$result_dir"
for length in 10 25 50 100; do
  for extension in json log; do
    if [[ -e "$result_dir/sumvec-$length.$extension" ]]; then
      echo "Refusing to overwrite $result_dir/sumvec-$length.$extension" >&2
      exit 2
    fi
  done
done
export OMP_NUM_THREADS=${OMP_NUM_THREADS:-2}
cargo build --release --locked --manifest-path "$crate_dir/Cargo.toml" --bin paper_core_eval
for length in 10 25 50 100; do
  cargo run --quiet --release --locked --manifest-path "$crate_dir/Cargo.toml" --bin paper_core_eval -- \
    randomised --type "sumvec:$length:1" --reports 4 --batches 6 --seed 1 \
    --out "$result_dir/sumvec-$length.json" > "$result_dir/sumvec-$length.log" 2>&1
done
echo "Results: $result_dir"
