#!/usr/bin/env bash
set -euo pipefail
# Requires Rust and OpenFHE 1.3.1 configured as in the repository CI.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
crate_dir=${PAPER_CORE_CRATE_DIR:-$(cd -- "$script_dir/../.." && pwd)}
if [[ ! -f "$crate_dir/Cargo.toml" ]]; then
  echo "Set PAPER_CORE_CRATE_DIR to the checkout's prio3/fhe-paper-core directory." >&2
  exit 2
fi
result_dir=${1:-$(mktemp -d "${TMPDIR:-/tmp}/paper-core-practical.XXXXXX")}
mkdir -p -- "$result_dir"
configurations=(
  "exact count"
  "exact sum:100"
  "exact histogram:8"
  "exact sumvec:10:1"
  "randomised count"
  "randomised sum:100"
  "randomised histogram:8"
)
for configuration in "${configurations[@]}"; do
  read -r mode task <<< "$configuration"
  name="$mode-${task//:/-}"
  for extension in json log; do
    if [[ -e "$result_dir/$name.$extension" ]]; then
      echo "Refusing to overwrite $result_dir/$name.$extension" >&2
      exit 2
    fi
  done
done
export OMP_NUM_THREADS=${OMP_NUM_THREADS:-2}
cargo build --release --locked --manifest-path "$crate_dir/Cargo.toml" --bin paper_core_eval
for configuration in "${configurations[@]}"; do
  read -r mode task <<< "$configuration"
  name="$mode-${task//:/-}"
  cargo run --quiet --release --locked --manifest-path "$crate_dir/Cargo.toml" --bin paper_core_eval -- \
    "$mode" --type "$task" --reports 4 --batches 6 --seed 1 \
    --out "$result_dir/$name.json" > "$result_dir/$name.log" 2>&1
done
echo "Results: $result_dir"
