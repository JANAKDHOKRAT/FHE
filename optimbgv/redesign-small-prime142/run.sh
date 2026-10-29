#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
source "$root/../count-openfhe142/activate.sh"
out=${1:?Provide a new evidence-output directory}
mkdir -p "$out"
for binary in redesign-small-prime142 histogram_lookup; do
    python3 "$root/measure.py" "$out/$binary.jsonl" "$out/$binary.stderr" "$CARGO_TARGET_DIR/release/$binary"
done
for length in 10 25 50 100; do
    python3 "$root/measure.py" "$out/vector$length.jsonl" "$out/vector$length.stderr" "$CARGO_TARGET_DIR/release/vector_lookup" "$length" --stream-keys
done
python3 "$root/check_algebra.py" > "$out/algebra.json"
python3 "$root/summarize.py" "$out"
