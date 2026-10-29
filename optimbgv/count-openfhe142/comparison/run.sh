#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
out=/workspace/fhe-validation/count-openfhe142-2026-10-28
# Qualification must complete first; do not benchmark beside running tests/builds.
test -f "$out/integration-completed.json"
python3 "$root/../qualification_report.py" > "$out/qualification-check.log"
source "$root/../activate.sh"
export OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
for epoch in 1 2;do
 python3 "$root/measure_process.py" taskset -c 0 "$out/boolean-count" "$epoch" > "$out/Boolean-e${epoch}.jsonl" 2> "$out/Boolean-e${epoch}.stderr"
 python3 "$root/measure_process.py" taskset -c 0 /workspace/fhe-build/count-port142/release/count-matched142 "$epoch" > "$out/BGV-e${epoch}.jsonl" 2> "$out/BGV-e${epoch}.stderr"
done
