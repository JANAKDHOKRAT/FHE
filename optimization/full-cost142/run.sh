#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
source "$root/../count-openfhe142/activate.sh"
export OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
python3 "$root/run_cases.py" "${1:?output directory}" "${2:-length100}"
