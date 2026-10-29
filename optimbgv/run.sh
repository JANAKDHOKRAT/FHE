#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
source "$root/activate.sh"
out=${1:?Provide a NEW output directory}
if [ -e "$out" ]; then
    echo 'Refusing existing output directory; preserve earlier attempts.' >&2
    exit 2
fi
python3 "$root/run_cases.py" "$out" "${2:-all}"
python3 "$root/full-cost142/summarize.py" "$out" --complete
