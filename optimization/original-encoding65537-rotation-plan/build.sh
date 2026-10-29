#!/usr/bin/env bash
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mode=${1:-stock}
mkdir -p "$here/.build"
compile() {
  g++ -std=c++17 -O3 -DMATHBACKEND=4 -fopenmp \
    -I"$sdk/include/openfhe" -I"$sdk/include/openfhe/core" \
    -I"$sdk/include/openfhe/pke" -I"$sdk/include/openfhe/binfhe" \
    -I"$sdk/include/openfhe/third-party/include" \
    "$1" -L"$sdk/lib" -Wl,-rpath,"$sdk/lib" \
    -lOPENFHEpke -lOPENFHEcore -lOPENFHEbinfhe -lcrypto -o "$2"
}
case "$mode" in
  stock)
    sdk=/workspace/fhe-deps/install-1.4.2
    compile "$here/low_dimensions.cpp" "$here/.build/low"
    compile "$here/vector.cpp" "$here/.build/vector"
    compile "$here/retained-histogram8/full_digits.cpp" "$here/.build/histogram8"
    ;;
  research)
    sdk=/workspace/fhe-deps/install-bound-prime-study
    compile "$here/prime-diagnostic/context100-fast.cpp" "$here/.build/context100"
    compile "$here/prime-diagnostic/vector100-late-shared.cpp" "$here/.build/vector100"
    ;;
  *) printf 'usage: bash build.sh stock|research\n' >&2; exit 2 ;;
esac
