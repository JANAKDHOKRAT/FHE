# Provision the two separate SDKs

The recorded scripts target a Linux `/workspace` layout. Prerequisites: Git,
CMake, a C++17 compiler/build tools, OpenSSL development headers/library,
Python3 and Rust/Cargo supporting edition2024. The research build needs OpenMP.
Provision these dependencies through your normal environment setup. Run from
the repository root. Do not overwrite an existing SDK or environment file.

For a fresh workspace, initialize the stock SDK at its pinned revision:

```sh
mkdir -p /workspace/fhe-deps /workspace/fhe-build /workspace/fhe-validation
git clone --recursive https://github.com/openfheorg/openfhe-development.git /workspace/fhe-deps/openfhe-1.4.2
git -C /workspace/fhe-deps/openfhe-1.4.2 checkout aa391988d354d4360f390f223a90e0d1b98839d7
git -C /workspace/fhe-deps/openfhe-1.4.2 submodule update --init --recursive
cmake -S /workspace/fhe-deps/openfhe-1.4.2 -B /workspace/fhe-build/openfhe-stock142 \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/workspace/fhe-deps/install-1.4.2 \
  -DMATHBACKEND=4 -DWITH_BE4=ON -DNATIVE_SIZE=64 -DWITH_OPENMP=OFF \
  -DWITH_NATIVEOPT=OFF -DBUILD_SHARED=ON -DBUILD_STATIC=OFF \
  -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF -DGIT_SUBMOD_AUTO=OFF
cmake --build /workspace/fhe-build/openfhe-stock142 -j2
cmake --install /workspace/fhe-build/openfhe-stock142
```

The frozen activation helper sources `/workspace/fhe-deps/paper-env.sh`. If that
file does not already exist, a minimal compatible file is:

```sh
export OPENFHE_DIR=/workspace/fhe-deps/install-1.4.2
export LD_LIBRARY_PATH="$OPENFHE_DIR/lib"
export CARGO_TARGET_DIR=/workspace/fhe-build/count-port142
export OMP_NUM_THREADS=1 OMP_THREAD_LIMIT=1
```

Save that text as `paper-env.sh` only in a fresh environment. Keep Rust/Cargo on
PATH; existing environments may additionally configure their own CARGO_HOME and
RUSTUP_HOME. Do not replace an existing helper used by other experiments.

The length100 SDK must be a DIFFERENT checkout/install:

```sh
git clone --recursive https://github.com/openfheorg/openfhe-development.git /workspace/fhe-deps/openfhe-bound-prime-study
git -C /workspace/fhe-deps/openfhe-bound-prime-study checkout aa391988d354d4360f390f223a90e0d1b98839d7
git -C /workspace/fhe-deps/openfhe-bound-prime-study submodule update --init --recursive
git -C /workspace/fhe-deps/openfhe-bound-prime-study apply --check /workspace/FHE/optimization/original-encoding65537-rotation-plan/prime-diagnostic/openfhe-bound-primes.patch
git -C /workspace/fhe-deps/openfhe-bound-prime-study apply /workspace/FHE/optimization/original-encoding65537-rotation-plan/prime-diagnostic/openfhe-bound-primes.patch
```

Those patch-file paths assume the repository clone is `/workspace/FHE`; adjust
only the repository prefix if your clone is elsewhere. Continue with the
research CMake configuration in REPRODUCE.md, which uses OpenMP and the separate
`install-bound-prime-study` prefix. Never apply this patch to the stock SDK.

Online dependency fetches may be required for Git submodules and Cargo before
offline commands work. If Cargo reports an uncached dependency, run `cargo fetch
--locked --manifest-path optimization/original-encoding65537-rotation-plan/inspector/Cargo.toml`
with network access, then use the locked build. Compiler/toolchain differences
can change binary hashes; raw recorded hashes describe the original environment.
Functional/context/codec checks are separate from binary-hash reproduction.
