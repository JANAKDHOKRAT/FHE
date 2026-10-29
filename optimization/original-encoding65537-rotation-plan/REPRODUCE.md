# Reproduce the original-encoding research

For SDK installation on a fresh machine, read [SDK-SETUP.md](SDK-SETUP.md).

Run commands from the FHE repository root. They describe the workspace used for
these records; `/workspace` paths in the research provenance checks are explicit.
Do not load stock and modified OpenFHE libraries into the same process. Do not
overwrite the existing SDK or published `optimbgv/` package.

## Stock SDK tasks

The existing setup in `optimization/count-openfhe142/` provides the pinned stock
OpenFHE 1.4.2 SDK. Source its activation file, then compile the native qualifiers:

```sh
source optimization/count-openfhe142/activate.sh
bash optimization/original-encoding65537-rotation-plan/build.sh stock
```

The script writes only this folder's `.build/` directory. Each invocation below
generates fresh keys and encrypted reports; no cached plaintext outcome is used
to decide the homomorphic result. These runs can take minutes and use gigabytes
of RAM. Run them sequentially for reproducible resource attribution.

```sh
. optimization/count-openfhe142/activate.sh
root=optimization/original-encoding65537-rotation-plan
mkdir -p "$root/.build/rerun"
python3 "$root/measure_research.py" "$root/.build/rerun/count.jsonl" "$root/.build/rerun/count.stderr" "$root/.build/low" count 1
python3 "$root/measure_research.py" "$root/.build/rerun/sum100.jsonl" "$root/.build/rerun/sum100.stderr" "$root/.build/low" sum 7
python3 "$root/measure_research.py" "$root/.build/rerun/hist3.jsonl" "$root/.build/rerun/hist3.stderr" "$root/.build/low" histogram 3
python3 "$root/measure_research.py" "$root/.build/rerun/hist8.jsonl" "$root/.build/rerun/hist8.stderr" "$root/.build/histogram8" histogram 8
python3 "$root/measure_research.py" "$root/.build/rerun/vector10.jsonl" "$root/.build/rerun/vector10.stderr" "$root/.build/low" sumvec 10
python3 "$root/measure_research.py" "$root/.build/rerun/vector25.jsonl" "$root/.build/rerun/vector25.stderr" "$root/.build/vector" sumvec 25
python3 "$root/measure_research.py" "$root/.build/rerun/vector50.jsonl" "$root/.build/rerun/vector50.stderr" "$root/.build/vector" sumvec 50
```

For Histogram(8), `build.sh` compiles the retained prior source from the included
`retained-histogram8/` folder, including its original headers. It does not silently substitute
the newer low-dimensional qualifier for the prior recorded measurement.

## Isolated length-100 fork

The fork is based on the same OpenFHE commit. Its only tracked source difference
is the versioned patch `prime-diagnostic/openfhe-bound-primes.patch`. Apply this
patch to a separate clean checkout; retain the original SDK unchanged. The
source path used here is `/workspace/fhe-deps/openfhe-bound-prime-study`, build
path `/workspace/fhe-build/bound-prime-study` and install prefix
`/workspace/fhe-deps/install-bound-prime-study`. Initialize the upstream third-
party submodules before configuring. The CMake configuration used was:

```sh
cmake -S /workspace/fhe-deps/openfhe-bound-prime-study -B /workspace/fhe-build/bound-prime-study \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/workspace/fhe-deps/install-bound-prime-study \
  -DMATHBACKEND=4 -DWITH_BE4=ON -DNATIVE_SIZE=64 -DWITH_OPENMP=ON \
  -DBUILD_SHARED=ON -DBUILD_STATIC=OFF -DBUILD_UNITTESTS=OFF \
  -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF -DGIT_SUBMOD_AUTO=OFF
cmake --build /workspace/fhe-build/bound-prime-study -j2
cmake --install /workspace/fhe-build/bound-prime-study
bash optimization/original-encoding65537-rotation-plan/build.sh research
```

Check the context and its actual primes before the expensive encrypted run:

```sh
root=optimization/original-encoding65537-rotation-plan
LD_LIBRARY_PATH=/workspace/fhe-deps/install-bound-prime-study/lib "$root/.build/context100"
python3 "$root/prime-diagnostic/check_context_fast.py"
```

The rational checker reads the retained `context100-fast.jsonl`. Compare the
new context's q array with that record; `summarize.py` also compares the actual
encrypted-run moduli. A different context needs its own bound checks and attack
estimates; do not reuse the existing screening by profile name alone.

Use a **new, nonexistent** fixture directory for each qualification. It contains
only public keys and synthetic encrypted fixtures; the secret key is not saved.

```sh
root=optimization/original-encoding65537-rotation-plan
mkdir -p "$root/.build/rerun"
export LD_LIBRARY_PATH=/workspace/fhe-deps/install-bound-prime-study/lib
export OMP_NUM_THREADS=3 OMP_THREAD_LIMIT=3
export FHE_PUBLIC_FIXTURE_DIR=/workspace/fhe-validation/original-rotation100-fresh
python3 "$root/measure_research.py" "$root/.build/rerun/vector100.jsonl" "$root/.build/rerun/vector100.stderr" "$root/.build/vector100" sumvec 100
```

A parameters-only pass is insufficient. Require four complete reports, all430
slot checks, final native task pass, zero child exit and actual aggregate codec
inspection. Logs from cancelled schedules are not substitute evidence.

## Independent wire inspection

The Rust inspector uses the frozen existing Rust report/packed codec without
modifying it. It checks the exact native-produced wire bytes, fresh ciphertext
metadata, report ID and lossless reconstruction, plus malformed parser cases.
It does not decrypt and does not prove ciphertext authenticity or security.

```sh
source optimization/count-openfhe142/activate.sh
cargo build --release --locked --manifest-path optimization/original-encoding65537-rotation-plan/inspector/Cargo.toml
/workspace/fhe-build/count-port142/release/original-rotation-inspect \
  optimization/original-encoding65537-rotation-plan/prime-diagnostic/context100-fast.jsonl \
  /workspace/fhe-validation/original-rotation100-fresh --require-aggregate
```

The final aggregate is not a fresh client report and must be parsed under the
evaluated-ciphertext policy. The native qualifier independently decrypts both
the original and serialized/reconstructed aggregate against the expected slots.

## Interpretation

The exact report bytes include the existing packed wire container with no
authentication attachment in these native tests. Evaluation-key bytes are the
sum of individually serialized selected rotation keys and the mult-key file.
These are not total setup transfer, peak server RAM or deployment costs.
Measurement-wrapper RSS covers every simulated role, setup and diagnostic
decryptions. Wall times include those diagnostics and must not be compared with
the professor's stage-specific timings as a speed benchmark.
