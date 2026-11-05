# BGV/FLP encrypted-verdict research implementation

**Experimental — production security gate NOT GREEN.** Published as a separate
research snapshot at the owner's request. Existing repository implementations
are unchanged. This folder contains both Rust crates and their C++ OpenFHE shim;
no secret keys, build outputs or installed dependencies are included.

## What changed

The evaluator receives encrypted validity decisions. The collector privately
computes T = sum(v_i (o_i+r_i)); the evaluator homomorphically computes
U = sum(v_i r_i); the collector releases decode(T-U). Client FLP encoding remains
unchanged. This adds durable task/key/batch binding, exact-ciphertext replay
protection, one-time aggregate release, a derived honest-input phase range guard,
and persistent key blocking on guard failure. The existing baseline APIs remain
for comparison; they are not the recommended deployment API.

The retained model assumes an honest evaluator and a separate noncolluding
collector. Metadata digests do not authenticate malicious evaluator computation.
Re-encryption, Sybils, filesystem rollback, timing channels and malicious
ciphertext security are not solved by the replay ledger or phase guard.

## Security status

The honest-input phase range bound is implemented. The current conservative
analysis does NOT certify 64-bit whole-vector noise hiding. This is a failure of
a sufficient bound, not a demonstrated attack or an encryption-security bit
estimate. Full ciphertext circuit privacy remains unproved. A phase guard is
not a proof that the requested computation was authorized. Do not deploy this
snapshot as a production-secure service.

## Build and test

Prerequisites: Rust supporting edition 2024, C++17 compiler, CMake, OpenMP and
OpenFHE **1.3.1** installed with shared libraries and MATHBACKEND=4. The build
rejects untested OpenFHE versions. Both Cargo.lock files are included.

```sh
export OPENFHE_DIR=/absolute/path/to/openfhe-1.3.1-install
export LD_LIBRARY_PATH="$OPENFHE_DIR/lib:${LD_LIBRARY_PATH:-}"
export OMP_NUM_THREADS=2
export CARGO_TARGET_DIR="$PWD/target"
cargo test --release --locked --manifest-path openfhe-tbgv-rs/Cargo.toml -- --test-threads=1
cargo test --release --locked --manifest-path fhe-flp/Cargo.toml -- --test-threads=1
cargo build --release --locked --manifest-path fhe-flp/Cargo.toml --bins
```

Run these commands from this folder. The crates use a relative path dependency.
For production operations a trusted persistent ledger and protected keys are
required; deleting or rolling back state defeats durable protection. A crash
while a key lease is active deliberately disables further key use in that ledger.

## Evidence and reproducibility

- `validation/`: test logs for this packaged snapshot.
- `fhe-flp/results/oblivious/`: historical **pre-phase-guard** matrix, 96 process
  runs (94 successful, two unsupported Sum100/p65537/N1024 refusals). These timings
  do not measure the newly added guard. One trial is not a throughput guarantee.
- `fhe-flp/results/phase-analysis/`: observed context parameters and mathematical
  bound diagnostics, including limitations.
- `fhe-flp/OBLIVIOUS-STATUS.md`: protocol and ledger details.
- `SHA256SUMS`: hashes of packaged files; `sha256sum -c SHA256SUMS` checks integrity,
  not mathematical or cryptographic correctness.

To generate new guard-inclusive measurements, first preserve the historical
results, then build the binaries above and run `results/oblivious/run.py` from
its directory. It appends results and overwrites machine metadata. The complete
matrix can take hours. Do not mix new measurements with the historical dataset.
