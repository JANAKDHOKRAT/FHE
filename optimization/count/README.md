# Count optimization experiment — separate from baseline

Later update: [HARDENING.md](HARDENING.md) records the separate authenticated Count path and independent parameter screening. This document describes the retained raw-core experiment; its historical results have not been rewritten.

Status: research publication authorized by the user. **Full production security remains NOT GREEN.**
The production/security gate is distinct from the measured correctness gate.
Read [CONTRACT.md](CONTRACT.md) and [ATTACKS.md](ATTACKS.md) before interpreting
results. The earlier 8.7 MiB figure was a conditional estimate, not a requirement
or an achieved value. Measured results will be generated in RESULTS.md.

## Isolation and preservation

- Original code remains at `../../prio3/`; this folder has its own three package
  copies and a separate Cargo target directory. No original optimization flag
  or default is changed.
- `baseline/source.tar.gz`, `baseline-sha256.json`, and `baseline.json` freeze
  the pre-experiment tree, including its uncommitted native implementation.
- `baseline/native-matrix/` and `baseline/native-followup/` preserve the earlier
  raw measurements. `baseline-evidence-sha256.json` fingerprints that evidence.
- This is an independent Cargo workspace. Running the original crate still
  uses original dependencies; the experimental crate uses siblings here.

## Actual change

Only the experimental native **exact Count** path may opt into
`NativeParameters { count_projection: true, .. }`. Default false retains the
old circuit. Projection is refused for every other task and randomized mode.
The aggregate contribution is `1-(x-1)^(p-1)`, proven equivalent for every field
value to the old Count contribution. Admission and output masks remain.
There is no exposed per-report validity flag in this contract.

The CLI opt-in is `--count-projection true`, together with `--key-mode single`.
Record p, requested and actual digits, ring dimension, Q/PK/QP primes, batch
limit, group count and complete wire sizes. Security selection stays enabled;
no ring size is forced and no standards-table bound is bypassed.

## Measurement rules

Five profiles compare baseline and projection with matched N=4/G=4; additional
small-ring full packing and N=32/G=32 expose packing costs. Two fresh keys per
profile, three timed batches per key. Every benchmark output is compared with
plaintext. Qualification is separate from timing. Context planning, setup,
admission, evaluation and collection have different boundaries; use wall_s for
whole-process time. Within-key samples are not assumed independent.

The operational cap is 32, even though the field permits more arithmetic
headroom. Smaller p reduces the theoretical N<p ceiling; declared functionality
in this study stays at N<=32. No result transfers to Sum/SumVec/Histogram.

## Reproduction environment

Measured with pinned OpenFHE 1.3.1, ordinary single-key BGV,
UNIFORM_TERNARY secrets and HEStd_128_classic. `evidence/host.json` identifies
the library build and host. Install the original repository's prerequisites;
this folder does not download or silently substitute cryptographic libraries.
On the measurement machine, source `/workspace/fhe-deps/paper-env.sh`, then use
`CARGO_TARGET_DIR=/workspace/fhe-build/count-optimization` rather than the
baseline build directory. `run_study.py` records commands, logs, hashes and
source snapshots. Reproduce into a new directory, leaving recorded evidence intact:

```sh
export CARGO_TARGET_DIR=/workspace/fhe-build/count-optimization
python3 optimization/count/run_study.py --out /tmp/count-study-new
python3 optimization/count/summarize.py --evidence /tmp/count-study-new
python3 optimization/count/verify_baseline.py
cargo test --release --locked --manifest-path optimization/count/fhe-paper-core/Cargo.toml --test count_boundary_attacks --test count_scope -- --nocapture --test-threads=1
```

Run from the repository root after setting OPENFHE_DIR and LD_LIBRARY_PATH.
Use a new output name for each run. Context selection rejections are retained.
The boundary/attack test is supplementary; it explicitly reproduces known
architecture limitations rather than asserting security for those attacks.
`evidence/runner-executed.py` preserves the exact initial measurement driver;
`run_study.py` adds non-overwriting reproduction/build orchestration.

A successful local test is not a proof of arbitrary-ciphertext security,
circuit privacy, replay resistance or authenticated aggregate correctness.
Those unresolved issues block a production-green conclusion. Research publication does not clear that gate. See PUBLICATION.md.
