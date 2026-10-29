# Original encodings, smaller-prime BGV — research package

This new folder is separate from the older `optimbgv/` lookup implementation.
All selected cases preserve the paper's measurement encodings at p65537 and
ring32768. Circuit specialization preserves aggregate contributions, not a
separately exposed validity flag. Only exact contribution checks are included.

**Completed finite tests:** Count; Sum100; Histogram3/8; binary SumVec10/25/50/100.
39 reports and1027 full-slot checks. This is not every parameter of those task
families. In particular bounded SumVec16 with maximum100 is not covered.

**Security status:** research, not production certified. Named library128-bit
target enabled; independent screening does not establish128-bit security. The
length100 profile requires the included isolated OpenFHE parameter-selection
patch; other selected cases use stock1.4.2. Malicious-ciphertext robustness,
circuit privacy and a complete negligible-failure analysis remain unresolved.

From the repository root:

```sh
python3 optimization/original-encoding65537-rotation-plan/verify_package.py
python3 optimization/original-encoding65537-rotation-plan/check_math.py
python3 optimization/original-encoding65537-rotation-plan/summarize.py --require-all
```

For a fresh machine, provision the SDKs using SDK-SETUP.md first.
These check package integrity, mathematical schedules and recorded evidence;
they do not rerun expensive FHE experiments. Read REPRODUCE.md for native builds
and fresh encrypted execution. The SDK must be provisioned at the documented
paths. This folder relies on tracked `optimization/count-openfhe142/` frozen Rust
sources and `optimbgv/full-cost142/` comparison records in the same repository.
The required older Histogram8 sources/evidence are copied into this package.

To inspect the included synthetic fixtures using the unchanged Rust codec:

```sh
source optimization/count-openfhe142/activate.sh
cargo build --release --locked --manifest-path optimization/original-encoding65537-rotation-plan/inspector/Cargo.toml
/workspace/fhe-build/count-port142/release/original-rotation-inspect \
  optimization/original-encoding65537-rotation-plan/prime-diagnostic/context100-fast.jsonl \
  optimization/original-encoding65537-rotation-plan/public-fixtures --require-aggregate
```

Read RESULTS.md for measured sizes, MATHEMATICS.md for equivalence and scope,
NOVELTY-REVIEW.md for prior-work limitations, and README.md for trade-offs.
WORK-STATE.md and stopped/partial logs are historical development records,
not active-run instructions or successful qualifications. Absolute paths in raw
records identify the original environment. Raw records were not rewritten to
hide failures or the legacy wrapper's status-name mismatch.

SHA256 hashes protect against accidental package changes, not malicious authors
or forged evidence. Public fixtures contain only a public key and synthetic
ciphertexts; no secret key or evaluation-key binaries are distributed.
