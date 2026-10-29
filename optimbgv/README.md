# optimbgv — consolidated small-prime SIMD BGV study

**Send this entire folder.** It includes the selected baseline implementations,
locked dependencies, tests, formal explanations, measured evidence, and the
Boolean/Prio3 comparison adapters. It has no source dependency on another folder
in this repository. External compilers, Rust crates and OpenFHE are still needed.

**New reader: start with [START-HERE.md](START-HERE.md).** It explains each task
with examples, why its circuit was chosen, where its code lives, and how to
distinguish checking old evidence from running new encrypted experiments.

This is the selected measured baseline, **not a universally best implementation
or a production-security certification**. It excludes the newer experimental
circuit searches and 2.5% transport experiment. Existing folders are preserved.

## Tasks and selected profiles

Every BGV row uses SIMD, p=65,537, ring dimension 32,768 and the library's named
128-bit setting with checks retained. Parameters differ by complete circuit.

| Task | Depth | HYBRID digits | Report bytes | Evaluation-key bytes |
|---|---:|---:|---:|---:|
| Count | 18 | 7 | 6,176,895 | 242,261,163 |
| Sum100 | 18 | 7 | 6,176,895 | 1,776,581,938 |
| Histogram3/8 | 18 | 7 | 6,176,895 | 1,211,305,863 |
| Binary SumVec10/25 | 18 | 7 | 6,176,895 | 2,261,104,288 |
| Binary SumVec50 | 19 | 21 | 6,496,383 | 6,783,150,432 |
| Binary SumVec100 | 20 | 22 | 6,815,871 | 7,429,158,368 |

One report is uploaded by EACH client; SIMD does not merge separate clients'
uploads. Large vector keys and collector outputs are real costs, not omitted
overhead. See [full results](full-cost142/RESULTS.md).

## What logic is implemented?

Count uses an exact Count projection. Sum uploads a scalar and evaluates a
weighted Fermat equality lookup. Histogram uploads an index and evaluates one
equality indicator per bucket. Binary SumVec uploads chunks of at most 13 bits,
decodes them with lookup tables, and gates all outputs on every chunk's validity.
The identity delta_a(x)=1-(x-a)^65536 gives exact equality over the prime field.
SIMD is the execution layout; Fermat is the equality/validation mechanism.

**Sum/Histogram/SumVec change the paper's input encodings.** Do not present these
as unchanged implementations of its weighted-bit/one-hot construction. Read
[FORMAL.md](redesign-small-prime142/FORMAL.md) and
[the detailed guide](REFERENCE-GUIDE.md) for proofs and scope. The reference guide
and frozen historical scripts retain original workspace paths; use the portable
top-level entry points below for this consolidated package.

## Build and reproduce (Linux)

Install a C++17 compiler, Python 3, util-linux/taskset, and Rust/Cargo supporting
edition 2024. Install the OpenFHE 1.4.2 SDK with shared libraries and headers;
the measurement source revision is
`aa391988d354d4360f390f223a90e0d1b98839d7`. Preserve its build settings in your
new evidence. OpenFHE itself is not vendored or automatically installed here.
The wrapper checks installed library versions. See the original
[environment record](full-cost142/evidence/environment.json).

From this folder:

```sh
export OPENFHE_DIR=/absolute/path/to/openfhe-1.4.2-install
python3 verify_package.py
bash build.sh
# Choose an allowed CPU: taskset -pc $$
export OPTIMBGV_CPU=0
bash run.sh /absolute/path/to/NEW-results-directory all
```

Run cases sequentially with ample RAM/disk: reference peak process memory is
about 7.78 GiB and some evaluation-key sets exceed 7 GB. Long vectors take many
minutes. Do not run concurrent builds/benchmarks. Setup and all simulated roles
run locally; this is not a deployed DAP service.

`all` runs the 21 measured configurations. `preflight`, `vectors`, and `length100`
are supported diagnostic subsets, but the complete-summary check deliberately
refuses an incomplete matrix. After a subset, inspect raw PASS/exit records or
run summarize.py without --complete; do not call it a complete reproduction.

The all-task cost matrix uses valid inputs; invalid-input qualification is
separate. Its source/tests and records are in count-openfhe142 and
redesign-small-prime142. Their historical scripts are retained unchanged, so
adapt their environment paths explicitly before reuse outside the old workspace.

## Evidence and limitations

The frozen code/evidence derives from JANAKDHOKRAT/FHE commit
ce95365727964ba0a58aa6f5c1dc3ca4121a6016. Package assembly changes only entry-point
scripts and documentation. verify_package.py checks package hashes and reruns
the original arithmetic/evidence audit, NOT expensive encrypted computations or
security estimators. Fresh encrypted runs must pass final output checks; failure
records must be kept. Timings are hardware-dependent single observations, not
stable throughput or guaranteed identical results.

The nominal library target is not an independent security proof. Arbitrary
malicious-ciphertext security and circuit privacy against the full-key collector
remain unresolved. The model retains an honest evaluator and non-colluding
collector. Authentication, replay controls, production key lifecycle and release
policy are not supplied. No full-code security audit or clean-machine build is
certified. These caveats apply even when finite correctness tests pass.
