# Pushed small-prime BGV: logic, implementation and reproduction

## Scope and reproducibility status

The reference measurement commit is `bf967d4ee00bcb22d99c5a51b693d9b6b77df696`
on `janak/fhe-prio3`. The code, locked Rust dependencies, recorded results and
audit are versioned. The installed OpenFHE SDK, compiler tools and Cargo cache
are external dependencies: the existing scripts assume the prepared Linux
workspace described below. This is not a self-contained clean-machine installer.
No clean-machine build is certified by this guide.

Fresh encryption and keys produce different ciphertext bytes. Reproduction means
matching declared profiles, functionality and accounting, not identical random
ciphertexts or identical timings. Report sizes should be checked against the
recorded serializer/profile; any discrepancy must be retained and investigated.

This guide excludes the uncommitted newer circuit searches and FPC2 transport
experiments. It documents the pushed baseline, not a production service.

## Which directories to use

* `count-openfhe142/`: frozen single-key Count path, wrapper, codec and tests.
* `redesign-small-prime142/`: exact lookup-based Sum, Histogram and binary
  SumVec circuits, formal derivations and separate invalid-input qualification.
* `full-cost142/`: matched Count/Sum/Histogram/SumVec measurement adapters,
  Boolean and Prio3 comparison, raw evidence and accounting protocol.
* `count/`: earlier retained baseline; do not silently substitute its SDK or data.

The measurement crates depend on the frozen copies inside `count-openfhe142/`,
not the separately modified top-level `prio3/` working tree.

## Mathematics and why these encodings were chosen

All these BGV profiles use p=65,537 and ring dimension n=32,768. Fully split
batching is compatible because 2n divides p-1. SIMD operates on many slots of
one ciphertext; it does not combine independent clients into one upload.

For any field element z, define delta_a(z)=1-(z-a)^(p-1). It equals one exactly
when z=a and zero otherwise. Since p-1=2^16, this exponent uses sixteen
successive squarings. This is Fermat validation, unlike the Boolean gate path.

### Count

Upload a binary measurement in the designated location. The opt-in Count
projection is delta_1(x): one for x=1, zero for every other field value.
It preserves Count's aggregate contribution, not a separately exposed validity
flag. The retained complete Count profile requests depth 18, HYBRID digits 7,
four packing groups, with a qualified admission cap of 32 reports. The cost run
uses four reports. Do not remove admission masks or group-flush logic.

### Bounded Sum(100)

Upload the scalar x instead of the paper's seven weighted bits. Evaluate
F(x)=sum_{a=1}^{100} a*delta_a(x). Admissible values contribute x; every other
field element contributes zero. Equality tables and reductions use SIMD slots.
Input isolation, sixteen squarings and plaintext weights require depth 18.
Require 100N<p for a non-wrapping integer aggregate.

### Histogram(3) and Histogram(8)

Upload a bucket index b, rather than the paper's one-hot vector. Output bucket
a receives delta_a(b). An invalid index contributes zero to all buckets, while
a valid index contributes exactly one count. Input isolation and output masking
bring the requested depth to 18. Require N<p. This construction enforces the
intended category semantics through index decoding; it is not the original
encrypted one-hot residual circuit.

### Binary SumVec(10/25/50/100)

Partition the vector into chunks of at most 13 bits. Upload each chunk as
z_h=sum_k 2^k*v_(h,k) in a designated slot. Define V_h as the sum of delta_a
over the admissible chunk range, and D_(h,k) as the sum over admissible a whose
k-th bit is one. The contribution is

    Y_(h,k) = D_(h,k)(z_h) * product_{j != h} V_j(z_j).

An invalid chunk zeros its own decoded bits and every other chunk's output,
so the entire invalid report contributes zero. Input slots are isolated before
broadcast; raw residuals from different reports are never summed for admission.
See `redesign-small-prime142/FORMAL.md` for slot isolation and the full argument.

| Length | Chunks | Requested depth | HYBRID digits |
|---:|---:|---:|---:|
| 10 | 1 | 18 | 7 |
| 25 | 2 | 18 | 7 |
| 50 | 4 | 19 | 21 |
| 100 | 8 | 20 | 22 |

Require N<p for each output coordinate. These implementations emit one output
ciphertext per vector coordinate, which makes collector traffic expensive.

These encodings permit shallower lookup circuits, but introduce substantial
rotation keys, computation and output costs. They were investigated for
feasibility, not established as universally optimal. They change the paper's
input encodings and must be identified as alternative constructions.

## Encoding versus wire format

Measurement encoding determines which field elements represent a measurement.
The packed Rust wire codec serializes ciphertext components and required
metadata. Native startup qualification checks ciphertext reconstruction; do not
bypass it. The collector-output bundle is distinct from a client report.
Context/key files and evaluation-key bytes are separate setup costs.

## Prepared-workspace execution

Expected layout: repository `/workspace/FHE`, external dependency environment
`/workspace/fhe-deps/paper-env.sh`, OpenFHE 1.4.2 installation
`/workspace/fhe-deps/install-1.4.2`, and Cargo target
`/workspace/fhe-build/count-port142`. The activation script sets these paths.

Requirements: Linux, C++17 compiler, Rust/Cargo supporting edition 2024, Python 3,
`taskset` with CPU 0 allowed, and OpenFHE 1.4.2 headers/shared libraries including
its CMake package metadata. See the recorded `full-cost142/evidence/environment.json`
for the measurement environment. Budget sufficient RAM and disk for multi-GB
evaluation keys; the measured process peak reaches about 7.78 GiB. Run serially.

On another host, first install OpenFHE 1.4.2 and dependencies, then adapt a COPY
of the activation/build/runner scripts. Preserve and record those changes.
Hard-coded paths also occur in the Boolean binary output location and runner.
`build.sh` uses Cargo `--offline --locked`: a fresh machine needs the locked
dependencies downloaded first, for example with `cargo fetch --locked
--manifest-path optimization/full-cost142/Cargo.toml`. The external SDK setup
is not supplied by that Cargo command. Different CPU affinity or library build
settings must be disclosed; do not present them as the original environment.

In the prepared workspace, use a NEW output directory on every attempt:

```sh
mkdir -p /workspace/fhe-validation/full-cost142
bash /workspace/FHE/optimization/full-cost142/build.sh
bash /workspace/FHE/optimization/full-cost142/run.sh /workspace/fhe-validation/reproduction-all all
python3 /workspace/FHE/optimization/full-cost142/summarize.py /workspace/fhe-validation/reproduction-all --complete
```

The matrix contains 21 cases: all three backends for Count and the four binary
vector lengths; BGV and Prio3 for Sum100 and Histogram3/8. Boolean Sum/Histogram
are unavailable because the supplied code lacks complete corresponding circuits,
not because Boolean FHE cannot implement them. The runner stops on failure.
Retain failed output; do not append retries into a previously populated directory.

For separate circuit qualification, consult and run the retained commands in
`count-openfhe142/README.md` and `redesign-small-prime142/README.md`. The full-cost
run uses valid inputs; it does not rerun all earlier hostile-input tests.

## Independently check the published records without rerunning FHE

```sh
python3 /workspace/FHE/optimization/full-cost142/audit/verify_claims.py
```

This checks recorded evidence, arithmetic and claims; its output explicitly says
that encrypted circuits and security estimators were NOT rerun. Hashes detect
changes relative to manifests, not fabricated data. For fresh results, inspect
exit records, final PASS, expected-versus-actual outputs, actual output ciphertext
counts, p/n/depth/digits and loaded library paths before trusting a summary.

## Expected reference sizes

| Task | Client report B | Evaluation keys B |
|---|---:|---:|
| Count | 6,176,895 | 242,261,163 |
| Sum100 | 6,176,895 | 1,776,581,938 |
| Histogram3/8 | 6,176,895 | 1,211,305,863 |
| SumVec10/25 | 6,176,895 | 2,261,104,288 |
| SumVec50 | 6,496,383 | 6,783,150,432 |
| SumVec100 | 6,815,871 | 7,429,158,368 |

Each client sends its own report. Evaluation keys belong to the evaluator, not
each client. Full setup, timings, memory and collector-output bytes are recorded
in `full-cost142/RESULTS.md`; do not replace them with Count's values.

## Limits for implementation and publication

The intended trust model is an honest-but-curious evaluator and collector that
do not collude. The collector holds the secret key. Finite tests and the named
HEStd_128_classic target do not establish independent 128-bit security,
arbitrary-malicious-ciphertext robustness, circuit privacy, or output-only
privacy against the full-key collector. Independent estimator findings must
remain disclosed; they are not an admission rule selectively applied to BGV.

These are research circuits and measurement adapters, without DAP/HPKE, network
admission/authentication, replay protection, production key lifecycle or safe
aggregate-release policy. Measurements use one fresh setup and one four-report
batch per case; no stable-throughput claim follows. No overall BGV efficiency
win over Prio3 or the professor's binary-vector implementation is established.
