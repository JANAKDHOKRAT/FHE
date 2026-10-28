# Complete core-cost measurements on OpenFHE 1.4.2

This is an isolated measurement adapter. The working Count port, redesigned BGV
circuits and professor's original source/build are preserved. It measures the
already implemented small-prime BGV variants (p=65,537, ring 32,768), original
professor Boolean STD128/GINX circuit, and pinned Prio3 0.18.1-alpha.3 baseline.
BGV's scalar/index/chunk encodings are alternatives, not the original paper's
unchanged bit/one-hot encoding. No stronger/weaker parameter profile is substituted.

The user selected all available tasks. The complete matrix has 21 configurations:
Count and binary SumVec(10,25,50,100) for all three backends; Sum(100) and
Histogram(3,8) for BGV and Prio3. The provided Boolean implementation has no
complete Sum/Histogram validator. Its cells are unavailable, not invented.

Each configuration uses one fresh process/key setup and one four-report valid
batch with common deterministic measurements, CPU0, one thread, serial execution.
These are diagnostic cost observations, not medians, confidence intervals or
stable-throughput claims. No network/DAP/HPKE/TLS/auth/release-wrapper costs.
The declared PROTOCOL.md fixes the measurement boundaries and limitations.

## What is measured

* Actual client serialization sizes and client encoding/encryption/proof time.
* One-time setup, including key generation, sizing/serialization, loaded evaluation
  keys, precomputed constants and BGV's mandatory native-codec qualification.
* Every public/evaluation/private-key/context size where the mechanism has one;
  no secret key bytes are saved to evidence files.
* Server processing from actual input deserialization through validation/masking,
  aggregation and final output serialization. Prio3 covers both aggregator roles
  and real serialized verifier-share/message decoder round trips.
* EXACT serialized collector output bytes, ciphertext counts and collector
  deserialization/decryption/unsharding. BGV vectors retain one output ciphertext
  per coordinate: they are not sized using an unrelated Count ciphertext.
* Full-slot/flag correctness diagnostics outside core timing. Every final output
  is compared with the reference. BGV vector operation counters check the
  preserved evaluation loop shapes.
* Full-process wall/CPU and OS peak RSS, including setup and diagnostics. This
  includes all simulated roles and transient buffers; it is not per-role RAM.

Key serialization uses bounded per-index BGV messages. Evaluator runtime starts
with keys loaded in every backend; no one backend alone pays per-batch key reload.
Task-native output formats differ and are recorded. Prio3 output bytes sum the
two actual serialized share messages; FHE bytes are their actual collector bundles.
Prio3 report payload excludes nonce/framing; duplicate nonce/public-share delivery
is recorded separately. None of these is a measured full DAP transport budget.

Progress prints and plaintext-reference checks do not influence ciphertext
evaluation. Test-only decryption is outside core timers; the evaluator computations
do not use the secret key. No guards or assertions were disabled. These tests do
not establish malformed-ciphertext security, circuit privacy, independent 128-bit
security, per-role administrative isolation or cloud-bill advantages.

## Reproduce

Requires the preserved SDK/dependency environment and sufficient RAM for the
multi-gigabyte evaluation keys. Do not run cases in parallel or build beside them.
The long-vector BGV circuit is expensive. Failures are kept and the runner stops;
no retry or parameter retuning manufactures a passing row.

```sh
bash /workspace/FHE/optimization/full-cost142/build.sh
bash /workspace/FHE/optimization/full-cost142/run.sh /workspace/fhe-validation/full-cost-reproduction all
python3 /workspace/FHE/optimization/full-cost142/summarize.py /workspace/fhe-validation/full-cost-reproduction --complete
```

The summary validates exit codes, final PASS records, expected/actual equality,
profile invariants, four reports, real output lengths and timing consistency.
An incomplete run produces an explicit pending list, not extrapolated results.

The separate preflight runs validate the adapters and timers and are not primary
samples. The primary source/binary hashes were frozen before measurement. Any
final report must distinguish measured data from the earlier matched Count study
or the paper's M2 snapshot. No commit/push is performed by these scripts.
