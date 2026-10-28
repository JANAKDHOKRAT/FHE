# Count on OpenFHE1.4.2 — separate validated port

This copy uses the professor's SDK version while preserving the existing small BGV Count profile and leaving both original implementations untouched.

| Setting | Preserved value |
|---|---:|
| Plaintext prime | 65,537 |
| Ring dimension | 32,768 |
| Circuit depth | 18 |
| Key-switch digits | 7 |
| Packing groups | 4 |
| Batch cap | 32 |
| Serialized client report | 6,176,895 bytes = 5.8907MiB |

The actual full Q and key-switch QP arrays match the saved1.3.1 small-profile result exactly. This is a compatibility port, **not another report-size reduction or a parameter retuning**. No forced ring or disabled qualification checks.

## What changed

Among the235 copied baseline files, only three existing files changed:

1. `openfhe-tbgv-rs/build.rs`: accept the now-tested1.4.2 SDK, retaining actual loaded-library version checks.
2. `openfhe-tbgv-rs/tests/key_noise_gap.rs`: serialize the two tests' context/key operations.
3. `openfhe-tbgv-rs/tests/crs_ceremony.rs`: add the same missing test serialization.

No existing circuit, predicate, arithmetic, noise bound or test assertion changed. The earlier concurrent noise-test failure was reproduced, passed in isolation, and fixed by respecting the wrapper's existing process-global-state serialization contract. See PORT-NOTES.md and verify_originals.py. Original1.3.1 code remains at ../count/; the professor's source and1.4.2 reference build were not edited.

## Validation

**199 tests passed; one pre-existing optional measurement ignored.** Breakdown:24 wrapper tests,170 fhe-prio3 tests (unit+integration),5 targeted Count-core tests. The full integration inventory was checked against the actual compiled executables' test lists. Long test programs ran in independent processes; each program ran one test at a time. Wrapper test guards were also tested with a two-thread runner. No failed assertion was disabled.

Count checks include the actual1.4.2 loaded libraries, unchanged full modulus arrays and report bytes, valid and invalid field inputs, all batch sizes1..32, non-output slot isolation, and rejection of report33 without changing the previous batch. Native and threshold qualification remain separate; projection stays opt-in, Count-only and exact-only. See QUALIFICATION.json. Successful attack-reproduction tests can document known limitations; they must not be described as defenses against every attack.

## Use and reproduce

In this prepared workspace:

```bash
source /workspace/FHE/optimization/count-openfhe142/activate.sh
/workspace/FHE/optimization/count-openfhe142/validate.sh
```

The full protocol validation is expensive. Dependencies are cached; Rust1.94.1 and OpenFHE1.4.2 are pinned by the existing workspace. SDK source commit: aa391988d354d4360f390f223a90e0d1b98839d7. Native SDK Release, OpenMP OFF, native optimization OFF. The wrapper checks the actual loaded shared-library versions, not only build labels.

The new1.4.2 setup uses fresh keys. Do not infer automatic migration/interoperability of persisted1.3.1 deployment state from these same-version tests. Keep old deployments and their original code separate.

## Matched comparison

See comparison/PROTOCOL.md, comparison/build.sh, comparison/run.sh and comparison/summarize.py. Both sides use the same installed1.4.2 SDK, original cryptographic profiles, same CPU/thread setting, batch4, same key reuse, warmup and repetition counts, and matched timing boundaries. All evaluator material is actually serialized and loaded for the explicit per-batch initialization scenario. Original professor code/build remains untouched; the adapter wraps his identical scalar gate/counter algorithm with measurement and serialization.

Final comparison results belong in comparison/RESULTS.md after the timed run completes. Do not mix in old1.3.1 results, the larger BGV profile, STD192, or functional-smoke timings collected under test load.

## Limits

This is the core Count port, not the full DAP service or a port of count-auth. Context creation and evaluation-key mutations still require serialization against other operations as documented by the original wrapper. Concurrency of initialization is not newly certified.

The requested named library security criterion is retained. Independent prior screening remains disclosed separately: BGV ADPS16~97.24/MATZOV~130.24; original Boolean ADPS16~97.53/MATZOV~120.92. Passing compatibility tests does not establish128-bit protocol security, arbitrary-ciphertext soundness, circuit privacy, negligible failure probability, or production readiness. Original trust assumptions and unresolved security issues remain. The optional ignored ceremony measurement is not a security pass.

Nothing is committed or pushed automatically. verify_originals.py checks preservation and exact permitted baseline edits.
