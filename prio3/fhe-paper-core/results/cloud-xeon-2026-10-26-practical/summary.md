# Practical exact and randomized task measurements

Completed 7/7 configurations, with six verified four-report batches per completed configuration.

| Task | Check | Depth | Evaluator median s/report | Observed s/report range | Ciphertext MB/report | Rotation keys GiB |
|---|---|---:|---:|---:|---:|---:|
| count | exact | 24 | 3.553 | 2.589–5.281 | 20.202 | 1.582 |
| sum:100 | exact | 27 | 6.168 | 5.732–22.465 | 22.364 | 2.710 |
| histogram:8 | exact | 28 | 6.299 | 4.568–10.441 | 23.085 | 2.969 |
| sumvec:10:1 | exact | 28 | 4.901 | 4.142–5.401 | 23.085 | 2.783 |
| count | randomised | 28 | 7.285 | 5.715–9.159 | 23.085 | 3.897 |
| sum:100 | randomised | 28 | 10.126 | 7.790–11.797 | 23.085 | 3.897 |
| histogram:8 | randomised | 28 | 9.858 | 7.426–13.389 | 23.085 | 3.897 |

## Scope and method

- This matrix uses the unchanged depth-28 configuration limit from commit 686b8d3: prime p=786433, nominal HEStd_128_classic security, ring dimension 65536, OMP_NUM_THREADS=2, OpenFHE 1.3.1, GCC 14.2, Rust 1.94.1, cloud Xeon Platinum 8573C. Each JSON records the actual context and machine.
- The paper roles use one collector key, but the reused OpenFHE wrapper retains its multiparty-capable context defaults, including NOISE_FLOODING_MULTIPARTY, FLEXIBLEAUTOEXT and UNIFORM_TERNARY. These measurements are not a demonstration of minimal single-key BGV parameters or optimal key size.
- Count, Sum bounded by 100, and Histogram with eight buckets are measured with both exact and seven-repetition randomized validation. Exact binary SumVec is measured at length ten. Bounds and bucket count are explicit workload choices, not an exhaustive sweep of all possible task parameters.
- Every measured batch must decrypt to the expected plaintext output before a configuration succeeds. These valid-input measurements are not a malicious-ciphertext security proof. Earlier encrypted integration tests exercised selected invalid encodings.
- Evaluator totals sum timed admission, validation flushes and finish calls within each batch. Divide each batch total by four, then summarize. Setup, evaluator construction/key loading, message serialization, client encryption and collector decryption are outside the evaluator total and must not be silently treated as end-to-end latency.
- The CSV also preserves total configuration wall time and that time divided by 24 reports. These include all roles, key loading, and setup in this serial local experiment; they are not network or deployed-DAP latency measurements.
- Six sequential observations share a collection key. Observed ranges are reported; statistical confidence-interval coverage requires sampling assumptions not established by sequential execution alone. No controlled warm-up, affinity or external background-load control was used.
- The rerun script targets the Linux build configured in CI. The current wrapper checks Linux .so library paths; native macOS requires a build adaptation before a same-M2 comparison.
- Earlier randomized SumVec measurements at lengths 10, 25, 50 and 100 remain valid and are not overwritten or rerun here. These cloud results are not a controlled speed comparison with the paper Boolean results on an Apple M2 Max.

## Exact validation limits and stopped larger-ring exploration

- With the retained configuration, exact binary SumVec requires depths 28, 29, 30 and 31 for lengths 10, 25, 50 and 100. The executable refuses the latter three before setup; exact-limit-checks.json records those actual refusals. No six-batch timing result is claimed for them here.
- This is a configuration frontier, not a proof of impossibility. A separate parameter probe found depth 29 can retain ring 65536 with six digits, while accepted depth-30/31 candidates used ring 131072. Some candidates were rejected by OpenFHE; none of those errors was bypassed.
- A separate experimental depth-31 encrypted length-100 integration test passed, including valid inputs, a cancellation pair, the last packed group and a cross-group write. Its rotation keys were 6.41 GiB and setup took about 190 seconds. This was a functional test, not a completed six-batch benchmark.
- At the user's direction the larger-ring benchmark was stopped, its experimental source was archived locally, and the core-library changes were reverted before this matrix. The larger-ring investigation does not appear as a successful timed configuration in this table.

## Evidence

Per-configuration JSON contains raw batch totals, stage summaries, sizes and machine metadata. Logs record six successful batch checks. matrix-metadata.json records the executable hash and base commit. verification.json records source and raw-file hashes. To rerun into a new directory, use bash rerun.sh OUTPUT_DIR, then python3 summarize.py OUTPUT_DIR. Set PAPER_CORE_CRATE_DIR when using the downloaded script outside this checkout. The original cloud runner is retained with the local experiment records.
