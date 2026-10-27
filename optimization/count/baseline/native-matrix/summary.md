# Native single-key study: verified measurements

Real encrypted qualification and timings on one host. This is not production-security certification. The default threshold implementation is unchanged. Screening rows use one key/three batches; Count controls use two independent keys/six batches each. No confidence intervals are claimed.

| Profile | N | Depth | Ciphertext MiB | Evaluation keys GiB | Key setup API s | Process peak GiB | Evaluator median s/report |
|---|---:|---:|---:|---:|---:|---:|---:|
| threshold-count | 4 | 24 | 19.266 | 1.688 | 30.355–31.547 | 3.987–3.988 | 2.785–2.910 |
| native-count-d3 | 4 | 24 | 17.391 | 1.547 | 23.107–26.152 | 3.659–3.659 | 2.069–3.235 |
| native-count-d5 | 4 | 24 | 17.391 | 2.422 | 34.688 | 5.406 | 3.190 |
| native-count-random | 4 | 28 | 20.141 | 2.561 | 39.410 | 5.879 | 5.472 |
| native-hist-exact | 4 | 28 | 20.141 | 1.893 | 27.562 | 4.465 | 3.727 |
| native-hist-random | 4 | 28 | 20.141 | 2.561 | 40.611 | 5.882 | 6.332 |
| native-sum-exact | 4 | 27 | 19.453 | 1.735 | 28.547 | 4.128 | 7.332 |
| native-sum-random | 4 | 28 | 20.141 | 2.561 | 38.133 | 5.906 | 7.121 |
| native-sv10-exact | 4 | 28 | 20.141 | 1.781 | 26.160 | 4.215 | 3.305 |
| native-sv100-g16 | 4 | 28 | 20.141 | 2.561 | 38.197 | 5.879 | 6.561 |
| native-sv100-n32 | 32 | 28 | 20.141 | 2.561 | 35.661 | 6.019 | 1.132 |
| native-sv100-random | 4 | 28 | 20.141 | 2.561 | 41.739 | 5.879 | 6.790 |

Verified timed batches: **54**; reports: **300**. Each recorded batch output matched its plaintext expectation.

Evaluation keys are serialized rotation plus multiplication keys. Public keys, context, outer report envelope, client/collector timings, raw batch samples and wall time are in the JSON. Native profile construction realizes a context before the setup timer; do not infer total setup speedup from that API stage. Whole-process wall time includes planning in both paths. Peak RSS covers all simulated roles, not evaluator memory alone. A range across two setups is an observed range, not a confidence interval.

Matched Count exact size change: ciphertext **9.73% smaller**, total evaluation keys **8.33% smaller**. This keeps the field, predicate, packing geometry and nominal encryption target fixed; setup and decryption APIs differ. It does not prove equal protocol security, minimum safe parameters, or deployment speedup.

Randomized native profiles declare Q=1,000,000 invalid attempts and a 128-bit global ideal bound; repetition counts were checked using exact integers. The lifetime attempt budget is an external assumption, not enforced by this study. Historical seven-repetition results do not have matched guarantees.

The smaller-prime CSV records context selection/rejection only. Wire coding headroom is an estimate, not achieved compression; FPC1 is unchanged. See NATIVE.md for changes, qualification coverage and security limitations.
