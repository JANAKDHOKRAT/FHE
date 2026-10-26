# Count exact: multiparty-mode parameter ablation

Actual encrypted circuit results, not a production-security certification. p=786433; OpenFHE nominal HEStd_128_classic; four reports per batch. Ranges below are across independent key setups, not confidence intervals.

| Profile | Qualification | Ciphertext MiB | All evaluation keys GiB | Setup s | Whole-process peak GiB | Evaluator median s/report |
|---|---|---:|---:|---:|---:|---:|
| flooding | Qualified on recorded tests | 19.266–19.266 | 1.688–1.688 | 30.097–32.925 | 3.987–3.988 | 3.317–3.473 |
| default-multiparty | Rejected at qualification-count.log | — | — | — | — | — |
| default-with-headroom | Rejected at qualification-count.log | — | — | — | — | — |

All evaluation keys means serialized rotation plus multiplication keys; public keys are separate in raw JSON. Memory includes all simulated roles. Setup and evaluator medians have different boundaries; whole-process wall time, client and collector timings remain in raw JSON.

The direct default-mode candidate must not be recommended if qualification fails. Adding context headroom preserves the rebuild guard, but neither that nor passing tests proves equal multiparty security or minimal safe parameters. No warm-up or network deployment is measured. See README.md for scope.
