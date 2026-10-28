# Matched Count comparison on OpenFHE1.4.2

Original professor source and1.4.2 build preserved. A separate benchmark adapter retains STD128/GINX and the identical four-gate scalar Count validator/mask and incremental counter (28 gates/batch4). BGV uses the separate1.4.2 port, with original p65537,ring32768,depth18,digits7,groups4,cap32,exact Count projection. Its full Q/QP profile and6176895-byte reports are unchanged.

Both use the same installed1.4.2 SDK, same host/CPU0/one thread, same four plaintexts, two fresh-key epochs, identical invalid qualification/warmup/three measured valid batches per epoch, and matched timing phases. Both deserialize context/public and evaluation material per batch; separate initialization and core columns prevent confusing key loading with circuit cost. This scenario is explicitly per-batch evaluator creation, not a claim that reloading every batch is optimal deployment caching. Original untouched professor CLI is a baseline; this adapter supplies instrumentation.

**20 batches /80 encrypted reports passed**. Valid[0,1,0,1] gives2; invalid-input[0,1,2,3] gives1; all Boolean diagnostic flags/digits checked outside measured server time, and every BGV scalar compared to expected. Primary data excludes the earlier adapter smoke run and qualification stress-test timings.

| Measured quantity | Original Boolean parameters | Small BGV Count parameters |
|---|---:|---:|
| Report bytes | 8,245 | 6,176,895 |
| Public-key bytes | 8,413,229 | 11,538,679 |
| All evaluation-key bytes | 464,718,498 | 242,261,163 |
| Output aggregate bytes | 12,189 | 581,724 |
| Server core seconds/batch, six-sample median | 2.648436 | 2.239629 |
| Server incl. batch initialization seconds, median | 2.910910 | 2.820569 |
| Client encryption+encoding+serialization seconds/report, median | 0.002366 | 0.076224 |
| Collector decoding+decryption seconds/batch, median | 0.000020 | 0.006224 |
| Combined measured client+server-init+core+collector seconds/batch, median | 2.921191 | 3.140978 |

## Per-key medians and ranges

- Boolean: core medians key1/key2 2.612 / 2.708s; with initialization 2.899 / 3.005s. Observed core range 2.558–2.825s; with-init range 2.844–3.117s. Whole-process peak RSS 1.609GiB.
- BGV: core medians key1/key2 2.239 / 2.270s; with initialization 2.691 / 2.876s. Observed core range 2.200–2.284s; with-init range 2.675–2.901s. Whole-process peak RSS 0.714GiB.

Server core includes report decoding, admission/conversion, validation/masking, aggregation and output serialization. Client and collector phases measured separately. No network, transport authentication or release-wrapper cost. Whole-process RSS includes all roles, key generation, serialization, codec qualification and material loading; it is not isolated server RAM. Stage sums exclude lifecycle cleanup; whole-process wall/CPU/RSS retained separately. SDK native library compilation is common; Rust/C++ adapter and shim compiler flags are recorded, so this is a concrete implementation comparison, not an algorithmic lower bound or proof of optimal tuning.

BGV startup includes mandatory native codec qualification; Boolean setup includes original public bootstrapping-key generation and encrypted constants. Setup raw fields retained in matched-summary.json. Diagnostic decryptions outside timing. Six measured batches share two keys, so no independent-sample confidence interval or broad failure-rate claim is made.

The requested nominal library security criterion is retained. Separate prior generic-lattice screening remains BGV ADPS16~97.24/MATZOV~130.24 and original Boolean ADPS16~97.53/MATZOV~120.92. A successful port/benchmark is not a128-bit protocol-security certificate. Arbitrary-ciphertext security and collector circuit privacy remain unproven. Count output equivalence does not expose an independent BGV validity flag. Boolean Z4 and BGV F65537 input spaces differ; common tested input domain0..3 and final Count disclosure are matched.

Count only, batch4 measurement; no vector-length crossover claim. The Count port additionally passed all batch boundaries1..32 and output-slot checks in separate correctness tests. Original1.3.1 code, professor artifact and previous experiments preserved. No automatic commit or push.

## Host and setup accounting

Host: AMD EPYC 9V74 80-Core Processor; VM CPU quota 400000 100000, memory limit 34359738368 bytes. Both ran on CPU0 with one thread. This restored workspace has a different processor from earlier Xeon-based experiments; those old runtimes are not mixed into this table.

- Boolean: one-time measured setup stages key1/key2 2.916 / 2.889s. Raw fields retained so native codec qualification and key serialization are not hidden.

- BGV: one-time measured setup stages key1/key2 11.653 / 12.357s. Raw fields retained so native codec qualification and key serialization are not hidden.

Combined stage sums are not network end-to-end latency: process cleanup, communication and transport are excluded. Setup scopes differ because BGV's own required codec qualification is additional implementation work; it remains enabled.

The1.4.2 BGV evaluation-key serialization is24bytes smaller in total than the retained1.3.1 sample (8bytes per key). Upstream EvalKeyRelin changed from an outer vector-of-vectors to separately serialized A/B vectors. Full mathematical Q/QP parameters and the client report are unchanged. Do not reuse1.3.1 serialized evaluation keys as if the schemas were identical; this port uses fresh1.4.2 setup and does not certify cross-version state migration.
