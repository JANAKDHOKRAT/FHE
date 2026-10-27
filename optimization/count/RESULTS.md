# Measured Count experiment

All figures below are measurements, not the earlier 50% estimate.

| Profile | Ring | Depth | Serialized report MiB | Eval keys MiB | Median evaluator seconds/report, by fresh key | Peak RSS GiB |
|---|---:|---:|---:|---:|---|---:|
| baseline-g4 | 65536 | 24 | 17.391 | 216.025 | 1.776, 2.258 | 1.123 |
| projected-large-g4 | 65536 | 22 | 16.016 | 198.023 | 1.689, 1.986 | 1.049 |
| projected-small-g4 | 32768 | 18 | 5.891 | 231.038 | 0.959, 1.052 | 0.727 |
| projected-small-full | 32768 | 18 | 5.891 | 1155.191 | 0.826, 0.670 | 2.506 |
| projected-small-g32 | 32768 | 18 | 5.891 | 462.077 | 0.292, 0.214 | 1.178 |

Full serialized report: 18,235,519 -> 6,176,895 bytes; measured reduction 66.127%.
Packed size is independently checked as 56 + ceil(2*n*sum(bitlen(q_j-1))/8) bytes from recorded ring and Q primes. Packed ciphertext bytes exclude the report envelope; serialized_report_bytes includes it. Neither includes an unspecified network transport.
30 timed batches, 288 reports; every benchmark batch checked against plaintext.

Two fresh keys per profile, three batches per key. These are small samples; no population speedup or independent-sample confidence claim is made. API setup_ms excludes native planning; wall_s covers the process. Lower seconds/report at N=32 is amortized batch throughput, not single-client latency.

Encryption parameters satisfy the pinned OpenFHE 1.3.1 ternary/classic-128 table including auxiliary QP. This is a table consistency check, not an independent lattice estimate or protocol-security proof.

**Production gate: NOT GREEN.** Replay, arbitrary-ciphertext security, authenticated aggregate provenance, output-only disclosure and network/concurrency resource controls are not established. See ATTACKS.md. No production push is authorized by these local passes.

Supplementary tests passed for every all-one batch size 1–32, with all other slots in both rows zero; four extra 32-report batches covered zero, p−1, p/2 and deterministic random nonbits. Wrong-key and 64 malformed submissions were refused in the tested cases. Aggregate substitution and direct collector decryption were reproduced as declared trust limitations. See evidence/supplementary.log and evidence/gate.json.
