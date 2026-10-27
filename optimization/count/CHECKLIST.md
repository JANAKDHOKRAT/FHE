# Requested Count checklist

Later update: [HARDENING.md](HARDENING.md) records the separate authenticated Count path and independent parameter screening. This document describes the retained raw-core experiment; its historical results have not been rewritten.

Statuses distinguish mathematical statements, finite test evidence, measured
results and open security work. No unexecuted attack is a pass. The consolidated
production gate remains NOT GREEN; preserve the baseline and do not push.

## Ten work items

| # | Item | Evidence / status |
|---|---|---|
| 1 | Freeze baseline | DONE: source archive, source inventory, both prior raw-result studies, evidence hashes |
| 2 | Security contract | DONE: CONTRACT.md; honest evaluator, noncollusion, full-key collector; no authentication or release proof |
| 3 | Contribution equivalence | PROVED by exhaustive cases in CONTRACT.md; exhaustive finite regression for both fields |
| 4 | Opt-in isolated implementation | DONE: separate package copies; flag defaults false; other tasks/modes refused |
| 5 | Complete depth | DERIVED: admission + exponent + final mask; recorded realized final level checked by collector |
| 6 | Prime/ring search | EXECUTED: 32 candidates in selection.csv, including refusals; no exhaustive global-minimum claim |
| 7 | Complete encryption parameters | RECORDED: Q/PK/QP, actual digits, ternary secret, pinned library; independent lattice estimate remains OPEN |
| 8 | Key switching/packing | MEASURED: matched G=4 controls, small-ring full packing and G=32/N=32; raw costs retained |
| 9 | Hostile qualification | EXECUTED finite field/ciphertext/format tests; service concurrency and arbitrary-ciphertext security remain OPEN |
| 10 | Reproducible evidence | Source snapshots, logs, commands, fresh-key repetitions, size formulas and hash-checking summary; see RESULTS.md |

## Ten requested outcomes

| # | Outcome | Assessment |
|---|---|---|
| 1 | Output equivalence | Exact field proof; requires correct encrypted evaluation |
| 2 | Smaller ring under declared encryption criteria | Library-selected n=32768; full QP checked against pinned classic-128 table; not independently certified |
| 3 | Exact report size | Measured both packed ciphertext and full serialized report; transport unspecified |
| 4 | Supported batch range | Main qualification capped at 32; supplementary all-one N=1..32 check recorded separately |
| 5 | Capacity and refusal | Complete circuits tested at operational maximum; 33rd refused; no asymptotic noise certificate |
| 6 | Slot/row isolation | Injected cross-slot/row inputs; supplementary full-ring plaintext inspection |
| 7 | Incompatibility rejection | Fingerprint/key/shape/length/residue tests; does not authenticate honest encryption |
| 8 | All setup/memory costs | Public key, context, rotation/mult keys, process peak RSS and wall time in raw JSON |
| 9 | Runtime trade-offs | Two fresh keys/profile, three batches/key; no universal speedup or confidence claim |
| 10 | Limitations documented | ATTACKS.md and production gate retain open issues; no hidden replacement of failures |

## Ten assumptions explicitly refused

| # | Assumption | How handled |
|---|---|---|
| 1 | Half ring guarantees half bytes | Actual bytes checked from actual RNS primes and ring, plus envelope |
| 2 | 128-bit label is a full proof | QP table consistency checked separately; independent security analysis OPEN |
| 3 | Depth guarantees decryption | Full real circuits tested; correctness evidence remains finite |
| 4 | Smaller prime is automatically suitable | Primality, split-field compatibility and N<p required; exact Count only |
| 5 | Projection is validity | Explicitly only Count aggregate contribution; no validity/count-of-valid-reports channel |
| 6 | Invalid-plaintext tests prove malicious-ciphertext security | Explicitly rejected; arbitrary-ciphertext security OPEN |
| 7 | FHE implies output-only disclosure | Circuit privacy and release authorization not established |
| 8 | Small keys are a free win | All keys and runtime measured; digit/packing trade-offs reported |
| 9 | Means establish reliability | Per-key raw batches retained, boundary and malformed cases separate |
| 10 | Count transfers to other tasks | Opt-in refused outside native exact Count; other task claims unchanged |

## Ten attacks and combinations

| # | Attack | Evidence / conclusion |
|---|---|---|
| 1 | Nonbinary values | Real encrypted 2,p-1,p/2; exact algebra covers every field value |
| 2 | Opposing residuals + repeated group + mixed batch | Real separate reports for 2/5,-1/5; duplicate-group flushing prevents cancellation before projection |
| 3 | Unauthorized slots + second row + valid authorized input | Injected report qualification; full-slot supplementary inspection |
| 4 | Replay + duplicate group | Real identical report accepted twice; anti-replay/unique participation not provided |
| 5 | Wrong key/parameters + forged report ID | Header/provenance mutations and supplementary other-key report rejection; public fingerprints are copyable |
| 6 | Malformed lengths/residues/header + recomputed ID | Packed tests and supplementary 64-submission rejection sequence; finite local resource evidence only |
| 7 | Non-honest ciphertext coefficients | Supplementary zero-payload observation; acceptance is not alone an exploit. Arbitrary-ciphertext security remains OPEN |
| 8 | Batch overflow + reused groups + maximal inputs | Main qualification fills mixed batch with ones to32, rejects33rd; supplementary all-one batches1..32 |
| 9 | Flood + concurrent traffic | Local finite malformed sequence only. No network service or concurrency-security qualification; OPEN |
| 10 | Evaluator substitution + collector decryption ability | Supplementary substitution of one-report aggregate as32-report output and direct individual decryption; outside honest-evaluator/authorized-delivery assumption |

Supplementary statuses must be read alongside their actual test logs and final
gate record. A failed or unfinished supplementary run cannot be called passed.
