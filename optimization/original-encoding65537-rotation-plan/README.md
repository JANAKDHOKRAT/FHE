# Original-encoding, small-prime BGV research

This is a separate research experiment. It does not replace `optimbgv/`, change
the paper, or establish a production-security claim. All eight selected cases, including length100, completed finite encrypted
qualification. See `RESULTS.md` and `evidence/qualification.json`. This establishes
finite correctness evidence, not production security.

The fixed measurement contract is **p = 65,537, ring dimension = 32,768**:

- Count is a bit.
- Sum(100) uses the seven original bits with weights 1,2,4,8,16,32,37.
- SumVec(10/25/50/100) here means **binary** vectors of those lengths.
- Histogram(3/8) uses the original one-hot vectors.
- Unused slots, including the second SIMD row, are ignored. They are deliberately
  populated with hostile values in the encrypted fixtures.

SIMD is an FHE evaluation mechanism, not a replacement for those encodings.
These experiments do not upload scalar sums, bucket indices, or lookup chunks.
They optimize the *aggregate contribution*. They do not preserve a separately
released per-report validity flag, and are not a drop-in implementation of
every possible paper interface.

## What changed mathematically

In the field, define Z(x)=1-x^65536 and D(x)=1-(x-1)^65536. These are exactly
the indicators of x=0 and x=1. Thus A=Z+D is the bit-membership indicator.

For coordinate k of a binary report, use

    Y_k = D(x_k) product_(j != k) A(x_j).

A valid report contributes its original bits. Any nonbinary coordinate makes
every contribution zero. Sum combines the Y coordinates with the original
weights. Count uses D alone. For a one-hot histogram, replace the other A
factors by Z: exactly one 1 and all other coordinates 0 are then required.
These identities hold for every field-valued input, not just tested inputs.
See [MATHEMATICS.md](MATHEMATICS.md) for slot isolation, depth and scope.

Balanced products and reusable interval products reduce depth and repeated
work. Composing rotations from a small key set reduces stored keys at a
possible runtime cost. Different tasks still use different parameter profiles.
This is not one universally optimal profile.

## Completed encrypted evidence

All byte counts below are decimal bytes per client report or the sum of the
serialized multiplication and selected rotation-key files. Public keys, context
and peak RAM are not included in the evaluation-key column.

| Task | Report bytes | Evaluation-key bytes | Fresh reports | Full-slot checks |
|---|---:|---:|---:|---:|
| Count | 5,578,879 | 199,258,085 | 5 | 16 |
| Sum(100), seven bits | 6,340,735 | 726,766,219 | 5 | 46 |
| Histogram(3) | 5,881,983 | 660,697,159 | 5 | 26 |
| Histogram(8), prior run | 6,488,191 | 795,981,379 | 5 | 51 |
| Binary SumVec(10) | 6,652,031 | 795,981,403 | 5 | 61 |
| Binary SumVec(25) | 7,086,207 | 2,219,081,020 | 5 | 136 |
| Binary SumVec(50) | 7,389,311 | 4,228,417,619 | 5 | 261 |
| Binary SumVec(100), research SDK | 7,405,695 | 6,397,146,236 | 4 | 430 |

Each check decrypts and compares all 32,768 slots against its expected value.
These are finite correctness checks. Five reports do not qualify maximum batch
size, negligible decryption failure, throughput or adversarial ciphertexts.
Histogram(8) is retained evidence, copied exactly into `retained-histogram8/`;
it was not rerun for this table. `summarize.py` validates the underlying records.

The published redesigned-encoding references report 6,176,895 bytes for the
small tasks and vectors10/25, 6,496,383 for vector50 and 6,815,871 for vector100.
Several original-encoding candidates above have **larger** uploads than their
corresponding references. Their evaluation-key totals
are lower than the corresponding selected lookup baselines, but no controlled
runtime comparison has been completed. Do not mix these measurements with the
older larger-ring paper-core baseline or quote a universal performance win.

All new qualifiers evaluate each report independently and add the encrypted
contributions. In particular, the published Count reference evaluates four
disjoint report groups together, whereas this Count candidate has one report
per evaluation and needs no folding rotation keys. Its key saving therefore
also changes computation/packing; it is not evidence of a throughput win.
The lookup task references already evaluate reports individually. The summary
checks byte references against their published raw logs and records their hashes.

## Length 100 is a separate research fork

The stock OpenFHE candidate was rejected by its security/ring check; that
failure is retained in `evidence/vector-100.jsonl`. It was not bypassed.

The selected length-100 candidate changes prime *selection* in an isolated
OpenFHE 1.4.2 fork. It chooses NTT primes above the same numerical noise bounds
instead of rounding up to powers of two first. Original ring/security checks
remain enabled. An independent rational checker verifies the actual primes
against the bounds, and the resulting 881-bit Q passes the unchanged library
table at ring 32,768. This preserves upstream numerical planning bounds; it is
not a complete circuit-noise or security proof.

The final source is `prime-diagnostic/vector100-late-shared.cpp`. Its live log is
`prime-diagnostic/vector100-late.jsonl`. Earlier schedules ending in `partial`
were deliberately stopped before qualification; none is counted as a pass.
Do not infer an encrypted pass from `CUSTOM_CONTEXT_PARAMETERS_ONLY`.

The candidate's measured keys total 6,397,146,236 bytes, below its selected
7,429,158,368-byte lookup reference. Its report fixture is 7,405,695 bytes.
The completed qualification also contains four `REPORT_PASS` records, 430
successful full-slot checks, a final `EXPLORATORY_TASK_PASS`, child return code
zero and an independent Rust aggregate-codec pass. The final output contains one
ciphertext and occupies557,116 serialized bytes. Public synthetic fixtures for
independent codec inspection are included in `public-fixtures/`; no secret key
is included.

## Security boundaries

`HEStd_128_classic` stays enabled. That is the **library target**, not a proof of
128-bit security. For example, the length-100 candidate's recorded primal-uSVP
estimates are approximately 92.86 bits under ADPS16 and 126.10 under MATZOV.
`evidence/screen-primal.jsonl` contains the exact checked models and profiles.
Only this attack family was screened; no complete independent assessment is
claimed. The user-selected comparison policy does not impose ADPS16 >=128,
but the estimates must still be disclosed.

The algebra assumes correct evaluation of ciphertexts encoding field elements.
It does not prove arbitrary-malicious-ciphertext robustness, collector circuit
privacy, deployment authentication/replay safety or malicious-evaluator safety.
The paper's honest-evaluator trust assumption remains. A correct plaintext
output is not evidence that the collector learns nothing else from its full
secret key and ciphertext. This folder is a native circuit experiment, not an
integrated deployment with the authenticated release wrapper.

No-wrap limits are N<65,537 for counts, histogram buckets and binary-vector
coordinates, and 100N<65,537 for Sum(100). Mathematical no-wrap limits do not
qualify noise capacity at those batch sizes. The tested batches are five
reports, or four in the length-100 candidate.

## Reproduction and verification

The current environment uses Linux, OpenFHE 1.4.2 at commit
`aa391988d354d4360f390f223a90e0d1b98839d7`, backend 4 and 64-bit native integers.
The original source/install remain separate from the research fork. See
[REPRODUCE.md](REPRODUCE.md) for build commands and required distinctions.

From the repository root, these inexpensive checks do not rerun FHE:

```sh
python3 optimization/original-encoding65537-rotation-plan/check_math.py
python3 optimization/original-encoding65537-rotation-plan/prime-diagnostic/check_context_fast.py
python3 optimization/original-encoding65537-rotation-plan/summarize.py
```

Use `summarize.py --require-all` to require every selected encrypted run and the
length-100 Rust aggregate inspection. It must fail while evidence is incomplete.
Even a pass means finite circuit qualification, not production-security approval.

`finalize_evidence.py --watch` can wait for the selected slow process, require
native success and run the independent Rust aggregate inspection. It then
generates the qualification record and RESULTS.md. It never changes raw status
records, starts another FHE run, commits or pushes. The running watch uses only
synthetic public fixtures and saves no secret key. This research folder requires
the documented tracked sibling SDK/Rust sources; it is not a
standalone deployment package.

The active length-100 run was started with the older frozen measurement wrapper,
which expects status `PASS`; this binary emits `EXPLORATORY_TASK_PASS`. Therefore
the old wrapper can record child returncode 0 but `final_pass_record: false` on
genuine native success. Raw records are retained. The independent summary checks
the child status and native record explicitly. Future runs use
`measure_research.py`, whose status mapping was qualified with a fresh encrypted
Count run in `evidence/wrapper-check-count.*`.
