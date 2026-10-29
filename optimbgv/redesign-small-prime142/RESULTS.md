# Actual small-prime redesign results — 2026-10-28

**The isolated redesigned circuits passed the stated encrypted tests.** These
are exact new encoding variants, not the paper's original upload representation,
and not a production-security certification. The original implementations are
unchanged. No library security guard was disabled and no ring was forced.

All primary candidates used OpenFHE 1.4.2, prime 65,537, ring 32,768, uniform
ternary secrets, native single-key BGV, FLEXIBLEAUTOEXT and the named
HEStd_128_classic setting. Their setup passes the existing native ciphertext
rebuild/decryption qualification. The server uses only ordinary OpenFHE
operations; equality lookups execute sixteen real ciphertext squarings.

## Measured uploads: ONE client report

| Task | Context depth | HYBRID digits | Actual serialized report bytes | MiB |
|---|---:|---:|---:|---:|
| Bounded Sum, maximum 100 | 18 | 7 | 6,176,895 | 5.890746 |
| Histogram, 3 buckets | 18 | 7 | 6,176,895 | 5.890746 |
| Histogram, 8 buckets | 18 | 7 | 6,176,895 | 5.890746 |
| Binary SumVec, length 10 | 18 | 7 | 6,176,895 | 5.890746 |
| Binary SumVec, length 25 | 18 | 7 | 6,176,895 | 5.890746 |
| Binary SumVec, length 50 | 19 | 21 | 6,496,383 | 6.195434 |
| Binary SumVec, length 100 | 20 | 22 | 6,815,871 | 6.500121 |

Sum and Histogram's full Q and QP arrays match the preserved small Count profile,
checked element by element. The vector profiles and their complete arrays are
in the raw evidence. Measured report lengths match the packed-format formula.
Separate clients still send separate reports: 100 clients do not share one upload.
Task-specific profiles explain the modest size increase with vector length;
this table does not claim that every profile has the same size.

## Actual qualification scope

* Sum: 40 encrypted reports in two batches: an eight-report boundary/invalid
  batch and a 32-report all-maximum batch. Inputs include 0,1,2,99,100,101,
  32,768 and 65,536. Expected aggregates 202 and 3,200 matched. An additional
  earlier eight-report run with fresh keys passed, retained separately.
* Histogram: five reports for each of L=3 and L=8. First/last valid buckets
  counted; index L, 32,768 and 65,536 contributed zero. Final bucket counts matched.
* SumVec: two encrypted reports per length 10,25,50,100. One valid mixed vector
  and one report with an out-of-range last chunk while the other chunks contained
  ones. Every coordinate of the invalid report was zero. Final aggregates matched.
* Every encrypted report deliberately populated unauthorized input slots and
  the second row with 65,536. Evaluator masking prevented their contribution.
* Every output slot was decrypted and compared with the oracle for each report
  and for each final aggregate. Intermediate validity flags were not decrypted.
  The per-report output decryptions are test diagnostics, not protocol releases.
* Primary total: 58 encrypted reports. A further two-report length-10 run passed
  through the bounded per-index key-packaging path. This is finite correctness
  evidence, not a proof of negligible decryption-failure probability or a tested
  maximum batch of 32 for every task. Vector batches tested here have size two;
  Histogram batches have size five.
* The scalar Sum formula was checked against all 65,537 field elements. The
  independent integer oracle also checked Fermat equality over the entire field,
  canonical chunk representations, and whole-vector invalid rejection. These
  algebra checks are labelled separately from encrypted executions.

## What changed mathematically

FORMAL.md proves the ideal-field contribution for every possible field element,
not just honest measurements. Sum uploads a scalar and performs a weighted
finite-domain lookup. Histogram uploads a bucket index and performs an equality
lookup. Binary SumVec uploads 13-bit scalar chunks, decodes bits by subset lookup,
and gates every coordinate by the other chunks' exact membership indicators.
One bad chunk invalidates the whole report. There is no division, residual
cancellation shortcut, randomized predicate error, or assumption of honest bits.

These encodings must be formally specified if added to the paper. They do not
silently replace its old bit/slack or one-hot wire representation. Binary SumVec
is covered; arbitrary multi-bit bounded SumVec has not been implemented here.

## Costs and losses: smaller uploads are not a universal improvement

| Task/profile | Actual serialized rotation-key bytes | Mult-key bytes | Public-key bytes |
|---|---:|---:|---:|
| Sum(100) | 1,695,771,165 | 80,753,713 | 11,538,679 |
| Histogram(3,8) | 1,130,515,061 | 80,753,713 | 11,538,679 |
| SumVec(10,25) | 2,180,276,397 | 80,753,713 | 11,538,679 |
| SumVec(50) | 6,540,895,071 | 242,255,361 | 11,538,735 |
| SumVec(100) | 7,163,753,165 | 265,327,073 | 12,063,185 |

The raw JSON is authoritative for exact key sizes. Length 50 uses one serialized
map per rotation index; the other primary vector runs used one combined map.
Per-map serialization overhead is included; no key-compression gain is claimed.
The fixed vector key plan is not claimed minimal.

Lookup evaluation uses SIMD slots as server-side tables. It gives up the old
inter-client packing/amortization: each client's report is evaluated individually
before its output is added. Vector lookup is slow and currently emits **one
output ciphertext per coordinate**, repeating that coordinate in the first row.
Sum and Histogram use one output ciphertext. Total collector output bytes and
all tasks' peak memory/setup/runtime have not been systematically benchmarked.
No controlled speed comparison or Boolean-versus-BGV winner is claimed.

The measured length-50 bounded-packaging process peaked at 7,453,952 KiB RSS and
took 701.92 seconds including setup, key serialization and test diagnostics while
another vector run was active. This is a resource observation, not an isolated
latency benchmark. The length-10 packaging regression peaked at 2,562,268 KiB.

## Failures retained

The initial BV digit-size-4 process ended with exit 137 near the environment
memory limit. The BV digit-size-22 candidate passed its binary-coordinate
SumVec(10) subtask, then failed at Histogram because a rotation key was absent.
Neither is a primary all-task pass. Their native serialization sizes are not
mixed with the packed Rust report sizes above.

An initial Sum attempt was refused by the retained rebuild guard; the primary
code runs the native startup qualification instead of bypassing it. Its early
key-byte figure also counted cumulative maps repeatedly and is not used above.
An initial vector run was stopped during startup to correct its rotation plan.
The first concurrent length-50 key setup was SIGKILLed; cgroup OOM events were
recorded. Its blank logs are not a circuit pass. The new per-index packaging
limits temporary serialization-buffer size and passed full length-50 and
length-10 circuits. A missing optional /usr/bin/time utility was replaced with
Python OS resource measurement; the failed invocation is retained.

## Security and deployment gate: NOT GREEN

No encryption-security parameter check was disabled. Nevertheless the named
128-bit library target is not an independent proof. The unchanged Count-profile
screening caveat still applies to identical profiles. The new depth-19/20 profiles
have not received a fresh independent assessment in this work; Sage was not
available in the restored environment. No unqualified 128-bit security claim is
made. Algebraic exactness is different from encryption security.

Arbitrary malicious-ciphertext security, circuit privacy against the full-key
collector, rigorous complete-circuit noise/failure bounds, task negotiation,
authentication/replay protection, and deployment release policy remain outside
this circuit implementation. The in-process harness uses fixed test task IDs.
These results demonstrate real encrypted functionality, not a production endpoint.

All 308 preserved Count-port manifest hashes and the older baseline's 393 source
plus 80 evidence hashes were verified unchanged. No commit or push was made.
