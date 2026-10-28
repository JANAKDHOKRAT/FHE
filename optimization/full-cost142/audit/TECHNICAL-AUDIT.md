# How we reached the small-prime variants: construction, evidence and critical audit

This is the current interpretation of the isolated optimization work, following commit `8972e72`. It supersedes historical wording where explicitly identified below. It does not change the frozen programs, parameters or raw measurements. The companion `verify_claims.py` checks algebra and the recorded evidence using Python integers, without importing our Rust/OpenFHE implementation. Its successful execution is not an independent cryptographic security assessment.

## 1. Scope and what was actually achieved

We built and executed single-key BGV Count, bounded Sum(100), Histogram(3,8), and **binary** SumVec(10,25,50,100), using plaintext prime p=65,537 and ring dimension n=32,768. The complete cost matrix has 21 configurations: eight BGV, eight Prio3, five professor Boolean. Each has one fresh process/setup and one batch of four valid reports, on the same host, CPU0 and one thread, with OpenFHE 1.4.2 for both FHE variants. All 21 final outputs matched the common plaintext reference and all processes exited successfully.

The professor's supplied complete Boolean circuit covers binary vectors, with length one serving as Count. It does not supply a complete corresponding Sum/Histogram validator; those cells are unavailable. We did not write a replacement and label it his implementation. Prio3 is the pinned library version `0.18.1-alpha.3`, not a claim of conformance to the latest DAP deployment specification.

The results demonstrate functional research circuits and cost observations. They do **not** demonstrate production readiness, a universal BGV improvement, independently established 128-bit security, or a cost/performance win over Prio3. Code/test readiness and production-security readiness are different gates.

The authoritative cost data is in `../evidence/`, summarized by `../RESULTS.md`. Mathematical specifications of the redesigned circuits are in `../../redesign-small-prime142/FORMAL.md`. The copied Count implementation and its qualification are in `../../count-openfhe142/`.

## 2. Design history and decisions

| Decision | Why we considered/adopted it | Cost, alternative and limitation |
|---|---|---|
| Preserve the original paper-core/threshold work | Avoid silently changing the previous implementation and measurements | The optimization is isolated. It must not inherit security claims merely because it reuses modules |
| Native single-key BGV | The retained architecture has one full-key collector; multiparty noise-flooding settings were not an appropriate automatic baseline for this path | Uses normal single-key generation/decryption and a separate startup qualification. It is not threshold security; the existing threshold path is preserved |
| Count projection before general task redesign | Count's observable contribution admits a simpler exact polynomial | It does not expose a validity bit or distinguish valid zero from invalid input |
| p=65,537 | p−1=2^16 makes a Fermat equality test sixteen successive squarings | p alone gives no encryption-security level. The small profile fails an earlier additional conservative screening rule |
| n=32,768 | Compatible fully split BGV batching: 2n divides p−1; library-selected profiles here use this ring | Not proof that it is the smallest secure/working ring. n=65,536 is incompatible with fully split batching at this same prime |
| Scalar Sum and index Histogram | Reduce depth by replacing bit/one-hot uploads with exact finite-domain lookup | New encodings, not unchanged paper Eq. 5. Nonlinear lookup must precede aggregation |
| 13-bit vector chunks | Their domains have at most 8,192 elements, fitting the 16,384-slot SIMD row as repeated lookup tables | A concrete compatible engineering choice, not a proved optimal chunk width. Many separate equality evaluations and rotations remain expensive |
| Gate each decoded bit by all other chunks | A single invalid chunk must zero the whole report | Checking only its own chunk would incorrectly count bits from otherwise valid chunks |
| Balanced factor multiplication | Minimize the multiplication depth of the cross-chunk gate for this factorization | Does not minimize total operations or prove global circuit optimality |
| HYBRID decomposition 7/21/22 | Retain the already executed task-specific compatible profiles | Chosen working configurations, not a complete parameter search or minimal-key proof; large digit counts make long-vector keys huge |
| One-index rotation-key messages | Bound temporary key-serialization allocations and avoid counting cumulative key maps repeatedly | More message overhead; not key compression. Fixed rotation plans are not demonstrated minimal |
| Same SDK/host/threads and loaded keys | Remove known version/machine/per-batch reload asymmetries | One sample still cannot establish stable latency; real deployments may parallelize Prio3's two roles |
| Retain original Boolean STD128/GINX | Compare the supplied professor design without substituting STD192 or a different circuit | Matching a named library target does not prove equal independent attack costs |
| Retain smaller BGV despite screening caveat | User requested this profile and the same named-library criterion, without silent substitutions | Label it a library-targeted research profile; do not call it conservatively certified 128-bit security |
| Do not add threshold collectors or malicious-evaluator proofs | User retained the paper's honest-evaluator/non-colluding-collector model | These are protocol changes and new costs, not accomplished by this circuit optimization |

We did not prove optimality over alternative primes, rings, chunk widths, rotation sets, key-switch settings, bootstrapping, BFV/BGV variants or output packing. The measurements compare these implementations, not the best possible implementations of each cryptosystem.

## 3. Mathematical contract and notation

Let F_p be the field of canonical residues {0,…,p−1}, p=65,537. Let n=32,768 denote the polynomial ring dimension, **not the client count**. Let B denote admitted reports, and L the vector length or bucket count as specified. The batching model uses two rows of n/2=16,384 slots. A ciphertext contains encrypted field elements; polynomial correctness assumes valid encryption/evaluation correctness. A parser accepting a ciphertext does not prove that cryptographic premise against arbitrary adversarial ciphertexts.

The collector is permitted to learn the intended batch aggregate and public task/batch metadata. Diagnostic per-report decryptions and full-slot checks in qualification are test-only observations, not protocol releases. Repeated copies of an intended aggregate coordinate in authorized output slots add no new plaintext function, but this fact alone does not prove ciphertext circuit privacy.

For exact integer counts require B<p; for bounded Sum with bound M require BM<p. For M=100 the algebraic no-wrap limit is B≤655. Count/vector/histogram's analogous limit is B≤65,536. **These are arithmetic limits, not qualified batch capacities.** Noise, memory, operational policy and tested boundaries impose additional limits. The Count API in this study is configured to cap B at 32. The lookup measurement adapters hard-code B=4; they are not general admission endpoints enforcing all possible workload contracts.

### Equality primitive

For a∈F_p define δ_a(x)=1−(x−a)^(p−1) in F_p. By Fermat, a nonzero field element has (p−1)-st power one, while zero has positive power zero. Thus δ_a(x) is exactly 1 when x=a and 0 otherwise. No division or random challenges occur. Primality is essential: for composite modulus 15, x=3 gives 3^14≡9 and 1−3^14≡7, not a zero/one indicator.

Here p−1=2^16, so equality uses sixteen sequential squarings. A circuit using only multiplication of degree-one inputs and additions cannot reach degree 65,536 with multiplication depth below 16, since degree is at most 2^d after depth d. This is a bound for that representation/operation model, not a universal optimality result allowing lookup primitives or bootstrapping.

For any set A of distinct field elements, Σ_{a∈A}δ_a(x) is its membership indicator: at most one summand is one. No cancellation or summation wrap can create a false positive. Repeated SIMD copies of a table are not extra logical summands: rotations sum exactly one table period. More explicitly, for a table period T=2^r, start with S_0(j)=e(j) and update S_{u+1}(j)=S_u(j)+S_u(j+2^u). Induction gives S_u(j)=Σ_{t=0}^{2^u−1}e(j+t), so S_r sums each table position once. This requires periodicity and the power-of-two period used here; summing the whole repeated row would multiply the result incorrectly.

The older randomized residual check with seven repetitions is not used by these optimized predicates. There is no t=7 or claimed 2^−137 validation error here: ideal field validation is exact. That says nothing about encryption failure probabilities or adversarial-ciphertext soundness.

## 4. Exact Count: encoding, algorithm and proof

A report's measurement is x∈F_p; honest Count uses x∈{0,1}. The old masked contribution is

    P(x) = x [1 − (x(x−1))^(p−1)].

Its validity factor is one exactly for x=0 or x=1. Consequently P(1)=1 and P(x)=0 otherwise. The new contribution

    R(x) = 1 − (x−1)^(p−1) = δ_1(x)

has exactly the same values for every x∈F_p. The proof uses field zero/nonzero cases; it does not require treating all nonbinary values as honest bits. Valid zero and invalid values both contribute zero. **R is the aggregate contribution, not the old validity predicate**, whose value at zero is one.

Algorithm (preserved `fhe-paper-core/src/lib.rs`, `fhe-prio3/src/verify.rs`):

1. Decode a report with exact fresh ciphertext metadata; check task/shape and content-derived report identifier.
2. Isolate the evaluator-assigned group using a plaintext mask, before combining reports. If a group is reused, flush the pending ciphertext first.
3. Combine only isolated disjoint groups and apply R slotwise. Unused slots yield R(0)=0.
4. Add contributions from independent flushes; fold groups to the output position and apply the final output mask.
5. Serialize one aggregate ciphertext; collector decrypts only the intended task result.

The nonlinear predicate must not be applied to two reports added in the same logical slot: e.g., R(2)+R(−1)=0, whereas R(2−1)=R(1)=1. Disjoint-group isolation and flushing are therefore correctness conditions, not optional performance choices. The test uses four groups. This packing is different from the lookup variants' per-report evaluation.

Depth accounting at p=65,537: input mask 1, equality 16, final mask 1 gives requested depth 18. At the earlier larger prime, Count's old/new context depths were 24/22; those are different profiles, not the measurements here. Historical 66% size claims mixed security-policy choices; the small-profile result is not an unconditional security-preserving 66% gain.

## 5. Bounded Sum(100): direct scalar lookup

Honest encoding is E(x)=x for integers 0≤x≤100, not the original bit encoding. Define

    F(x) = Σ_{a=1}^{100} a δ_a(x).

F(x)=x on the admissible range and zero for every other field value. Zero's omitted term has weight zero. The aggregate is Σ_i F(x_i), interpreted as an integer only under 100B<p.

Algorithm: isolate slot zero; broadcast its value through the first row; subtract the repeated table 0,…,127; perform sixteen squarings and subtract from one; multiply by weights a for 1≤a≤100 and zero otherwise; sum one period with rotations 1,2,4,8,16,32,64; add report contributions. The second row has zero weights. The resulting first row repeats the one scalar aggregate. Requested depth is 1+16+1=18. Rotations/additions introduce noise/cost but no new ciphertext multiplication depth.

It is wrong to sum raw scalars first and then validate the sum: F(101)+F(−1)=0, but F(100)=100. Each report is validated/decoded before aggregation.

The paper draft's original maximum-100 bit weights are (1,2,4,8,16,32,37); their total is 100. Earlier criticism that its seven binary coordinates necessarily allow 127 was incorrect for that encoding. Our direct scalar lookup is a separate construction, not a repair of that alleged flaw. Historical “bit/slack” shorthand is not an exact description of that draft's Eq. 5.

## 6. Histogram: bucket-index lookup

Honest encoding is a single bucket index b∈{0,…,K−1}; K=3 or 8. Output coordinate a is δ_a(b). This yields exactly one unit contribution for a valid index and all zeros for any invalid index.

Algorithm: mask/isolate slot zero; broadcast the scalar; subtract a table of period next_power_of_two(K); evaluate equality; apply a mask keeping valid bucket positions in row one and clearing padding and row two. Aggregate these vectors, then read the first K positions. Depth is 18. One ciphertext carries repeated copies of the intended aggregate histogram, with zeros in padding. There is no summation across bucket positions.

This is a new wire representation: index decoding is nonlinear. For K=3, adding two indices b=1 before decoding gives a bucket-2 event rather than two bucket-1 events. The paper's linear one-hot aggregation argument cannot be transferred to this encoding before lookup.

## 7. Binary SumVec: chunk encoding and whole-report validation

Partition L bits into m=ceil(L/13) chunks of widths b_h≤13. Honest chunk h is

    z_h = Σ_{k=0}^{b_h−1} 2^k v_{h,k},   0≤z_h<2^b_h<p.

Each chunk occupies its designated scalar slot within one client ciphertext. Authorized slots are chosen by the evaluator, not accepted merely because a client claims them. Define

    V_h(z)   = Σ_{0≤a<2^b_h} δ_a(z),
    D_h,k(z) = Σ_{0≤a<2^b_h, bit_k(a)=1} δ_a(z),
    Y_h,k    = D_h,k(z_h) ∏_{j≠h} V_j(z_j).

V is exact range membership. D is the requested bit for valid chunks and zero for invalid chunks. If all chunks are valid, Y is the original vector. If chunk q is invalid, its own D values vanish; every other coordinate's product contains V_q=0. Thus one bad chunk zeroes the **whole** report. No probabilistic soundness loss is introduced by this field predicate.

Algorithm for each report:

1. Isolate each chunk slot, rotate it to row position zero and broadcast through row one.
2. For each bit, enumerate the distinct domain values with that bit one. Also enumerate the full domain for V. Each table is periodic and a power of two in length.
3. Evaluate δ against every SIMD table entry using sixteen squarings, then sum exactly one period by powers-of-two rotations. No extra bit-selection plaintext multiplication is required.
4. Combine D and the other m−1 membership factors using a balanced tree. Aggregate each output coordinate across reports.
5. Serialize L ciphertexts. The collector decrypts one scalar per ciphertext; row one repeats that coordinate and row two is zero.

For the second row, D's table excludes zero; a zeroed scalar there therefore has D=0. V may equal one there, which cannot change a zero D. This explains the slot-level proof; merely checking slot zero would not establish it. Qualification deliberately populated unauthorized slots and row two, then checked all output slots.

Depth is 17+ceil(log2 m): initial isolation 1, equality 16, then m-factor multiplication depth ceil(log2 m). Context depth is at least 18 in the measured profiles. For m=1, the empty product is one and no cross-chunk multiply is used.

| L | Chunk widths | m | Required depth | Requested depth | HYBRID digits |
|---:|---|---:|---:|---:|---:|
| 10 | 10 | 1 | 17 | 18 | 7 |
| 25 | 13,12 | 2 | 18 | 18 | 7 |
| 50 | 13,13,13,11 | 4 | 19 | 19 | 21 |
| 100 | 13,13,13,13,13,13,13,9 | 8 | 20 | 20 | 22 |

Per report there are 16(L+m) squarings and L(m−1) cross-chunk ciphertext multiplications in this implementation. The actual-call counters in the four-report logs match these formulas. They do not count every library-internal primitive and do not by themselves predict runtime.

This is binary SumVec only. A multi-bit bounded SumVec needs a new encoding/predicate/correctness/parameter analysis. The current construction gives up cross-client packing for lookup tables and emits L output ciphertexts. Smaller uploads do not imply smaller output, keys or total cost.

## 8. Parameter record and what it establishes

All BGV profiles use ordinary single-key BGV with uniform ternary secrets, `FLEXIBLEAUTOEXT`, HYBRID key switching and `HEStd_128_classic`. The separate single-key constructor selects `FIXED_NOISE_MULTIPARTY` rather than the old threshold-noise-flooding mode and uses normal single-key operations. Removing a threshold-mode flag by itself was not the complete fix: retained native codec/startup qualification and the single-key path matter. Multiparty guards were not removed from the old path.

The full ciphertext-modulus Q and extended key-switch basis QP are recorded in every lookup SETUP record. Count's cost log does not repeat its arrays; they are frozen in `count-openfhe142/fhe-paper-core/tests/fixtures/count142_profile.rs` and tested by `count142.rs`. The audit output reproduces all eight profiles' arrays, their sums of log2 moduli, storage bit widths, depth and digits. QP must be considered when assessing public evaluation-key attack surfaces; ignoring auxiliary key-switch moduli is not a justified security shortcut.

| Profile | Q towers | Sum of tower storage bit widths | log2 Q (approx.) | log2 QP (approx.) | Client report bytes |
|---|---:|---:|---:|---:|---:|
| Count/Sum/H3/H8/Vec10/Vec25 | 20 | 754 | 734.586 | 854.586 | 6,176,895 |
| Vec50 | 21 | 793 | 772.586 | 832.586 | 6,496,383 |
| Vec100 | 22 | 832 | 810.587 | 870.587 | 6,815,871 |

The extended-basis budget is not monotone here: decomposition choices differ. These numbers are not attack-cost estimates. “Q storage bits” is the sum of integer bit lengths, whereas log2 Q is the sum of real logarithms; substituting one for the other gives wrong size/security calculations.

For fresh reports with two polynomial elements, the measured packed report size is

    127 + ceil(2 n Σ_t bitlength(q_t) / 8) bytes.

The 127 includes the 56-byte ciphertext header and this report envelope's 71 bytes. It is a formula for this fresh, one-chunk, unauthenticated report, not all future messages or DAP framing. Output ciphertexts use fewer towers and different envelopes, so Count's output size must not be reused for vectors. The 754-bit profile gives 6,176,895 bytes exactly; the later profiles give the sizes above. The serializer retains all coefficients and checks lengths, residues, metadata and fingerprints; it is not lossy compression.

Full Q/QP congruence and primality checks are arithmetic compatibility checks, not RLWE hardness or decryption-noise proofs. Library defaults not explicitly set by the constructor depend on the pinned SDK. Anyone reproducing security estimates must extract the actual error distributions/widths, secret distribution, moduli, decomposition and all relevant samples from the pinned build; p, n and a security-setting string alone are insufficient.

Earlier independent-model screening reported approximately BGV ADPS16 97.24/MATZOV 130.24 bits for the small Count profile and Boolean ADPS16 97.53/MATZOV 120.92 for the original profile. These are historical model outputs, not rerun or independently certified by this audit. New depth-19/20 profiles do not inherit those estimates. We cannot honestly state either “the smaller prime is insecure” or “both implementations provide independently proved equal 128-bit security” from this record. Matching the named library criterion and passing an additional conservative estimator rule are different policies. Apply whichever policy is declared to both systems without silently changing one.

## 9. Measurement logic and comparison limits

The full-cost run uses the same four valid semantic measurements in every available backend. Count sums 0,1,0,1. Sum inputs 0,100,37,63 give 200. Histogram maps client i to i mod K. Binary vectors use `(17*i+31*j+floor(j/3)+floor(i*j/7)) mod 2`. The new verifier reconstructs these independently rather than trusting each log's self-reported expected result.

Setup includes key/context generation, serialization/sizing, installation, constants/codecs and mandatory native qualification. Server time begins with evaluator keys loaded for **all** backends. The older repeated Count comparison charged a per-batch key reload; those timings answer a different question and cannot be merged. Client time covers encryption/proof creation and serialization. Server time includes decode, validation, masking, aggregation and actual output serialization. Collector time includes decode, decrypt/unshard and output extraction. Plaintext-reference checking, extra diagnostic decryption and progress logging are outside core-stage timers; whole-process wall/CPU/RSS include additional work and cleanup.

Prio3's two roles execute serially and verifier artifacts use actual library serialization/decoding, without a network. Sum of role work is not parallel deployment latency. FHE roles also share one measurement process; this is not proof of separate operating-system trust domains. Whole-process peak RSS is not evaluator-only memory. Key bytes are serialized object sizes, not peak resident key allocations.

Prio3 report bytes count public share plus two input shares, excluding nonce and transport. The logs also account separately for duplicated public shares and nonces. FHE uses its prototype encoding. These are declared core payloads, not identical complete DAP messages. Shared honest-input output semantics are matched; malformed-input handling and input domains are **not** identical: Prio3 proof rejection is different from FHE silently zeroing an invalid plaintext, and Boolean's Z4-style validation domain differs from BGV's F_65537. No theorem of full protocol equivalence follows from equal honest aggregates.

For four reports Boolean uses three sum bits per coordinate. The counter width, gate count and output sizes are tied to this batch size. Its validation/masking plus ripple addition uses 28L bootstrapped gates in the adapter. This does not prove negligible Boolean gate/decryption failure probability or secure handling of arbitrary non-honestly-generated ciphertexts.

At L=100 the observed BGV report is 6,815,871 bytes **per client**, the collector bundle is 58,169,101 bytes per batch with 100 ciphertexts, and evaluation keys total 7,429,158,368 bytes. Server work is about 2,763 seconds per four-report batch. These actual costs prevent a credible claim that the redesigned long-vector circuit is currently a practical performance replacement for Prio3. FHE's architectural reduction of one aggregation role is a different benefit, conditional on trust/deployment needs, and has not been converted into measured monetary or operational savings.

One observation per configuration has no measured variance or confidence interval. Very short Prio timings can be dominated by timer/startup/cache effects. Do not infer stable speed ratios or a crossover outside measured lengths. Even size crossovers need a qualified profile, input semantics and an explicit per-client versus cross-client packing distinction.

## 10. Evidence review, errors and unresolved risks

| Finding | Reason and consequence | Required treatment |
|---|---|---|
| Original encoding and lookup encoding were sometimes conflated | Original linear decoding/aggregation arguments do not apply to nonlinear index/chunk lookup | Specify new encodings and the proofs above; evaluate before aggregation |
| “Count shortcut is a validity flag” is false | R(0)=0 while zero is valid | Claim contribution equivalence only; no validity-rate release |
| “One or 100 reports costs one upload” is false | Each client encrypts and sends its own report | Multiply per-client bytes by client count, separately from evaluator packing |
| “Same Count size at every vector length” is false | Depth/digit profiles change and output has L ciphertexts | Use actual task-specific bytes and full Q/QP |
| “All 21 passed means production GREEN” is false | Valid-input cost tests do not cover protocol security or negligible failure rates | Label finite correctness/cost evidence only |
| Prior claimed missing Sum100 range constraint was mistaken for the draft reviewed | Weights (1,2,4,8,16,32,37) total 100 | Do not repeat the earlier 127 criticism |
| Historical redesign results say complete cost measurements are pending | They predate the full-cost run | Current `full-cost142/RESULTS.md` supersedes that sentence, not the earlier raw data |
| Historical documents say “no push” | True when those snapshots were made; publication occurred in 8972e72 | Read as historical state, not current repository status |
| All-primary-cost inputs are valid | Matching outputs is not a hostile-input campaign | Cite separate invalid/unauthorized-slot qualification without counting it as timed samples |
| Vector encrypted invalid test changes only selected chunks/cases | Formula covers all fields ideally; ciphertext execution is finite | Add encrypted boundary/multi-invalid tests and multiple keys before broader reliability claims |
| Count cap 32 is a configured scope | No-wrap arithmetic alone does not bound noise/latency | Do not call it the mathematical maximum or qualify all tasks at 32 |
| No batch-zero workload measured | Count evaluator refuses empty finish; other adapters fix B=4 | Define deployment empty-batch behavior before API generalization |
| Small-prime no-wrap does not prevent replay | Duplicates can be mathematically valid contributions | Authentication, replay ledger, epochs and release policy need a separate endpoint layer |
| Hash report ID/fingerprint is not authentication | Publicly computable metadata binds bytes/context, not sender authorization | Do not claim unique users, authorization or honest encryption |
| Ordinary decoding is not malicious-ciphertext soundness | Valid residues/metadata can still form adversarial algebraic ciphertexts | Need a suitable encryption-validity proof/protocol analysis or an explicit restricted-client assumption |
| Output plaintext isolation is not circuit privacy | Full-key collector also sees ciphertext structure/noise | Require a circuit-privacy argument/transformation and noise bounds; no numerical bound is certified here |
| Honest evaluator is an explicit security assumption | A malicious evaluator could substitute an individual ciphertext/aggregate | Retain limitation; signatures alone do not prove aggregate correctness |
| Non-collusion is still required | A full-key collector receiving client ciphertexts can decrypt them | Control access and retain architecture assumption; threshold redesign is separate |
| Setup/codecs use fixed task IDs in adapters | Not deployment task/key-epoch negotiation | Bind authenticated task, profile, key epoch and permitted outputs in a real endpoint |
| Complete-circuit noise headroom is not proved | Additions, rotations and plaintext multiplications affect noise beyond depth | Need failure analysis and boundary/repeated-key tests, not just one passing batch |
| Rotation plans and chunk width are not optimality results | Unused/minimizable rotations or different table plans may exist | Explore separately, preserve baseline and repeat qualification for any change |
| No independent estimator execution in this audit | Integer checks cannot establish lattice attack costs | Reproduce with pinned estimator/model inputs; explicitly retain non-certification |
| Earlier failed/OOM candidates exist | Working profiles were selected during development | Preserve failures; do not mix failed native/packed sizes or concurrent-run timings with primary matrix |
| Baseline settings differ across historical experiments | Threshold, single-key, packed/native serialization and SDK versions change costs | Identify exactly which baseline is used for each claim |

We did not find a contradiction in the ideal-field Count or lookup formulas under their stated assumptions. This is a scoped review, **not a claim that all possible implementation or cryptographic errors have been found**. The remaining security gaps are material. They cannot be closed by editing prose, adding a checksum or declaring the library's label sufficient.

### Exact scope of earlier encrypted qualification

| Evidence | Executed coverage | What it does not establish |
|---|---|---|
| Preserved Count port | 24 wrapper + 170 protocol + 5 selected Count tests passed; one optional measurement ignored | Not 199 independent cryptographic-security proofs; inherited threshold tests are not automatically single-key security arguments |
| Redesigned Sum | 40 primary encrypted reports, including boundary/invalid values and a 32-report all-maximum batch | Not a negligible decryption-failure bound or production malicious-ciphertext soundness |
| Histogram | Five reports each at K=3,8, including invalid indices | Not qualification at all arithmetic-allowed batch sizes |
| Redesigned vector | Two reports at each supported L, including a whole-report-invalid case; additional two-report L10 packaging regression | Not exhaustive encrypted combinations or B=32 qualification |
| Full cost matrix | 21 cases × four valid reports = 84 report evaluations | Does not replace invalid-input tests or repeated timing trials |

Repeated use of the same module across test suites is not independent implementation diversity. The independently written integer checker strengthens the algebra/evidence audit, but still relies on the supplied records for claims about past encrypted execution. Raw report/output ciphertext blobs are not archived in the full-cost evidence; serialization lengths are logged at execution, checked against formulas where available, and can be independently remeasured by rebuilding/rerunning. Do not describe a log checksum as an independent measurement of those ciphertext blobs.

No secret-key bytes are intentionally published in the evidence; only their serialized lengths are recorded. Ordinary buffer overwriting in measurement code is not a demonstrated compiler-resistant secure-erasure guarantee or a production key-management policy. Protocol proof/security constants in inherited threshold modules must be assessed in their own scope; their existence is not evidence that this proof-free single-key measurement adapter has 128-bit malicious-client soundness.

## 11. What was checked again and what an independent reviewer can do

The audit verifier performs these fresh checks:

* SHA-256 checks over the three committed optimization trees, including this audit's source/text and raw evidence. The manifest excludes itself to avoid a circular hash.
* Deterministic unsigned-64-bit primality checks of p and every logged Q/QP tower; batching/root congruences and unique tower/basis-prefix checks. This is compatibility evidence only.
* Both Count polynomials on all 65,537 field values. Fermat's zero indicator on all field values. The **full 100-term Sum polynomial** on every field input, and Histogram(3,8) equality outputs on every field input.
* All bit-subset table definitions and canonical chunk encodings for widths 1…13. Every possible binary valid/invalid pattern for the supported m=1,2,4,8 chunks, including every possible D value allowed by the pattern. These are not exhaustive enumeration of all field vectors or all ciphertexts.
* All 21 raw process/final-PASS records, reconstructed common expected outputs, stage-time consistency, report counts and actual output counts. The published CSV is cross-checked against raw sizes, key sizes, timings and RSS. Profile/depth/digit/size formulas and vector actual-call counts are checked separately from each program's own expected values.

From the repository root:

```sh
python3 optimization/full-cost142/audit/verify_claims.py > /tmp/fhe-audit.json
cmp /tmp/fhe-audit.json optimization/full-cost142/audit/CHECKS.json
(cd optimization && sha256sum -c full-cost142/audit/SHA256SUMS.txt)
python3 optimization/count-openfhe142/verify_originals.py
python3 optimization/redesign-small-prime142/check_algebra.py
```

The first checker takes longer than a checksum because it evaluates millions of actual modular powers. It requires Python 3 only, not OpenFHE or Sage. It does not mutate the input files. `CHECKS.json` records the deterministic output and full parameter arrays. The older preservation checker additionally needs the previously tracked `optimization/count/` baseline, available in this repository.

To independently **reproduce encrypted execution**, install the pinned SDK/dependencies as documented by the port, run its qualification, then build and run the full-cost harness using `../README.md`. The current scripts assume the recorded `/workspace` SDK/build layout and offline dependency cache; a fresh machine needs that environment provisioned, not merely this checker. The long-vector cases require substantial RAM/time. Do not run them concurrently or mix new runs into the frozen evidence folder. Use a new output directory and keep all failures. Rebuild binary hashes may differ with toolchain/environment; source hashes and functional/profile checks are separately meaningful.

A checksum proves that reviewed bytes match the manifest. It does not prove the data was honestly measured, the source compiled to the reported binary, a theorem is correct, or a cryptosystem is secure. Independent execution, source review and a reproducible parameter-security analysis remain separate steps. There is no substitute for them in this document.

## 12. Remaining work before stronger claims

1. Publish the new encoding/functionality definitions and retain the honest-evaluator/non-collusion scope explicitly.
2. Reproduce complete cryptographic parameters and independent attack-model estimates under the same declared policy for Boolean and BGV, including extended key-switch bases and actual distributions.
3. Establish a suitable malicious-client/ciphertext security argument and circuit privacy, or explicitly restrict the claim. Neither is solved by exact field predicates.
4. Analyze complete-circuit noise and supported batch limits; test multiple fresh keys, maximum declared workloads, cross-slot boundaries and combined invalid inputs.
5. Repeat matched performance measurements with enough samples for variability and clearly separate loaded-key amortization, setup and actual deployment/network overhead.
6. Treat replay/authentication, resource limits, task negotiation and release policy as endpoint work, separate from these fixed-input measurement adapters.
7. If claiming an operational win over Prio3, measure one in a specified deployment. Fewer aggregation roles is an architectural observation, not a demonstrated lower bill or higher throughput.

The technically defensible present claim is: **these exact alternative encodings work for the tested encrypted tasks, their complete declared core costs were measured, and their limitations are explicit.**
