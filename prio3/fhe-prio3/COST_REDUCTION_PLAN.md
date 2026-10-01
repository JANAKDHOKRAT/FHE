> **Update 2026-10-01.** Superseded for silent mode by the batch-level
> circuit (spec §6b, "Batched silent mode"): per report the aggregator now
> masks the ciphertext to its group's slots, adds it into a batch
> accumulator, and the circuit runs once per batch. Measured 712 ms
> (Count) and 744 ms (Sum(100)) per report per aggregator with 64-report
> batches, 425–428 ms with 256, against the 4.75 s and 4.66 s below. The figures below are kept as the record of the
> earlier design and its measurements.

# Cost reduction plan for silent mode

Target: the slow path, silent mode, measured at **16.2–16.8 s per report per
aggregator**, 29 MiB per report, 18 rotation keys of 111 MiB, 72 s ceremony
(4 vCPUs, ring 65536, `p = 786433`, `k = 4`, depth 25 of a depth-25 context).

Per report the circuit as written performs, counted from `verify.rs`:

| operation | count | where |
| --- | --- | --- |
| ciphertext × ciphertext | 24 | 1 (`x(x-1)`) + 20 (Fermat: `E^3`, 18 squarings) + 2 (class product) + 1 (`x · valid`) |
| ciphertext × plaintext | 8 | 2 per repetition |
| rotation | 18 | 3 (place repetitions) + 13 (class sums, `log2 8192`) + 2 (class product) |

Every idea below went through the same four checks: (1) does the math and
the security argument survive unchanged; (2) can it be built with OpenFHE
1.3.1 and the code in this repository; (3) what does it change, counted in
operations, levels or bytes, with measured numbers where we have them and
labelled estimates where we do not; (4) verdict. Ideas that fail a check
are dropped and the reason is stated.

**Status after implementation.** A1 (batched chain) and A2 (`EvalSquare`)
are implemented; see the spec, section 6b, for the final A1 design, which
differs from the sketch below in one important way: each report is masked
to its own group *before* the final multiply and folded onto group 0 at the
cheap level, so no selector and no operation past the configured depth is
needed. The "gate" C5 is therefore an ordinary worst-case correctness test
at depth 25 (`batched_silent_worst_case_inputs_gate`), which passes. B1,
B6 (policy), B7 (one key per batch is the node default) and B8
(persistence) are implemented in `fhe-prio3-node`. B3 (native build) is
measured in the spec's performance section. Measured numbers replace the
estimates in the spec, not here.

Facts established by experiment for this plan:

* No prime `≡ 1 (mod 2^17)` exists below 786433 (enumerated).
* OpenFHE chooses ring 65536 up to depth 25 and 131072 at depth 26 for this
  prime (probed).
* One operation past the configured depth (a plaintext or ciphertext
  multiplication) still leaves 3 RNS limbs and decrypts correctly under
  noise flooding (probed at depth 3: `x^4` at the last level, then
  `x^4 · [1,0,1]` and `x^5` one level further, all correct). This is an
  observation, not a guarantee from OpenFHE's parameter selection.
* This machine has AVX-512 (`avx512f/bw/cd/dq/vl`). OpenFHE 1.3.1's CMake
  has `WITH_NATIVEOPT`; it has no Intel HEXL option.
* `EvalSquare`, `EvalMultNoRelin` and `Relinearize` exist in the API.

## Part A. Fifteen approaches at the circuit and parameter level

### A1. Share the Fermat chain across a batch of R reports — **implemented; measured 3.5×**

Measured with `R = 64`: 4.75 s (Count) and 4.66 s (Sum) per report per
aggregator against 16.8 s, including the batch close. The estimate below
(2–3 s) was optimistic: the un-amortised per-report work is a larger share
than the operation count suggested. The final design (spec, section 6b)
masks each report to its group before the final multiply and folds at the
last level, so it needs neither the selector nor the extra level discussed
below; that text is kept as the record of the analysis.

The 20 Fermat multiplications and the class product act slot-wise and do not
depend on the report. If the check values of R reports occupy disjoint slot
classes of one ciphertext, one chain serves all R.

*Layout.* Row of `row = N/2` slots; `R` a power of two; `block = row/(4R)`
elements per report (so `m ≤ block`). Report `r`, repetition `j`, element
`i` lives at slot `j + 4r + 4R·i`. The client is assigned `(r, R)` before
encrypting and packs element `i` at slot `4r + 4R·i` (repetition 0). The
aggregator places repetitions 1..3 with rotations by `-1, -2, -3` after
multiplying by the coefficient plaintexts (coefficients first, rotation
second, as today: untrusted slots never enter the sum). Class sums use
rotations by `4R·2^t`, `t < log2(block)`, which wrap the whole row, so every
slot of class `(r, j)` holds `E_{r,j}` and there is no junk, exactly as in
the current interleaved layout with `4R` classes instead of 4.

*Check 1, math.* `E_{r,j}` is the same random linear combination as today;
Fermat and the product over `j` (rotations by 1 and 2 stay inside
`4r..4r+3`) give `valid_r` in every slot `4r + 4R·i`. `y_r = x_r · G` is
non-zero only at report `r`'s slots. The batch sum `Σ_r y_r` therefore holds
the reports *separately*; decrypting it would reveal each report, so the
groups must be folded first: rotations by `4·2^t`, `t < log2 R`, put
`Σ_r x_{r,i}·valid_r` in slot `4R·i` but leave partial sums over subsets of
reports in the other slots. Those slots must be zeroed with a plaintext
selector before decryption. That selector costs one level: `2 + 20 + 2 + 1
+ 1 = 26` on a depth-25 context. It is the "one operation past depth" case
probed above. Soundness and the per-report zero contribution are
unchanged; the additional requirement is that the selector multiplication
decrypts correctly, which must be validated statistically (Part C, C5)
because OpenFHE's noise analysis only covers the configured depth. If that
validation fails the fallback is a depth-26 context at ring 131072, which
removes most of the gain; the plan is not worth doing unless C5 passes.

*Check 2, implementable.* Yes: layout, challenge placement, one batch
accumulator, an `(r, R)` assignment in the report admission, fold and
selector at batch close. Rotation keys: `-1, -2, -3`, `4R·2^t`
(`log2 block` keys), `1, 2`, `4·2^t` (`log2 R` keys): about the same count
as today.

*Check 3, cost.* Per report: 1 full ciphertext multiplication, 8 plaintext
multiplications, 3 full rotations, and one multiplication of a 4-limb
ciphertext (`x_r · G`, after OpenFHE drops `x_r` to `G`'s level). Per batch:
`log2 block` rotations, 20 Fermat multiplications, 2 rotations and 2
multiplications for the product, `log2 R` cheap rotations and one plaintext
multiplication at the end. With `R = 64` and Sum(100) (`block = 128`): per
report `1 + 22/64 ≈ 1.3` full multiplications and `3 + 9/64 ≈ 3.1` full
rotations instead of 24 and 18. That is roughly nine times fewer heavy
operations. Estimated time 2–3 s per report per aggregator; to be measured,
not promised. Capacity: `R ≤ row/(4·next_pow2(m))`, i.e. 512 for Sum(100),
8192 for Count, 4 for SumVec(1200, 4 bits).

*Check 4.* Implement, gated on C5.

### A2. `EvalSquare` for the 18 squarings — **implemented, no measurable gain**

Check 1: identical arithmetic (tested equal to `mult(a, a)`). Check 2:
`EvalSquare` exists; one shim function. Check 3: a squaring skips half of
the tensor product; the key switch, which dominates, is unchanged.
Measured: 16.8 s per report with `EvalSquare` against 16.2–16.8 s without,
i.e. within run-to-run noise. Kept because it is free and correct; it is
not a cost reduction.

### A3. Smaller plaintext prime for a shorter Fermat chain — **drop**

Check 1 fails on availability: 786433 is the smallest prime `≡ 1 (mod
2^17)`; the next ones (1179649, 2752513) have longer chains (21, 22).
Primes `≡ 1 (mod 2^16)` such as 65537 (chain 16) only pack for rings up to
32768, whose security bound (`log q ≤ 881`) fits about depth 15, not 22.

### A4. Lower-degree zero test — **drop**

Check 1 fails: a polynomial `f` over `F_p` with `f(0) = 1` and `f(x) = 0`
for all `x ≠ 0` has `p − 1` roots, so degree `≥ p − 1`. `E_j` is uniform in
`F_p` when non-zero, so no smaller domain can be assumed.

### A5. Three repetitions instead of four — **drop**

Check 1: soundness `3·19.58 = 58.7` bits, below Prio3's Field64 (`≈ 62`).
Check 3: saves 2 plaintext multiplications and 1 rotation per report, about
3 %. Not worth the soundness.

### A6. One random scalar for the linear constraint instead of one per repetition per slot — **drop**

Check 1 fails in a corner: with `E_j = ⟨r_j, (x_i(x_i−1) + λ_j c_i x_i)_i⟩ + λ_j c_0`,
a non-bit vector with `x_i(x_i−1) = −λ_j c_i x_i` for all `i` gives
`E_j = λ_j c_0`, which is zero whenever `c_0 = 0` (Sum with
`max_measurement = 2^bits − 1`). Saves 4 plaintext multiplications
(≈ 0.2 s). Soundness case analysis is not worth 1 %.

### A7. Lazy relinearisation (`EvalMultNoRelin` + one `Relinearize`) — **drop**

Check 3: it helps when several products are summed before relinearising.
The Fermat chain is a sequence of dependent squarings; `x(x−1)` is a single
product. Nothing to batch.

### A8. Different exponent chain for `p − 1 = 3·2^18` — **drop**

Check 3: any chain for exponent `786432` needs at least `⌈log2 786432⌉ = 20`
levels; `E^3` then 18 squarings, or 18 squarings then a cube, are both 20.

### A9. One Fermat test for the whole batch — **drop**

Check 1: testing `Σ_r ρ_r E_{r,j} = 0` says only whether *all* reports are
valid. It cannot zero the invalid ones, so one malicious report would void a
batch: a denial of service Prio3 does not have.

### A10. Avoid the final `x · valid` level — **drop**

Check 1: `x_r` has to be multiplied by the last product; the level is the
maximum of the operands plus one. Folding `x` into a leaf of the product
tree does not lower the tree's depth.

### A11. Bootstrapping to lift the depth ceiling — **drop**

Check 2: OpenFHE 1.3.1 has no BGV bootstrapping.

### A12. Switch scheme (BFV, CKKS) — **drop**

Check 1/2: CKKS is approximate, so the exact zero test is impossible. BFV
needs the same modulus for the same depth and has no cheaper ciphertexts at
lower levels; the level-25 sums that are 4.5 MiB here would stay full size.

### A13. Fewer rotation keys by composing rotations — **optional**

Check 1: rotations compose exactly. Check 3: e.g. class-sum keys
`4R·2^t` for even `t` only, each odd rotation done as two: halves the
class-sum keys (memory −0.7 GiB) for `+log2(block)/2` rotations per batch,
which under A1 is amortised. Check 4: implement only if the 2.1 GiB per
aggregator is a problem in deployment; it is a memory/time trade with no
security effect.

### A14. Bit-packed transport of ciphertexts — **implemented, measured** (spec §6b)

Check 1: lossless, and verified exact on every object kind the protocol
exchanges. Check 2, corrected: the premise here was wrong. The moduli are
not all 48-bit. Measured limb widths are 48, 60, 60, 55, 55, 55 and 17
bits in verdict mode. In silent mode they are 36, 60, 60, then 25 limbs of
44 bits, then 21. Packing each tower at its own width saves 21.9 % in
verdict mode (3,672,149 → 2,867,256 bytes per chunk) and 31.2 % in silent
mode (30,414,913 → 20,922,424 bytes). It was built as an own serializer of
the limbs through the shim, not as a parser of the cereal layout. Check 3,
also corrected: there is a CPU gain on the receiving side. Parse and
rebuild take 4.6 ms against 22.9 ms for OpenFHE's deserializer in verdict
mode, and 53.8 ms against 124.0 ms in silent mode. What decided it was
not bandwidth: OpenFHE's loader crashes on mutated input (16 of 2,400
mutants), and with the packed format no received byte reaches it.

### A15. Clients pre-place repetitions (send four rotated copies) — **drop**

Check 1: the aggregator must apply the coefficients before any rotation;
a client-supplied rotated copy is not verifiably a rotation of the same
plaintext. Rejected on soundness.

## Part B. Twelve ideas at the system and deployment level

### B1. Batch pipeline: verify in groups of R — **implement (needed by A1)**

Silent mode produces nothing per report, so waiting until `R` reports have
arrived costs latency only. Admission (signature, quota, replay, structure)
still runs per report on arrival. Check 4: implement with A1.

### B2. Parallel evaluation of independent reports in one process — **test before use**

Check 2: OpenFHE parallelises inside each operation with OpenMP; whether
concurrent operations on distinct ciphertexts sharing one context are safe
is not something this repository has tested, and the Rust `Context` is
deliberately `!Sync`. Check 3: on 4 vCPUs the inner parallelism already
uses the cores partly; the gain is unknown. Check 4: write the test (two
threads, two reports, compare with serial results and check for crashes
over 100 runs); enable only if it passes. Do not assume.

### B3. Build OpenFHE with `WITH_NATIVEOPT=ON` — **measured, no gain, not adopted**

Check 2: the option exists and the CPU has AVX-512. Check 3, measured:
4.75 s against 4.75 s per batched silent report and 690 ms against 598 ms
per verdict report (default build faster, within noise). OpenFHE 1.3.1's
NTT does not vectorise further with `-march=native` here. Check 4: keep
the default build.

### B4. Intel HEXL — **drop**

Check 2: not an option in this OpenFHE version's build.

### B5. GPU — **drop**

Check 2: no GPU backend in OpenFHE 1.3.1.

### B6. Tiered verification policy — **implement (policy, not code change)**

Enrolled institutional clients with contracts use verdict mode (0.5 s);
anonymous or device clients use silent mode. Check 1: each tier keeps its
own stated guarantees; the mix does not weaken either. Check 4: a
per-client policy field in the registry.

### B7. Several batches per key in silent mode — **implement as a configurable bound**

Check 1: batch close is the only decryption in silent mode (count and
sums), so the number of decryption-oracle queries per key is the number of
batches, not reports. Reusing a key for `b` batches multiplies that by `b`
and amortises the 72 s ceremony. Check 4: `batches_per_key` in the config,
default 1, documented as the exposure knob.

### B8. Persist aggregator state — **implement (engineering)**

Sums, counter, seen ids and quotas to disk after each batch step, so a
crash does not lose 16 s of work per report. No cost effect; production
requirement.

### B9. Run the fast verdict check first and silent mode after — **drop**

Check 1 fails: the fast check reveals the verdict, which is the leak silent
mode exists to remove.

### B10. Trust a client-side validity hint — **drop**

Check 1 fails: clients are the adversary the check is for.

### B11. Encrypt at a lower level to shrink reports — **drop**

Check 1: the circuit needs the full 25 levels from a fresh ciphertext.

### B12. Overlap plaintext encoding with evaluation on a second thread — **optional**

Check 3: the 8 coefficient plaintexts per report cost NTTs of about 10–20 ms
each; under A1 they are 8 of the ~12 remaining heavy-ish operations per
report, so overlapping them is worth up to 5 %. Only after B2 is settled.

## Part C. Fifteen ways to get there, in order

1. Add `tbgv_eval_square` to the shim and use it in `Circuit::fermat` (A2).
   Measure before/after with `simulate --mode silent`.
2. Rebuild OpenFHE with `WITH_NATIVEOPT=ON`, rerun both suites and the
   simulator (B3). Keep only if the numbers improve.
3. Add `LayoutKind::Batched { r, R }` with the slot formula of A1, the
   rotation index set, and unit tests of the cyclic closure of class sums
   (a plaintext model of the rotations over the row).
4. Add slot assignment to admission: a silent-mode aggregator hands each
   admitted report a group index `r` deterministically from its arrival
   order in the batch; clients request `(r, R)` before encrypting. Every
   aggregator derives the same assignment from the same admitted order
   (the batch is defined by the ordered list of report ids).
5. **Gate test for the extra level (C5).** Build a depth-25 context, run
   the full A1 circuit on worst-case inputs (all coefficients `p−1`,
   `x = p−1` in every slot) 1000 times with fresh keys and fresh
   encryptions, and check that the level-26 selector product decrypts
   correctly every time. If any run fails, stop A1 and record it.
6. Implement the batch accumulator: per report `x(x−1)`, coefficient
   multiplications, 3 placement rotations, add into `T`.
7. Implement batch close: class sums, one Fermat chain, product, per-report
   `y_r = x_r · G`, fold over groups, selector, add into the sums and the
   counter.
8. Extend the collector to decode from slot `4R·i` and verify the count
   as today.
9. Tests: an honest batch of R with two invalid reports (contribute zero);
   a batch where one report's ciphertext carries overflowing noise (the
   consistency check rejects the batch); cross-report isolation (the
   cancellation pair placed in another report's slots does not change the
   victim's validity); `R = 1` reproduces today's numbers.
10. Measure with `simulate --mode silent --batch 64` for Count, Sum(100),
    Histogram(64); replace the estimate in this document with numbers.
11. Add `batches_per_key` (B7) and persist state between steps (B8).
12. Add the per-client tier field to the registry and the policy switch
    (B6).
13. Write the thread-safety test for concurrent evaluation (B2); on
    success make an explicit `SyncContext` wrapper with the tested
    operations only.
14. Done: packed transport encoding with per-tower widths (A14), applied
    to every ciphertext exchanged during operation (reports, masks, all
    partial decryptions), with round-trip and attack tests.
15. Optionally halve the class-sum keys by composition (A13) if memory
    per aggregator has to drop below 2 GiB.

## Part D. Added after the plan: horizontal sharding — **implemented, measured**

Not in the fifteen approaches or twelve ideas above; requested afterwards
as the deployment-level lever left once per-set cost was measured.

Check 1 (math): a shard is a whole task with its own id and joint key;
the only cross-shard operation is adding released plaintext results, which
is exact in the integers (`sharding::combine_results`, unit-tested
including regression refit). Check 2 (crypto): every report, challenge,
signature and share is bound to the task id, so nothing built for one
shard is usable in another; each shard's argument is the single-set
argument of the spec unchanged. Found and fixed while testing: a repeated
close produced a second noise-flooded partial decryption of the same
ciphertext (aggregators now release each partial decryption once and
persist it), and the sharded client trusted the router for the joint
public key (material is now attested by every aggregator and clients pin
the aggregators' identity keys). Check 3 (cost, measured with real processes and pinned
threads, `fhe-prio3-node/tests/sharded.rs`): 2 shards at one thread each
finish 16 reports 1.6–1.8× faster than 1 shard; under a fixed 4-thread budget
only 1.1×, since one shard already uses all cores. Check 4: adopted, as
the scaling path across machines; it does not make one machine faster.

## What this plan does not claim

* The 2–3 s estimate for A1 is derived from operation counts and will be
  replaced by a measurement; the true figure depends on the relative cost
  of rotations and multiplications at ring 65536, which we have measured
  only in aggregate.
* A1 depends on step C5. If OpenFHE's noise margin does not cover the
  selector multiplication reliably, A1 is not viable at ring 65536 and
  silent mode stays at its current cost.
* None of the ideas changes the two limits stated in the spec: no proof of
  plaintext knowledge, and silent mode detects but cannot attribute a
  non-encryption.
