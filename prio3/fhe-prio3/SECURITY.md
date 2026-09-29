# FHE-Prio3: security argument

This document states what the system claims, under which assumptions, and
why each claim holds, with proof sketches at the level of detail an
external reviewer can check line by line against the code. It is **not** a
machine-checked proof and it is **not** an external audit: it was written by
the authors of the code. `AUDIT.md` describes how an external audit should
proceed and what we found when we attacked the system ourselves.

Notation: `n` aggregators, plaintext modulus `p` (`t` in FHE notation),
ring dimension `N`, `R_t = Z_t[X]/(X^N + 1)`, which splits into `N` slots
because `p ≡ 1 (mod 2N)`. `w_s` is the value of the plaintext `X` in slot
`s`; every `w_s` is a primitive `2N`-th root of unity mod `p`.

## 1. Parties, adversary, goals

Parties: clients, `n` aggregators (each holding one additive share `s_i`
of the joint BGV secret `s = Σ s_i`), collectors (no key share), and in a
network deployment a leader (aggregator 0) that relays messages and a
router (sharded deployments) that relays nothing secret.

Adversary: static, may corrupt any set of clients, up to `n − 1`
aggregators, any collectors, the leader's relay role and the router, and
controls the network (subject to TLS and the protocol's own signatures and
sealing). It may deviate arbitrarily (malicious), except where an
assumption below says otherwise.

| Goal | Statement |
|---|---|
| **R1** robustness against clients | An invalid measurement enters no aggregate, except with probability `≤ (2/p)^k` per report (`k` repetitions). |
| **R2** robustness against aggregators | A malicious aggregator cannot make an invalid report accepted in verdict mode, except with probability `≤ 1/p` per repetition whose check value is nonzero (§4.1). It cannot change the decrypted valid count (silent mode) or a released aggregate without the verifier aborting, except with probability `≤ 2^-80` per verification (§4.2). It **can** make valid reports rejected and stop the protocol (n-of-n). |
| **P1** input privacy | A coalition of up to `n − 1` aggregators, any collectors and any clients learns nothing about an honest client's input beyond the released aggregates of batches with at least `min_batch_size` **valid** reports, plus the leakage listed in §6. |
| **K1** key secrecy | No coalition of fewer than `n` aggregators learns the joint secret key or an honest share. |
| **K2** key integrity | Keys produced by the distributed ceremony decrypt, relinearize and rotate correctly, or the ceremony aborts. |

## 2. Assumptions

| # | Assumption | Where it is used |
|---|---|---|
| A1 | Decision-RLWE is hard for OpenFHE 1.3.1's parameters at `HEStd_128_classic` (ring dimension and modulus chosen by OpenFHE from the depth). | semantic security of every ciphertext (P1), hiding of the check exponents (R2), security of key contributions (K1) |
| A2 | OpenFHE's `NOISE_FLOODING_MULTIPARTY` partial decryptions are statistically simulatable from their fused plaintext for ciphertexts whose noise is within the bound OpenFHE's parameters assume, for the number of partial decryptions per ciphertext the protocol makes (§5). | P1, K1 |
| A3 | Every key contribution in the ceremony is well formed (small secret, noise from the specified distribution). **Not verified by the protocol** (§6.2). | A2's noise bound; K2 at depth |
| A4 | SHA-256 is collision resistant and, for commitments to high-entropy values, modeled as a random oracle (hiding). SHAKE128 is a random oracle for challenge and CRS expansion. | R1 (Fiat–Shamir), R2 (commitments), K1/K2 (CRS, commitments) |
| A5 | Ed25519 is EUF-CMA; X25519 + HKDF-SHA256 + AES-256-GCM is IND-CCA as a KEM-DEM. | ceremony and attestation authenticity; sealing to collectors |
| A6 | OpenFHE 1.3.1 implements BGV-RNS as documented. The build is gated to that version, and a start-up self-test checks exact rebuild of every exchanged object at every level the task uses. | everything |
| A7 | Honest parties run this code on hardware and operating systems that do not leak their shares; TLS authenticates peers. | everything |

## 3. Robustness against clients (R1)

Unchanged from `FHE_PRIO3_SPEC.md` §4.1: for an invalid `x`, each
repetition's `E_j = <r_j, v(x)>` is zero with probability `1/p` over the
Fiat–Shamir challenge, and the revealed `E_j ρ_j` is zero with probability
at most `2/p`. The range of every linear constraint over 0/1 slots is
checked not to reach `±p` (`check_constraints_fit`), so arithmetic mod `p`
equals arithmetic over the integers. Tests: `tests/protocol.rs`,
`tests/bounds.rs`, `types.rs::constraint_fit_is_exact_on_every_assignment`.

## 4. Robustness against aggregators and verifiable decryption (R2)

Every decryption in the protocol fuses one partial decryption per
aggregator. A malicious aggregator can replace its partial by any value.
Three places consume decryptions, and each now has a defence.

### 4.1 Verdict mode: no forced acceptance (commit-then-reveal)

**Attack (demonstrated, `tests/malicious_aggregator.rs::verdict_forced_acceptance_needs_an_adapted_partial_and_is_refused`).**
The fused verdict value is `c_0 + Σ_i π_i`. An aggregator that sees every
other partial before sending its own sets
`π_mal = −c_0 − Σ_{honest} π_i + (0 in the result slots)` and the honest
aggregators accept an invalid report.

**Second attack (demonstrated,
`verdict_mask_cancellation_needs_the_honest_mask_and_is_refused`).** Masks
used to be sent in the clear in round 1. An aggregator that received the
honest masks first (for example the leader, which relays them) could send
`Enc(r) − Σ honest masks` and fix the combined mask to any `r` it chose.
With `r = 0` every invalid report is accepted. With a known `r ≠ 0` the
decrypted `u` is `E_j · r`, which reveals the check value `E_j` itself
instead of one bit. Combined with the malleability of §6.1, `E_j` for a
related report `x + δ` is a known linear function of the honest bits `x`:
up to `k` field elements about an honest input per forged report, not one
bit.

**Defence.** Two commit-then-reveal steps. (1) Every aggregator first sends
`H(ctx_mask ‖ M_i)` (`MaskCommit`, `prepare_init`) and reveals its mask
only after holding every other mask commitment (`prepare_mask_reveal`).
`prepare_masks` refuses a mask that does not match its commitment. (2)
Every aggregator sends `H(ctx ‖ π_i)` (`VerifierCommit`) and reveals `π_i`
only after holding every other commitment (`prepare_reveal`).
`prepare_finish` refuses a revealed partial that does not match its
commitment.

**Claim.** The coalition's masks are fixed before any honest mask is
revealed, so they are independent of the honest mask's plaintext (A4
binding and hiding; A1 for the honest mask ciphertext). For an invalid
report, the coalition's revealed partials are likewise fixed before any
honest partial is revealed. The fused result-slot value is then
`E_j ρ_j + δ_j`, where `δ_j` is determined by the coalition's committed
partials, and `ρ_j = Σ_i ρ_{i,j}` includes an honest aggregator's mask,
uniform, encrypted under the joint key (hidden by A1) and independent of
the coalition's masks. For a slot with `E_j ≠ 0`, `E_j ρ_j + δ_j` is uniform over `F_p`, so
acceptance has probability at most `1/p` per such repetition, plus the RLWE
advantage. The coalition **can** make a valid report fail (any `δ ≠ 0`);
it could equally refuse to participate. That is a denial of service, not a
break of R2 as stated.

### 4.2 Blinded known-answer checks (`vdec.rs`)

A verifier holds ciphertexts `c_1..c_A` (accumulators) and receives every
aggregator's partial decryptions of them.

1. The verifier draws, per check `ℓ` (for `κ` checks per metadata group),
   exponents `k_{ℓ,a} ∈ [0, 2N)` and blinding randomness `u ∈ {−1,0,1}^N`,
   `e_0, e_1` with centered binomial coefficients in `[−20, 20]`, and sends
   `C_ℓ = Σ_a X^{k_{ℓ,a}} c_a + Z_ℓ` with `Z_ℓ = (b u + t e_0, a u + t e_1)`
   (a public-key encryption of zero under the joint key, on the
   accumulators' towers).
2. Every aggregator partially decrypts every `C_ℓ` and sends only
   commitments `H(ctx ‖ π_{i,ℓ})`.
3. With every commitment in, the verifier reveals `(k, u, e_0, e_1)`.
4. Every aggregator rebuilds `C_ℓ` from its own `c_a` and the opening
   (`vdec::build`, deterministic; ranges checked), compares residues and
   metadata with what it decrypted, and reveals `π_{i,ℓ}` only if they are
   identical.
5. The verifier checks each revealed partial against its commitment, fuses
   the accumulators and the checks, rejects any fusion whose value before
   reduction mod `t` reaches `q_0 / 4` (`Context::fuse_magnitude`), and
   accepts only if, in every slot `s` and for every `ℓ`:
   `fused(C_ℓ)[s] = Σ_a w_s^{k_{ℓ,a}} fused(c_a)[s]  (mod p)`.

`κ = ⌈80 / log2(2N)⌉`: 5 for `N = 65536`.

**Lemma 1 (an accepted shift is fixed by the coalition).** Fusion, as
implemented in OpenFHE 1.3.1 (`MultipartyBGVRNS::MultipartyDecryptFusion`,
reproduced step for step by `tbgv_fuse_magnitude`), sums element 0 of the
partials, then drops towers one at a time with BGV `ModReduce`:
`x ↦ (x + d)/q_l` with `d = t·[−x t^{-1}]_{q_l}`, so `d ≡ −x (mod q_l)` and
`d ≡ 0 (mod t)`. The plaintext is `γ · lift(r) mod t`, where `r ∈ Z_{q_0}` is
the result, `lift` is the centered representative and `γ` is a unit mod `t`
fixed by the metadata (inverse tower product and scaling factor).

Write the fused sum as `x_h + Δ`, where `x_h` is what the parties would sum
if the coalition had sent honest partials (with the flooding it chose) and
`Δ` is its deviation. Per dropped tower, `d(x_h + Δ) − d(x_h) − d(Δ)` is
`t·q_l·j` with `|j| ≤ 1`, and earlier differences are divided by `q_l`. So
`r_total = r_h + r_Δ + t·J (mod q_0)` with `|t·J| < 2t`, where `J` depends on
both `x_h` and `Δ`. Let `H` bound `|lift(r_h)| + 2t` over honest inputs.

If `H < q_0/8` and the verifier accepts (`|lift(r_total)| < q_0/4`), then
`lift(r_h) + lift(r_Δ) + tJ` cannot have wrapped modulo `q_0`. A wrap would
need `|lift(r_Δ)| > q_0/2 − H`, which leaves `|lift(r_total)| > q_0/2 − 2H > q_0/4`.
So `lift(r_total) = lift(r_h) + lift(r_Δ) + tJ` over the integers, and the
plaintext is `m_h + δ` with `δ = γ · lift(r_Δ) mod t`. That is fixed by `Δ`
alone; the honest-dependent carries vanish mod `t`. In words: an accepted
fusion is the honest plaintext plus a shift the coalition fixed.

*Completeness, and `H < q_0/8`.* Honest fusions measured `2^32.5` against
`q_0 = 2^47` (verdict parameters, `t < 2^32`) and `2^20.1` against `2^35`
(bottom of the silent-mode chain, `t < 2^20`). With the carries,
`H < 2^34` and `H < 2^21.2`, at least 10 bits below `q_0/8`
(`openfhe-tbgv-rs/tests/vdec_primitives.rs`). This margin is **measured**,
not derived from a noise bound; A2's noise bound is what would make it a
theorem.

**Lemma 2 (slot separation).** For a fixed slot `s` and a fixed nonzero
`δ ∈ F_p`, the map `k ↦ w_s^k δ` is injective on `[0, 2N)`, because `w_s`
has multiplicative order exactly `2N`. Checked:
`SlotPowers::new` refuses a `w_s` that is not a primitive `2N`-th root, and
the primitive test checks every `w_s^{2N} = 1`, `w_s^N = −1`.

**Lemma 3 (hiding of the exponents).** Given everything the coalition
sees before step 3, the exponents are computationally hidden: `C_ℓ` is
`Σ X^{k_a} c_a` plus `Z_ℓ`, and `Z_ℓ` is indistinguishable from uniform
under A1 (it is an ordinary public-key encryption of zero with fresh `u`,
`e_0`, `e_1`). A hybrid replacing `Z_ℓ` by uniform makes `C_ℓ` independent
of `k`.

**Theorem (soundness).** Suppose some coalition shift makes some
accumulator's fused value differ from its true decryption in some slot, and
the verifier accepts. The coalition's shifts `δ_a` (accumulator partials: sent
with, or before, the checks) and `δ'_ℓ` (check partials: committed before
the opening) are fixed before `k` is revealed (A4). The coalition may choose
them after seeing the `C_ℓ` and any honest accumulator partials (rushing);
that does not matter. By Lemma 1, acceptance requires `δ'_ℓ[s] = Σ_a w_s^{k_{ℓ,a}} δ_a[s]` for every
`ℓ` and `s`. Take `a*`, `s*` with `δ_{a*}[s*] ≠ 0`. Conditioned on the
other exponents, the right-hand side takes `2N` distinct values as
`k_{ℓ,a*}` ranges over `[0, 2N)` (Lemma 2). By Lemma 3, `k_{ℓ,a*}` is
independent of `δ'_ℓ` up to the RLWE advantage. So each check passes with
probability at most `1/(2N) + ε_RLWE`, and the `κ` independent checks pass
together with probability at most `(2N)^-κ + κ ε_RLWE ≤ 2^-80 + κ ε_RLWE`.
A shift that makes the fused value reach `q_0/4` is refused outright. ∎

**Proof status.** The soundness argument above is a proof sketch. Its
weakest step is Lemma 3 inside the full protocol. A complete reduction must:
(i) replace the honest parties' partial decryptions by simulated ones
(A2), so that it does not need the honest key shares while it uses the
hiding of `Z_ℓ`; (ii) extract the coalition's committed check partials from
the random oracle (A4); (iii) handle key contributions it did not generate.
Without A3, (iii) means extracting the coalition's shares, which needs
exactly the proofs of knowledge §6.2 says we do not have. We believe these
steps are standard for threshold FHE with noise flooding, but they are
**not written out and not machine-checked**. The carry step in Lemma 1
rests on OpenFHE's ModReduce, which we read and reproduced but did not
prove.

**Theorem (checks leak nothing new).** An honest aggregator reveals
partials only of ciphertexts it rebuilt itself as `Σ X^{k_a} c_a + Z` from
its own accumulators `c_a` (the ones it releases anyway) and randomness in
range. Their plaintext is `Σ_a w^{k_a} ⊙ m_a`, a function of released
plaintexts and public exponents. So a malicious verifier cannot use a
"check" to have anything else decrypted. Demonstrated:
`aggregators_refuse_forged_or_repeated_release_checks`, where a victim's
ciphertext passed off as a check is refused by every aggregator. The extra
partial decryptions per ciphertext are bounded (§5).

**What it does not give.** It gives no attribution: the verifier learns
that some aggregator cheated, not which one. Attributing the cheat would
need per-share proofs (§6.2). It also gives no protection against refusal
to answer.

### 4.3 Where the checks are used

* **Silent-mode valid count** (`count_share`, `count_commit`,
  `count_open`, `count_reveal`, `count_finish`). Every aggregator is a
  verifier of its own checks. An honest aggregator records a valid count,
  and so can release anything, only if its checks pass. **This closes a
  privacy hole** (P1), demonstrated in
  `silent_count_forgery_is_caught_before_any_release`: shifting the count
  partial made a batch with one valid report read as `min_batch_size`,
  which would have made the honest aggregators release that one report to
  a colluding collector.
* **Release to a collector** (`release_challenge`, `release_commit`,
  `release_open`, `release_reveal`, `release_finish`). The collector is the
  verifier. It also requires every aggregator to send the same
  accumulators (bytes), and every partial to have exactly its
  accumulator's shape. Demonstrated:
  `a_shifted_release_partial_is_caught_by_the_collector`.
* **Verdict** uses commit-then-reveal (§4.1). It does not use the checks:
  the adversary cannot target a value it cannot predict, and the checks
  would cost `κ` extra decryptions per report.

## 5. Privacy (P1) and key secrecy (K1)

*Ciphertexts.* Every client ciphertext is an encryption under the joint
key (A1). No coalition of fewer than `n` shares decrypts: the fused value
needs every share. The secret is `s = Σ s_i` with each `s_i` an independent
small secret. Given the coalition's shares, `s` still contains the honest
`s_h`, which is protected by RLWE through its only public use,
`b_h = −a s_h + t e_h` (A1).
(`openfhe-tbgv-rs/tests/threshold.rs` checks the operational side: one share
alone does not decrypt.)

*What honest aggregators decrypt.*
1. Verdict mode: `u` (the masked check value it computed itself), which
   decrypts to zero for valid reports and to a uniform value in the failing
   repetitions otherwise (spec §4.2).
2. Batch accumulators it computed itself, released only once per (batch,
   collector) and only after a **verified** valid count of at least
   `min_batch_size` (silent mode; in verdict mode the count is the public
   number of accepted reports).
3. Silent-mode count checks and release checks: only ones it rebuilt
   itself (§4.2), `κ` per verifier per count round and `κ` per metadata
   group per release.

*Number of partial decryptions per ciphertext* (A2 is statistical in this
number):
* count ciphertext: 1 (count share), plus `κ` checks per verifier over it
  (`(n−1)κ` others' checks decrypted by each aggregator);
* each accumulator: 1 per collector it is released to, plus the collector's
  `κ` checks per group.

They are fixed by the task: each release happens once and each challenge
is answered once (state persisted). A second challenge is refused
(`refusing a second set`).

*Key ceremony.* An honest party publishes `b_i = −a s_i + t e_i` and
key-switching contributions against a CRS `a` it helped generate, never
against a peer's `a` (A1, A4). It publishes round-2 eval-mult contributions
`s_i · (joint round-1 key) + noise`, where the joint round-1 key sums
contributions that were committed before any was revealed, so it contains
an honest uniform part. It also publishes partial decryptions of the joint
key check value, which encrypts a jointly random vector with no client
data. Rogue keys are prevented by commit-before-reveal; a first-party
trapdoor in `a` is prevented by the CRS. Tests: `tests/ceremony.rs` (nine
deviations), `fhe-prio3-node/tests/ceremony_node.rs` (three processes).

## 6. Leakage and gaps (stated, not hidden)

### 6.1 Leakage by design

* Verdict mode reveals, per report, whether it was valid. A malicious
  aggregator can form related reports by ciphertext malleability, which
  gives it a validity oracle bounded by authentication quotas (spec §4.3,
  item 1). Mask commitments (§4.1) are what keep this at one bit per
  forged report. Silent mode reveals no per-report bit.
* The aggregate of each batch of at least `min_batch_size` valid reports;
  the count of valid reports; to each collector, what its policy names.
* Sybil attacks (filling a batch with the adversary's own valid reports)
  are bounded only by authentication and enrolment, as in DAP.

### 6.2 Not proven: well-formedness of key contributions (A3)

A malicious aggregator may contribute key material whose noise (or
secret) is far larger than specified. What the protocol does about it:

* Wrong keys are detected by the ceremony's joint key check (square and
  every rotation at the top of the chain, every slot), which catches any
  contribution that breaks decryption there. Tested: uniformly random
  contributions and a round-2 contribution under another secret are caught.
* Keys that pass at the top of the chain but fail deeper (moderately
  oversized noise) show up as wrong or refused results later. The release
  checks and the collector's consistency checks refuse them; the batch is
  lost (denial of service), not silently wrong.
* **Not covered:** oversized noise that stays within decryption
  correctness but exceeds what the noise flooding (A2) was sized to hide.
  The decryption noise of honest ciphertexts could then carry information
  that flooding no longer masks statistically. No end-to-end attack is
  known to us. But without a proof that every contribution is well formed,
  **privacy against a malicious aggregator during key generation rests on
  assumption A3**.

Closing this needs zero-knowledge proofs of short secrets/noise for
RLWE key shares (lattice NIZKs such as those of Lyubashevsky–Nguyen–Plançon
2022 or LaBRADOR) at ring dimension 65536 across the whole modulus chain.
No production implementation for OpenFHE's key formats exists, and
building one is a research-engineering project in its own right. We do not
implement it and do not claim it.

When it matters: it is **necessary** for a proof of P1/K1 against an
aggregator that is malicious *during key generation*. It is **not needed**
if key generation is run by aggregators that follow the protocol, i.e.
semi-honest at setup and malicious afterwards (the ceremony binds every
contribution to a signed transcript, so a deviation is attributable after
the fact).

### 6.3 Other residual risks

* **Denial of service by an aggregator.** Refusal, wrong partials (caught
  but not attributed), forced rejection of valid reports. Inherent to n-of-n.
* **The leader** is a single point of coordination (liveness only; it
  learns nothing extra with release policies: shares and reveals are
  sealed).
* **Well-formedness of client ciphertexts** (spec §4.3, item 2): the
  soundness bound concerns the plaintext a ciphertext decrypts to. A
  noise-malformed ciphertext is a heuristic concern in verdict mode; in
  silent mode it corrupts the batch, which the consistency and release
  checks refuse.
* **Implementation.** The C++ shim and OpenFHE are in the trusted base.
  Received bytes never reach OpenFHE's deserializer (packed format, fuzzed
  in CI), but the shim is memory-unsafe code reviewed only by us.

## 7. Evidence map

| Claim | Tests |
|---|---|
| R1 | `tests/protocol.rs`, `tests/bounds.rs`, `tests/mitigations.rs`, unit tests in `types.rs`, `config.rs` |
| R2 verdict | `tests/malicious_aggregator.rs::verdict_forced_acceptance_needs_an_adapted_partial_and_is_refused`, `::verdict_mask_cancellation_needs_the_honest_mask_and_is_refused` |
| R2 count, P1 min-batch | `tests/malicious_aggregator.rs::silent_count_forgery_is_caught_before_any_release` |
| R2 release | `tests/malicious_aggregator.rs::a_shifted_release_partial_is_caught_by_the_collector`, `tests/vdec.rs` |
| checks leak nothing new | `tests/malicious_aggregator.rs::aggregators_refuse_forged_or_repeated_release_checks`, `tests/vdec.rs::aggregators_refuse_a_check_that_is_not_one` |
| Lemma 1 completeness margin | `openfhe-tbgv-rs/tests/vdec_primitives.rs` |
| Lemma 2 | `openfhe-tbgv-rs/tests/vdec_primitives.rs`, `vdec::SlotPowers::new` |
| K1/K2 | `tests/ceremony.rs`, `openfhe-tbgv-rs/tests/crs_ceremony.rs`, `fhe-prio3-node/tests/ceremony_node.rs` |
| A6 | `openfhe-tbgv-rs/src/selftest.rs` (fault injection), `build.rs` version gate |
| wire format | `tests/wire.rs`, fuzz targets `fuzz/` |
