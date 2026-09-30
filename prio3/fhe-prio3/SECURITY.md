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
| **R1** robustness against clients | An invalid measurement enters no aggregate, except with probability `≤ (2/p)^k` per submitted report (`k` repetitions). The bound is online: the challenge is keyed with the aggregators' secret verify key, so a client cannot search offline for a passing report. A client colluding with an aggregator that gives it the key can search offline: about `(p/2)^k` encryptions per forgery (`2^124` verdict, `2^78` silent). |
| **R2** robustness against aggregators | A malicious aggregator cannot make an invalid report accepted in verdict mode, except with probability `≤ 1/p` per repetition whose check value is nonzero (§4.1). It cannot change the decrypted valid count (silent mode) or a released aggregate without the verifier aborting, except with probability `≤ 2^-80` per verification (§4.2). It **can** make valid reports rejected and stop the protocol (n-of-n). |
| **P1** input privacy | A coalition of up to `n − 1` aggregators, any collectors and any clients learns nothing about an honest client's input beyond the released aggregates of batches with at least `min_batch_size` **valid** reports, plus the leakage listed in §6. |
| **K1** key secrecy | No coalition of fewer than `n` aggregators learns the joint secret key or an honest share. |
| **K2** key integrity | Keys produced by the distributed ceremony decrypt, relinearize and rotate correctly at the top of the chain and at the task's full depth, or the ceremony aborts. |

## 2. Assumptions

| # | Assumption | Where it is used |
|---|---|---|
| A1 | Decision-RLWE is hard for OpenFHE 1.3.1's parameters at `HEStd_128_classic` (ring dimension and modulus chosen by OpenFHE from the depth). | semantic security of every ciphertext (P1), hiding of the check exponents (R2), security of key contributions (K1) |
| A2 | OpenFHE's `NOISE_FLOODING_MULTIPARTY` partial decryptions are statistically simulatable from their fused plaintext for ciphertexts whose noise is within the bound OpenFHE's parameters assume, for the number of partial decryptions per ciphertext the protocol makes (§5). Measured: the flooding is uniform on `[-Q'/2, Q'/2]`, `Q' = Q_l/q0`, and honest noise is 119 bits or more below it at every decryption point (§6.2). | P1, K1 |
| A3 | Every key contribution in the ceremony is well formed (small secret, noise from the specified distribution). **Not proven; bounded by the ceremony's deep key check** so that accepted keys leave every decryption point about 64 bits or more below the flooding (measured, verdict mode, §6.2). | A2's noise bound |
| A4 | SHA-256 is collision resistant and, for commitments to high-entropy values, modeled as a random oracle (hiding). SHAKE128 keyed with the 256-bit verify key is a PRF (challenge expansion) and a random oracle for CRS expansion. | R1 (keyed challenge), R2 (commitments), K1/K2 (CRS, commitments) |
| A5 | Ed25519 is EUF-CMA; X25519 + HKDF-SHA256 + AES-256-GCM is IND-CCA as a KEM-DEM. | ceremony and attestation authenticity; sealing to collectors; secrecy of the verify key in the ceremony |
| A6 | OpenFHE 1.3.1 implements BGV-RNS as documented. The build is gated to that version, and a start-up self-test checks exact rebuild of every exchanged object at every level the task uses. | everything |
| A7 | Honest parties run this code on hardware and operating systems that do not leak their shares; TLS authenticates peers. | everything |

## 3. Robustness against clients (R1)

As in `FHE_PRIO3_SPEC.md` §4.1: for an invalid `x`, each repetition's
`E_j = <r_j, v(x)>` is zero with probability `1/p` over the challenge, and
the revealed `E_j ρ_j` is zero with probability at most `2/p`. The
challenge is expanded from the task's verify key, which the ceremony
generates jointly and only aggregators hold, so a client cannot evaluate
it and each submitted report is one attempt (tests:
`challenge_is_bound_to_report_task_and_verify_key`,
`aggregators_with_different_verify_keys_accept_nothing`, and the ceremony's
`SplitVerifyKey` deviation and no-cleartext check in `tests/ceremony.rs`). The range of every linear constraint over 0/1 slots is
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

`κ = ⌈80 / log2(2N)⌉`: 5 for both `N = 32768` (verdict mode) and `N = 65536` (silent mode).

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

### 6.2 Well-formedness of key contributions (A3): bounded and measured, not proven

**The risk.** OpenFHE's `NOISE_FLOODING_MULTIPARTY` partial decryption adds
`t·e` with `e` uniform in `[-Q'/2, Q'/2]`, `Q' = Q_l / q0` (read from
OpenFHE 1.3.1's `MultipartyDecryptMain/Lead`; measured: kurtosis 1.80, max
0.99997 `Q'/2`). Partial decryptions are revealed at full precision, so
whoever fuses them sees `m + t·(noise + Σ e_i)` before any modulus
reduction. A party whose key contribution carries oversized noise `E` makes
the noise of every ciphertext contain `u·E` (for the public key, `u` is the
encrypting party's randomness). Once that stands out of the flooding, the
fuser reads `u`, and `c0 − b·u = m + t·e0` decrypts the ciphertext from its
own bytes. Keys with oversized noise still decrypt correctly, so the joint
key check's comparison of values cannot see them.

**Measured gap (verdict parameters, `openfhe-tbgv-rs/tests/key_noise_gap.rs`).**

| Decryption point | Honest noise | Flooding `Q'` | Margin | Room above flooding |
| --- | --- | --- | --- | --- |
| fresh ciphertext | 2^12 t | 2^298 | 285 bits | 14.0 bits |
| sum of 2^20 reports | 2^32 t | 2^298 | 265 bits | 14.0 bits |
| verdict check value (depth 3) | 2^54 t | 2^174 | 119 bits | 14.0 bits |
| silent bottom (24 squarings) | 2^44 t | 2^206 | 161 bits | 14.4 bits |
| silent bottom, sum of 2^16 | 2^60 t | 2^206 | 145 bits | 14.4 bits |

With a public key inflated by `2^k` (constant polynomial), the fuser's
guess of `u` from one fresh decryption stays at chance (1/3) up to
`k = 292` and is exact from `k = 299`. Decryption stays correct and `vdec`'s
earlier `q0/4` bound passed up to `k = 310`.

**What the protocol now does.**

1. *Runtime flooding bound* (`vdec::check_flooding`, shim
   `tbgv_fuse_flooding_check`). Every fusion requires every coefficient of
   `Σ partial_i` at full precision within `t·(n·Q'/2 + Q'·2^-20 + 1)`, the
   support of `n` flooded partials plus the honest noise allowance. A
   violation aborts the count round, the release and the key ceremony. At
   the per-report verdict decision it rejects the report
   (`ValidityCheckFailed`): there a malformed client ciphertext and a
   malformed key or partial cannot be told apart, and a client must not be
   able to make aggregators abort. No false rejection is possible for
   honest parties. Every inflation from `k = 292` is refused, before the
   fuser guesses `u` better than 37% of the time. It fires only after the
   partials are revealed, so it detects rather than prevents.
2. *Deep key check in the ceremony* (`ceremony.rs`, before any client
   encrypts). The joint test ciphertext is taken to the task's full depth,
   through a squaring chain whose result is compared slot by slot (keys
   verified at depth, K2), and through the protocol's own circuit to each
   of its decryption points: the verdict check value, the silent gated sum
   and count, and moment products. Each circuit value's noise is multiplied
   by 2^64 by exact doublings and must pass the flooding bound. Passing
   means that at every decryption point the noise sits about 64 bits or
   more below the flooding.

**Measured result of the deep check (verdict parameters,
`tests/key_noise_protocol.rs`, keys from the real ceremony with one party
deviating).** Largest inflation each contribution can carry through the
ceremony (`tests/ceremony_sweep.rs`): public key 2^59, eval-mult round 1
2^116, round 2 2^123, rotation keys 2^130. With those keys, one at a time or
all four at once, the protocol's decryption points keep this margin below
one party's flooding:

| Keys | fresh | verdict check value | released sum |
| --- | --- | --- | --- |
| honest | 284.7 | 118.3 | 283.5 |
| public key 2^59 | 238.0 | 67.1 | 235.7 |
| eval-mult round 1 2^115 | 284.8 | 66.3 | 283.7 |
| eval-mult round 2 2^123 | 284.8 | 67.0 | 283.6 |
| rotation keys 2^129 | 284.7 | 65.0 | 283.4 |
| all four together | 240.0 | 65.7 | 237.7 |

A margin of `m` bits bounds the statistical distance one decryption leaves
per coefficient, against one honest party's uniform flooding, by `2^-m`.
So an aggregator that is malicious during key generation gains at most
about 2^-65 per coefficient per decryption. It no longer reads encryption
randomness exactly, as it could with the top-level check alone. Two steps
of the design were each found insufficient by measurement and replaced:
- the depth-1 joint key check let through public-key noise that exceeded
  the flooding at the depth-3 verdict check value by 2^13;
- an un-amplified circuit check still let that value come within 7 bits of
  the flooding.

**What remains (stated, not hidden).**

* **A bound, not a proof.** It is measured for the tested parameter sets
  and task shapes, and the correspondence "test value noise ≥ protocol
  value noise" rests on running the same circuit with full-range test
  inputs. No proof covers every task shape, input distribution or key
  structure. We tested constant-polynomial inflations of each key, singly
  and together, not every shape an adversary could choose.
* **Silent-mode thresholds are not measured.** An honest silent ceremony
  passes the amplified check (two processes over TLS: 300.5 s against
  164.5 s before, peak 6.3 GiB per party). An in-process sweep with three
  silent parties does not fit in the 15 GiB machine used, so the
  thresholds and margins above are verdict-mode results. The mechanism is
  the same and honest silent margins are larger (145 bits or more).
* **Runtime checks alone cannot close A3.** A party can trade its own
  flooding share for signal. With its flooding shrunk to `[-Q'/6, Q'/6]`
  and an inflation of exactly `Q'/3`, its contribution is exactly uniform
  on `[-Q'/2, Q'/2]`, invisible to any bound or distribution test on
  decrypted values. Yet it guesses 55.8% of `u` from one decryption (5/9
  predicted, 1/3 by chance) and 94% from six. It is ruled out only because
  its inflation, about 2^296, is far above what the ceremony lets a key
  carry. The ceremony's checks are what bound A3.
* A proof that every contribution is well formed still needs
  zero-knowledge proofs of short secrets and noise for RLWE key shares
  (lattice NIZKs such as Lyubashevsky–Nguyen–Plançon 2022 or LaBRADOR) at
  ring dimension 65536 across the modulus chain. No implementation for
  OpenFHE's key formats exists. We do not implement it and do not claim
  it. `design-notes/key-proofs/README.md` records an assessment of
  building it on IBM's LaZer library (2026-09-30): compatible with the
  ceremony and invisible to clients, but our key moduli exceed LaZer's
  proof-ring limit, so it needs a per-tower lifting with one shared
  commitment that nobody has built; a partial-tower proof is shown there
  to be an attack. Decision: not now. For deployments that need more
  than the measured bound: run the ceremony in attested TEEs with
  reproducible builds and independent operators.

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
| A2 flooding shape, honest margins | `openfhe-tbgv-rs/tests/key_noise_gap.rs` |
| A3 bound (runtime flooding check, deep key check) | `openfhe-tbgv-rs/tests/key_noise_gap.rs`, `tests/ceremony.rs::oversized_key_noise_is_stopped_at_the_ceremony_up_to_the_flooding_range`, `tests/key_noise_protocol.rs`, `tests/ceremony_sweep.rs` (on demand) |
| A6 | `openfhe-tbgv-rs/src/selftest.rs` (fault injection), `build.rs` version gate |
| wire format | `tests/wire.rs`, fuzz targets `fuzz/` |
