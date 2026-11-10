# PINE in the one-aggregator protocol: security arguments

Two arguments, written against the implementation at the commit that adds
this file:

1. **Admission.** Every admitted report is evaluated as the intended
   field arithmetic; honest reports are admitted; what the admission
   copies reveal to the collector.
2. **Challenge binding.** A reduction for malicious clients, with
   concrete bounds.

**Review status: written by the implementer, not reviewed by anyone
else.** The completion criterion "a reviewed security reduction" is
therefore **not met** by this file; it is the text a reviewer needs.
Statements taken from the literature are marked *cited*; statements about
the library are marked *read* (from its source) or *observed* (in a test
only).

Scope: experiment E1 of `PINE-THREAT-MODEL.md` (malicious clients, honest
evaluator and collector) for both parts, and experiment E3 with a passive
collector for 1.5. Nothing here covers an evaluator that deviates.

## Notation and parameters

* `p = 4293918721` (FieldPrio2), `N = 8192`, `R = Z[X] / (X^N + 1)`.
* Ciphertext moduli `q0` (60 bits), `q1`, `q2` (55 bits each),
  `Q = q0 q1 q2`, `L = floor(log2 Q) = 169`. Every `q_i` is 1 modulo `p`
  (checked when a task is created).
* A ciphertext is `(c0, c1)` in `R_Q^2`; its phase is `c0 + c1 s` reduced
  to coefficients in `(-Q/2, Q/2]`; `|.|` is the largest coefficient
  magnitude. The *plaintext* of a ciphertext is its phase modulo `p`.
* `E = 39`: support bound of the library's Gaussian sampler.
* `A = 112` (`ADMIT_BITS`), `k = 78` (`ADMIT_MASK_BITS`).
* `C`: ciphertexts per report. `w = L - 34 = 135`: flooding width of
  `finish`.

Library: OpenFHE 1.3.1, source commit `32362085` (the commit the installed
library was built from, `results/machine.txt`).

## 1. Admission

### 1.1 Facts about the library and the wrapper

| | Fact | Basis |
|---|---|---|
| F1 | Key generation: `pk = (p e_pk - a s, a)`, `s` ternary, `e_pk` Gaussian | *read*: `base-pke.cpp`, `KeyGenInternal` |
| F2 | Encryption of `m`: `c0 = pk0 v + p e0 + m`, `c1 = pk1 v + p e1`, `v` ternary, `e0`, `e1` Gaussian | *read*: `base-pke.cpp`, `EncryptZeroCore`; that `m` enters as its centered lift is *observed* |
| F3 | A Gaussian sample has magnitude at most `E = ceil(3.19 * 12.0061) = 39` | *read*: `discretegaussiangenerator-impl.h`, `Initialize`, `FindInVector` (inversion from a table of `E` entries, an exception beyond it); `Context::gaussian_bound` returns it |
| F4 | `mult_plain` is the product in `R_Q` with the centered lift of the plaintext (coefficients of magnitude at most `p / 2`); `add_plain` adds the centered lift to `c0` | *observed*: `openfhe-tbgv-rs/tests/phase_bits.rs` (multiplying by `p - 1` behaves as `-1`); the encoding code was not read |
| F5 | `flood(ct, w)` adds `p (e - 2^(w-1))` to `c0`, `e` uniform in `[0, 2^w)` per coefficient | *read*: `openfhe-tbgv-rs/wrapper/tbgv.cpp`, `tbgv_ciphertext_flood` |
| F6 | Dropping modulus `q_l`: each component becomes `(c + p delta) / q_l`, `delta` the centered residue of `-c / p` modulo `q_l`, so `|delta| <= q_l / 2`; no plaintext correction is applied in the mode used | *read*: `dcrtpoly-impl.h`, `ModReduce`; `mubintvecnat.cpp`, `SwitchModulus` (values above half the modulus are taken negative); `bgvrns-leveledshe.cpp`, `ModReduceInternalInPlace` |
| F7 | Decryption returns the centered phase modulo `p` | *observed* in every test; standard; the decryption code was not read |

F4 and F7 are the two facts not read from source. Every end-to-end test
would fail if either were false for honest inputs; that is evidence, not
a derivation.

### 1.2 Honest ciphertexts

**Lemma 1.** An honest encryption of `m` has
`|phase| <= p / 2 + p (2 N + 1) E < 2^52`.

*Proof.* By F1 and F2, `c0 + c1 s = m + p (e_pk v + e0 + e1 s)`. A product
in `R` of a polynomial with coefficients in `[-E, E]` and a ternary one
has coefficients of magnitude at most `N E`. So the noise polynomial has
magnitude at most `(2 N + 1) E`, and `|m| <= p / 2` (F2). Numerically
`p (1 + (2 N + 1) E) < 2^32 * 2^19.3`. The bound is far below `Q / 2`, so
the centered phase is this integer polynomial. ∎

Test: `honest_phase_and_modulus_switch_stay_within_the_derived_bounds`
(20 keys, dense plaintexts).

### 1.3 What admission bounds

The evaluator's copy of a report ciphertext `(c0, c1)` is
`(c0 + u + p r, c1)`, with `u` the centered lift of a uniform plaintext
and `r` uniform in `[-2^(k-1), 2^(k-1))` per coefficient (F4, F5). The
collector admits the report when every copy's phase is below `2^A`.

**Lemma 2.** If a copy is admitted, the report ciphertext has
`|phase| < 2^A + p / 2 + p 2^(k-1) < 2^(A+1)`.

*Proof.* The copy's phase is `phase + u + p r` modulo `Q`. Write
`D = u + p r`, `|D| <= p / 2 + p 2^(k-1) < 2^110`. If the centered phase
of the copy is `P'` with `|P'| < 2^A`, then `phase = P' - D` modulo `Q`,
and `|P' - D| < 2^A + 2^110 < Q / 2`, so the centered phase of the report
ciphertext is `P' - D`. ∎

**Lemma 3 (completeness).** An honest report is admitted.

*Proof.* By Lemma 1 the copy's phase has magnitude below
`2^52 + 2^110 < 2^A`. ∎ (Condition (b) of `PineTask::new` checks this
inequality with the context's actual `E`.)

Lemma 2 holds for arbitrary `(c0, c1)`: it does not assume the report
ciphertext is an encryption of anything.

### 1.4 Admitted reports are evaluated as field arithmetic

Let a report be admitted, with ciphertexts `ct_1 .. ct_C` of phases
`phi_b` and plaintexts `m_b = phi_b mod p`.

**Lemma 4 (verifier elements).** For every verifier row
`(row_1 .. row_C)` with constant `c`, the ciphertext the evaluator sends
decrypts at coefficient 0 to `sum_b <row_b, m_b> + c` in `F_p`.

*Proof.*
1. The evaluator computes `sum_b ct_b * q_b` with `q_b` the plaintext
   whose product has `<row_b, .>` at coefficient 0. By F4 the phase of the
   sum is `X = sum_b phi_b q_b` modulo `Q`, where each coefficient of each
   product is a sum of `N` terms of magnitude below `(p / 2) 2^(A+1)`.
   So `|X| < C N p 2^A <= 2^(A + 32 + 13 + ceil(log2 C))`, which condition
   (c) of `PineTask::new` requires to be at most `2^(L-3) <= Q / 8`.
2. Adding the mask (centered lift of a plaintext, magnitude at most
   `p / 2`, value `c` at coefficient 0) and flooding (F5, magnitude at
   most `p 2^(w-1) < 2^(L-3) <= Q / 8`) gives a phase of magnitude below
   `Q / 8 + Q / 8 + 2^32 < 3 Q / 8`. So the centered phase is the integer
   polynomial `X + mask + p f`, congruent modulo `p` to
   `sum_b m_b q_b + mask`.
3. Dropping `q2` (F6): both components become `(c + p delta) / q2`, so
   the phase becomes `(phase + p (delta_0 + delta_1 s)) / q2` exactly (the
   numerator is divisible by `q2`), of magnitude below
   `(3 / 8) q0 q1 + p (N + 1) / 2 + 1 < q0 q1 / 2`. Since `q2 = 1`
   modulo `p`, the phase modulo `p` is unchanged. The same for `q1`: the
   magnitude is below `(3 / 8) q0 + p (N + 1) < q0 / 2` by condition (d).
4. By F7 the collector obtains the phase modulo `p` at coefficient 0:
   `(sum_b m_b q_b)[0] + c = sum_b <row_b, m_b> + c`. ∎

**Lemma 5 (aggregate).** The aggregate over admitted reports
`i = 1 .. n` decrypts, at the gradient coordinates, to the sum of the
plaintexts `m_i` there.

*Proof.* The phase before masking is `sum_i phi_i`, of magnitude below
`2^24 * 2^(A+1) < Q / 4` (condition (c), `n <= 2^24`); the rest is as in
Lemma 4 with mask 0 at the gradient coordinates. ∎

**Consequence.** For an admitted report the collector's decision is
prio's `decide` applied to prio's `query` on the fixed vector
`(m_1 .. m_C)` restricted to the report layout, and its contribution to
the released sum is that vector's gradient coordinates. This holds for
every admitted report, honest or not. Rejected (not admitted) reports
contribute nothing and none of their verifier elements is decrypted.

Tests: `a_ciphertext_with_large_noise_is_not_evaluated_linearly`,
`noise_beyond_the_admission_bound_is_refused_before_the_verifier_is_decrypted`,
and the user's `chosen_phase_linearity` (a phase of `L - 1` bits, far
above `2^A`).

### 1.5 Supported parameters

`PineTask::new` refuses a task unless, for the context it creates:
(a) every modulus is 1 modulo `p`; (b) Lemma 3's inequality; (c)
`A + 1 + max(ceil(log2 C) + log2 N + 32, 24) + 2 <= L`; (d)
`p (N + 1) < q0 / 8`. With `L = 169` condition (c) allows up to
`C = 512` ciphertexts per report. The arguments above use nothing else
about a task.

### 1.6 What the admission copies reveal to the collector

Experiment E3, passive collector; evaluator and client honest. The
collector holds `s` and `e_pk`.

**Proposition 6.** Let `(c0, c1)` be an honest encryption of `m`. The copy
`(c0 + u + p r, c1)` is within statistical distance `N 2^-k = 2^-65` of a
distribution that does not depend on `m`.

*Proof.* By F2 the copy is `(pk0 v + p e0 + m + u + p r, pk1 v + p e1)`.
Write the integer sum of centered lifts `m + u = t + p kappa`, with `t`
the centered lift of `(m + u) mod p` and `kappa` in `{-1, 0, 1}` per
coefficient. `t` is uniform and independent of `m` (one-time pad modulo
`p`); `kappa` is a function of `(m, t)`. The copy is a function of
`(v, e0, e1, t, r + kappa)`, with `(v, e0, e1, t)` independent of `m`.
For `r` uniform on an interval of `2^k` integers, `r + kappa` is at
statistical distance `|kappa| 2^-k <= 2^-k` from `r`, per coefficient,
whatever `(m, t)`. Summing over `N` coefficients gives the claim; the
reference distribution is the same expression with `kappa = 0`. ∎

Per report this is at most `C 2^-65`, per batch `n C 2^-65`: for the
largest batch at 15 fractional bits (65520 reports) and `C = 18`, below
`2^-44`.

What the collector does obtain from the copies, and what follows:

* **`c1` of every report ciphertext, and `c0` masked.** The key holder now
  stores one component of each report ciphertext. Proposition 6 says this
  reveals nothing of the plaintext *as long as the mask is not revealed*;
  the deployment boundary of the threat model (the collector never
  obtains a report ciphertext) now also means: never the evaluator's
  masks.
* **The client's encryption noise**, up to the 78-bit `r`: the copy's
  phase is `t + p (e + kappa + r)` with `e` the noise polynomial of
  magnitude below `2^20`. The noise is independent of `m`.
* **The query points.** The second component of a verifier ciphertext is
  `sum_b c1_b q_b`. The collector knows `c1_b` (copies), and the entry
  gives it the nonce and the part digests, hence the wraparound vectors
  and the joint randomness; the rows are then functions of the query
  point alone, which it can solve for. It does not learn `verify_key`
  (query points are outputs of the XOF keyed with it). Prio3's
  aggregators know the query points too, and the FLP's zero knowledge is
  stated for a verifier that knows them, provided they avoid the proof
  domain, which the evaluator enforces. For soundness the query points
  must be unknown to *clients* before they fix their report; a collector
  that tells a client is outside E1 and E3.
* **Nothing more from combining copies with verifier ciphertexts, at the
  level of plaintexts.** The collector can compute
  `sum_b copy0_b q_b = sum_b c0_b q_b + sum_b (u_b + p r_b) q_b`. Modulo
  `p` the last term is `sum_b u_b q_b`, uniform in the ideal sum that
  also contains `sum_b m_b q_b`, and independent of everything else; so
  the plaintext-level view is the uniform values `t_b`, the verifier
  elements, and uniform masks.

**Proposition 7 (noise of verifier and aggregate ciphertexts, honest
clients).** For a report of honest ciphertexts, the phase of a verifier
ciphertext before flooding has magnitude at most
`p x`, `x = C N (p / 2) (1 + (2 N + 1) E) + 1 < 2^(63.3 + log2 C)`, and
the flooded phase is within statistical distance `N x 2^-w` of
`plaintext + p f` with `f` uniform of `w` bits: `2^-56.7` for `C = 4`,
`2^-54.5` for `C = 18`. For the aggregate of `n` honest reports the
distance is at most `N n 2^20 2^-w`, below `2^-86` for 65520 reports.

*Proof.* Lemma 1 and step 1 of Lemma 4 with honest phases; a shift by
`x` of a uniform variable on `2^w` integers has distance `x 2^-w` per
coefficient. The modulus switch is a function of the flooded ciphertext.
∎

So, for honest clients and an honest evaluator, the collector's view of a
batch is within the sum of these distances of a view computed from the
verifier messages, the released sum and public metadata alone, **given**
the FLP's zero knowledge for the verifier messages (*cited*: [BBCGGI19],
as specified in the VDAF draft) — up to the points not covered below.

Not covered by 1.6:
* an evaluator that deviates (it makes the copies and the masks);
* an active collector (`PINE-THREAT-MODEL.md`, E3);
* reports of malicious clients mixed with honest ones change nothing for
  the honest reports' copies (each copy depends on one report), but the
  noise bound of Proposition 7 is for honest ciphertexts only;
* the per-ciphertext distance of Proposition 7 is about `2^-55`, not
  `2^-64`: it is what the modulus allows at this flooding width, and is
  stated as it is;
* the randomness of masks and flooding is the library's and the
  operating system's generators, taken as uniform.

## 2. Challenge binding

### 2.1 Model and assumptions

* **A1.** XofTurboShake128 is a random oracle, independently for each
  domain separation tag used (`"... wraparound seed"`,
  `"... wraparound vectors"`, `"... joint randomness seed"`,
  `"... joint randomness"`, `"... query randomness"`).
* **A2.** SHA-256 is collision resistant (used for the part digests and
  the commitment).
* **A3 (*cited*).** Soundness of prio's FLP for a gadget of degree 2:
  for any input `x` and any string `pi`, if the circuit's output on `x`
  (with the given joint randomness) is not 0, then over a query point
  uniform outside the `2 P`-th roots of unity the verifier accepts with
  probability at most `eps = 2 (P - 1) / (p - 2 P)`, `P` the wire
  polynomial length ([BBCGGI19], Theorem 4.3; VDAF draft, section 7.3).
* **A4 (*cited*).** The wraparound lemma: let `g` in `Z^d` have
  coordinates in `(-p/2, p/2]` with `sum g_j^2 = v + k p`, `0 <= v <= B^2`,
  `k >= 1`, for parameters passing `Shape::new`'s guards. For one test
  vector drawn as PINE draws it, the probability that `<z, g> mod p` lies
  in `[-wr_bound + 1, wr_bound]` is at most `1/2` ([ROCT23], Lemma 3.3,
  as used by `draft-chen-cfrg-vdaf-pine`). **Not verified here**: the
  lemma's exact hypotheses were taken from the draft's use of it, not
  from a reading of [ROCT23].
* **A5.** Evaluator and collector follow the protocol; `verify_key` is
  uniform and never leaves the evaluator; part 1 holds for the task.

The adversary controls any set of authorized identities, knows the task
and the public key, makes at most `q` oracle queries in total (counting
the derivations done for the reports it submits), submits at most `n`
reports, adaptively, and learns each verdict.

### 2.2 Definitions

For an admitted report `R = (nonce, G, W, P)` let `m_G`, `m_W`, `m_P` be
the plaintexts of its parts (part 1), `K` the task-and-key context, and
`c_G, c_W, c_P` the SHA-256 digests of the parts' bytes. Let

    z      = vectors(H_wr(K, nonce, c_G))            100 test vectors
    jr     = H_jr(K, nonce, c_G, c_W)                three field elements per main proof
    t      = H_q(verify_key; K, commit(K, nonce, c_G, c_W, c_P))
    x(R)   = gradient and norm bits from m_G, wraparound part from m_W, dot products <z_i, gradient>
    pi(R)  = the proofs, from m_P

*Valid*: the centered gradient has integer squared norm at most `B^2`.
`C_ne(x)`: the norm-equality circuit's output. `S(x)`: every bit-checked
entry is 0 or 1; `v + u = B^2`; for every test `i`,
`g_i (dot_i - (dec(bits_i) - (wr_bound - 1))) = 0`; `sum g_i = 100`. The
main circuit's output `C_main(x; jr_j)` is a polynomial in `jr_j` that is
identically 0 if `S(x)`, and otherwise vanishes with probability at most
`delta = (bit_checked_len + 101) / p` over uniform `jr_j` (three
Schwartz-Zippel steps: degree `bit_checked_len - 1` in the first element,
99 in the second, 3 in the third).

### 2.3 The statement

**Theorem 8.** Under A1 to A5, the probability that the collector accepts
some report that is not valid is at most

    q^2 / 2^256  +  q / 2^256                               collisions; guessing verify_key
    + n eps_ne^k_ne                                          norm equality
    + sum_{j=0..k} min(1, q C(k,j) delta^j) min(1, n eps^(k-j))   main circuit
    + q 2^-100                                               wraparound

with `k`, `k_ne` the numbers of main and norm-equality proofs and `eps`,
`eps_ne` the bound of A3 for each circuit.
`PineTask::soundness_bound` evaluates the last three lines.

### 2.4 Proof

*Step 0 (the decision is a function of the report).* By part 1, for an
admitted report the collector's decision is prio's `decide` on prio's
`query(x(R), pi_j; t_j, jr_j)` for every proof, with the challenges the
honest evaluator derives as in 2.2. A report that is not admitted is
rejected.

*Step 1 (what each challenge is independent of).* Exclude a collision of
SHA-256 among the adversary's at most `q` part strings and commitments
(first term; A2 would give a computational bound, the term is the
random-function one). Then:

* `c_G` determines the bytes of `G`, hence `m_G` (a function of the bytes
  and the secret key), hence the gradient and norm bits. So `z` is the
  oracle's answer at a point that determines the gradient: the gradient
  is fixed before `z` is drawn. A re-encryption of the same gradient is
  another byte string, hence another `c_G` and another, independent,
  answer; so is another nonce. Each costs one query.
* `(nonce, c_G, c_W)` determines the gradient, the norm bits, the
  wraparound part and (through `z`, an answer of a different oracle) the
  dot products: all of `x(R)`. So `jr` is the answer at a point that
  determines `x`.
* The commitment determines `(nonce, c_G, c_W, c_P)`, hence `x` and
  `pi`. `t` is the answer of `H_q` keyed with `verify_key`, which the
  adversary can query only by guessing the key (second term). So for each
  distinct commitment `t` is uniform (outside the excluded roots, by the
  evaluator's rejection sampling) and independent of `(x, pi)` and of
  everything the adversary saw before submitting, including earlier
  verdicts, which depend on other commitments' query points.

*Step 2 (cases for an accepted report that is not valid).*

(i) `C_ne(x) != 0`. Each norm-equality proof is accepted with probability
at most `eps_ne` over its own query point (A3), independently. Over at
most `n` reports: `n eps_ne^k_ne`.

(ii) `C_ne(x) = 0` and not `S(x)`. For each oracle point
`(nonce, c_G, c_W)` and each proof `j`, `C_main(x; jr_j) = 0` with
probability at most `delta`, independently over `j` (the `jr_j` are
disjoint parts of one answer). Call a point *j-bad* if this happens for
at least `j` proofs: probability at most `C(k, j) delta^j` per point, so
at most `q C(k, j) delta^j` that the adversary ever queries one. A report
at a point with exactly `j` such proofs is accepted with probability at
most `eps^(k-j)` over the other proofs' query points (A3). Summing over
`j` the probability that the best point found is `j`-bad times the
probability that one of `n` reports there passes gives the main-circuit
line.

(iii) `C_ne(x) = 0`, `S(x)`, not valid. From `S(x)`: `v`, `u` are
integers below `2^norm_bits <= 2 B^2` with `v + u = B^2` in `F_p`, hence
over the integers (`v + u <= 4 B^2 - 2 < B^2 + p` by `Shape::new`'s guard
`p > 3 B^2 + 2`), so `0 <= v <= B^2`. From `C_ne(x) = 0`: the centered gradient's squared
norm is `v` modulo `p`; not valid means it is `v + k p` with `k >= 1`.
From `S(x)`: the 100 success bits sum to 100 in `F_p` and are bits, so
all are 1, and then every dot product equals a value in
`[-wr_bound + 1, 2^wr_bits - wr_bound] = [-wr_bound + 1, wr_bound]`
(`wr_bound` is a power of two and `2^wr_bits = 2 wr_bound`). By A4 and
the independence of the 100 vectors (disjoint parts of one answer, drawn
after the gradient is fixed), this has probability at most `2^-100` per
oracle point `(nonce, c_G)`: `q 2^-100` in total. Acceptance is then not
needed to be bounded further.

The three cases are exhaustive. ∎

### 2.5 Concrete bounds

`tests/pine.rs`, `concrete_soundness_bounds`: dimension 1000, norm bound
1.0 with 15 fractional bits, chunk lengths 4 and 4, `q = 2^64`.

| proofs (main / norm eq.) | reports `n` | norm equality | main circuit | wraparound | total |
|---|---|---:|---:|---:|---:|
| 5 / 1 (the reference's counts) | 1 | 2^-23.0 | 2^-37.7 | 2^-36.0 | **2^-23.0** |
| 5 / 1 | 2^16 | 2^-7.0 | 2^-22.0 | 2^-36.0 | **2^-7.0** |
| 7 / 3 | 1 | 2^-69.0 | 2^-76.3 | 2^-36.0 | **2^-36.0** |
| 7 / 3 | 2^16 | 2^-53.0 | 2^-60.4 | 2^-36.0 | **2^-36.0** |
| 7 / 4 | 2^16 | 2^-76.0 | 2^-60.4 | 2^-36.0 | **2^-36.0** |

Reading:
* With one norm-equality proof, `n` colluding identities get `n` tries at
  `2^-23`: **`2^-7` for 65536 of them.** One norm-equality proof is not
  enough for a cohort with many malicious identities; three or four are.
* The main-circuit term is much weaker than `delta^k` suggests: with
  `2^64` queries the adversary finds a point where 3 of 5 proofs have
  favourable joint randomness, and needs the queries to miss on only two.
* **The wraparound term `q 2^-100` does not improve with more proofs.**
  It is fixed by PINE's 100 tests. With `2^64` offline hash queries it is
  `2^-36`. The reference derives its test vectors by Fiat-Shamir too; the
  number of tests is a constant of this implementation
  (`NUM_WR_CHECKS`), and raising it means leaving the reference's
  parameters.

### 2.6 What Theorem 8 does not establish

* Anything against an evaluator or a collector that deviates.
* Privacy (part 1.6 is separate, and partial).
* A3 and A4 themselves. A4 in particular is the heart of PINE and is
  taken from the draft's account of it.
* That modelling XofTurboShake128 as independent random oracles is
  sound; that F4 and F7 hold beyond what the tests observe.
* Completeness of honest clients beyond Lemma 3 (an honest client retries
  when a wraparound test fails; the probability of that is the
  reference's and is not re-derived).
* **Review.** No one but the author has read this argument.
