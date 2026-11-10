# PINE in the one-aggregator protocol: status against the repair guide

Section by section of `PINE-SECURITY-FIX-GUIDE.md`. "Done" means
implemented and tested as described, with the limits stated. "Not done"
means exactly that: a heading or an interface here is not a completed
item. **The two cryptographic repairs the guide asks for (sections 4 and
5) and the privacy theorem (section 6) are not done. Production status is
red.**

| Guide section | Status |
|---|---|
| 2. Security contract | Written: `PINE-THREAT-MODEL.md`. Not reviewed by anyone else |
| 3. Canonical transcript, authenticated cohort | Done in code, with limits below |
| 4. Challenge binding: construction and proof | Argument written for malicious clients (`PINE-SECURITY-ARGUMENT.md`), with concrete bounds; **not reviewed**, two statements cited. Gate not met |
| 5. Authenticated computation before decryption | **Not done.** Relation stated below; no proof system |
| 6. Randomness ownership, ciphertext privacy | Ownership table below; a statistical argument for a passive collector with honest clients and evaluator (`PINE-SECURITY-ARGUMENT.md`, 1.6), unreviewed. **Not done** for adversarial inputs, an active collector, or an evaluator that deviates |
| 7. Collector state machine | Done in code, with limits below |
| 8. Regression and adversarial evidence | Partly done: table below |
| 9. Parameters and end-to-end qualification | Parameter guards done; training qualification not done |
| 10. Release sequence | Step 1 written, unreviewed. Steps 2 to 4 open. Step 5 done for what can be refused today. Steps 6 to 9 open |

## 3. Canonical transcript and authenticated cohort

Done:
* One versioned binary descriptor (`src/pine/descriptor.rs`): magic,
  version, application identifier, model hash, round, dimension, integer
  norm bound, fractional bits (the scale), chunk lengths, proof counts,
  release threshold, authorized identities. Fixed-width little-endian
  fields, an explicit count, identities strictly increasing. Decoding
  refuses any other length, version or order.
* The task hash covers the descriptor, the wraparound constants, the
  field and the BGV ring and moduli. The collector's public key enters
  separately (`key_context`), hashed in the form its serialization keeps
  from the first deserialization on (measured: the bytes differ before).
* A report's commitment hashes the task and key, the nonce, and the
  digest of each of `G`, `W`, `P` separately (fixed lengths). The client
  signs it (Ed25519, strict verification).
* The collector verifies, before any decryption or record: every identity
  authorized, identities strictly increasing, every signature. It never
  receives a report ciphertext.
* Batch identifier, verdict hash (batch, commitments in order, verdicts)
  and accepted count tie the aggregate request to the check.
* Release policy in the descriptor: a threshold on accepted reports.

Gate ("a malicious evaluator cannot substitute the cohort while still
presenting an authorized descriptor"): **met for the cohort's identity,
not for its content.** The entries of a check request are reports that
authorized clients signed for this task and key
(`a_cohort_the_clients_did_not_sign_is_refused_before_anything_is_decrypted`).
The ciphertexts the collector then decrypts are not tied to those
entries; that is section 5.

Limits:
* Omission is allowed and undetected: the evaluator may forward any
  subset. No inclusion deadline, no receipt to clients.
* The list of identities is the application's. Nothing here admits or
  removes identities.
* Metadata the collector now learns: which identities reported in which
  batch, and each one's verdict (`PINE-THREAT-MODEL.md`).
* A signature authenticates a client's intent to submit these bytes. It
  says nothing about the ciphertexts being well formed or the gradient
  being honestly computed.
* Ed25519 is not post-quantum.

## 4. Challenge binding

### The construction as implemented (Route B of the guide)

This is a new adaptation, not unchanged PINE. Per report, with `K` the
hash of task and collector key:

    c_G, c_W, c_P = SHA-256 of the bytes of G, W, P
    wr_seed  = XofTurboShake128(0^32, "... wraparound seed" || K; nonce || c_G)
    vectors  = PINE's {-1, 0, 1} sampling from XofTurboShake128(wr_seed, "... wraparound vectors" || task)
    joint    = XofTurboShake128(XofTurboShake128(0^32, "... joint randomness seed" || K; nonce || c_G || c_W), "... joint randomness" || K)
    commit   = SHA-256("... report commitment" || K || nonce || c_G || c_W || c_P)
    query    = XofTurboShake128(verify_key, "... query randomness" || K; commit), rejecting roots of unity of the proof domain

Stages: `G` is fixed before the test vectors exist; `W` before the joint
randomness; `P` before the query points, which the client never learns.

### What a proof has to establish, and where it stands

`PINE-SECURITY-ARGUMENT.md` now holds the argument. Per obligation:

1. **The committed input is well defined (client ciphertext admission).**
   *Problem demonstrated* (`a_ciphertext_with_large_noise_is_not_evaluated_linearly`,
   and the wrapper test `chosen_phase_linearity`): a ciphertext with a
   large phase decrypts to a plaintext, but its plaintext products do not
   decrypt to the products.
   *Construction implemented:* the collector measures the phase of a
   masked copy of every report ciphertext and admits a report only below
   `2^112`.
   *Argument written* (part 1 of the argument file): an admitted
   ciphertext has a phase below `2^113`; then nothing wraps through
   products, masking, flooding and both modulus switches, and every
   decrypted value is the linear function of the plaintexts
   `phase mod p`; an honest report is always admitted. The bounds are
   derived from the library's source at the installed commit (key
   generation, encryption, the Gaussian sampler's support, the modulus
   switch) and from the wrapper's flooding code; `PineTask::new` checks
   the numeric conditions for each task.
   *Open:* review; two library facts observed and not read (plaintext
   lifting, decryption).

   *Relation to `PINE-CLIENT-NOISE-OBLIGATION.md`.* That note asks for a
   zero-knowledge proof by the client of a bounded encryption witness,
   checkable by the evaluator without any key. The construction here
   bounds the phase itself, measured by the key holder, and needs no
   proof system. What the witness proof would give and this does not:
   verification before the evaluator computes anything, without the
   collector seeing any part of a report ciphertext, and validity against
   an evaluator that deviates.

2. **What the copies reveal** (part 1.6): a copy is within `2^-65` of a
   distribution independent of its plaintext; the collector obtains one
   component of every report ciphertext, the client's noise up to a
   78-bit mask, and can compute the query points; for honest clients the
   noise of a verifier ciphertext is hidden up to about `2^-55` per
   ciphertext (stated as it is: not `2^-64`). *Open:* review; an
   evaluator that deviates; an active collector.

3. **Extraction order, re-encryption, nonce changes, grinding** (part 2,
   Theorem 8): written, in the random-oracle model, with the FLP's
   soundness and PINE's wraparound lemma cited. Concrete bounds are in
   `PINE.md` and computed by `PineTask::soundness_bound`. *Open:* review;
   the two cited statements, of which the wraparound lemma's hypotheses
   were taken from the draft's use of it and not from the paper.

4. **Query secrecy.** `verify_key` is the evaluator's alone and is not
   committed to anyone. Against a malicious evaluator (experiment E2) the
   query points are adversarial; that is part of section 5.

Gate ("a complete, reviewed argument"): the argument is complete as far
as its stated scope and assumptions go; it is **not reviewed. Not met.**

Route A (evaluating upstream's share hashing and seed comparison under
BGV) was not attempted: it needs hash evaluation under encryption and a
representation of two virtual verifiers' secret states, a different and
much larger circuit than the affine queries here.

## 5. Authenticated computation

### The relations

With `D` the task descriptor and key, and per report `i` the signed
entry `(identity_i, nonce_i, c_G,i, c_W,i, c_P,i)`:

**Check relation.** `R_check(D, batch, entries, C; witness) = 1` iff
there are report bodies `(G_i, W_i, P_i)` with the entries' digests, a
`verify_key`, masks and flooding values such that every ciphertext
`C_i,r` equals the prescribed computation: the challenges of section 4
from the digests and `verify_key`, row `r` of the closed-form verifier
map, the sum over the report's ciphertexts of the plaintext products,
plus a mask that is 0 at coefficient 0 up to the row's constant, plus
flooding within the stated width, then the modulus switch. It must also
fix `verify_key` across reports and batches (a commitment to it in `D`).

**Final relation.** `R_final(D, batch, entries, verdicts, C; witness) = 1`
iff `C` equals, for the same bodies, the sum of `G_i` over the accepted
`i`, plus a mask that is 0 on the gradient coordinates, plus flooding,
then the modulus switch.

Two proofs are needed: the first protects the check decryptions, the
second the release. Both must be zero knowledge towards the collector
for the bodies, the masks and the flooding values (revealing them undoes
section 6), and are statements about arithmetic modulo three 55 to 60 bit
primes on polynomials of degree 8192.

### Status

**No proof system is instantiated. Nothing is verified.** No choice is
made here between candidate systems: that needs the properties the guide
lists (knowledge soundness, zero knowledge, setup, post-quantum or not)
and a measured cost on these relations, neither of which exists. What
was deliberately not done: sending the collector reports, or accepting a
hash, a signature of the evaluator, a count or a batch identifier as
evidence of computation.

**What the reactions give an evaluator that deviates (experiment E2).**
The collector answers one bit per report: admitted and accepted, or not.
Both parts depend on the secret key applied to ciphertexts the evaluator
chose: the admission bit on the phase of an arbitrary ciphertext, the
acceptance bit on whether decrypted values satisfy the verifier's
equations. Bits of this kind about chosen ciphertexts are what reaction
attacks on lattice encryption use, against clients' inputs (the
crafted-query attack of `HARDENING-PLAN.md`) and against the key itself.
No such attack is implemented or measured here; nothing here rules one
out. What limits it today: every query needs an entry signed by an
authorized client that has not reported before in the task, so a task
gives at most as many reaction bits as it has identities; a collector key
used for several tasks accumulates them. Until section 5 exists, treat
the collector's key as exposed to an evaluator that deviates, and use a
fresh key per task.

Gate (the substituted sum refused before decryption): **not met.**
`known_limit_an_evaluator_that_deviates_can_substitute_the_sum` still
passes, which means the attack still succeeds. The decryption counter the
gate asks for exists (`PineCollector::decryptions`) and is used by every
refusal test that can be refused today.

## 6. Randomness and ciphertext privacy

| Value | Generated by | Distribution | Seen by | Lifetime | If biased, reused or revealed |
|---|---|---|---|---|---|
| nonce | client, OS randomness | 16 uniform bytes | evaluator, collector | one report | reuse: the report is refused; predictability alone does not help a client (challenges also depend on its ciphertexts) |
| encryption randomness of `G`, `W`, `P` | client, OpenFHE's samplers | the library's ternary and Gaussian | nobody (inside the ciphertexts) | one report | the client's own privacy; a malicious client may use any values: admitted only with a phase below `2^113` (section 4, item 1) |
| masks of the admission copies | evaluator, OS randomness (plaintext part) and `flood` (the `p r` part) | uniform field elements; uniform 78-bit values | nobody | one copy | revealed to the collector: it decrypts that report ciphertext |
| prover randomness | client, OS randomness expanded by XofTurboShake128 | uniform field elements | nobody | one report | reuse or bias: the FLP's zero knowledge for that client |
| signing key | client | Ed25519 | nobody | the client's | compromise: reports in its name |
| wraparound vectors, joint randomness | derived by hashing | as PINE samples them | evaluator; client | one report | public by design; soundness rests on when they become known |
| `verify_key` | evaluator, by the operator | 32 uniform bytes | evaluator only | the task | known to a client: FLP soundness is lost; chosen after seeing reports: a privacy risk the VDAF draft warns of (its section 9.1), not prevented here |
| query points | derived from `verify_key` and the commitment | uniform outside the proof domain | evaluator | one report | as `verify_key` |
| batch identifier | evaluator, OS randomness | 32 uniform bytes | collector | one batch | reuse: refused |
| masks of check and aggregate ciphertexts | evaluator, OS randomness expanded by XofTurboShake128 | uniform field elements on every coefficient but the one(s) to be read | nobody (the collector sees masked values) | one ciphertext | revealed to the collector: it reads the other coefficients (other linear functions of a report; sums of norm bits) |
| flooding values | evaluator, OpenFHE-side uniform sampling in `flood` | uniform in a `width`-bit range per coefficient, times `p` | nobody | one ciphertext | revealed or biased: the noise of the computation is exposed |
| BGV key pair | collector | OpenFHE key generation | secret key: collector only | the task | the secret key decrypts every report |

A proof that a computation used *some* mask does not show the mask was
sampled uniformly; section 5's relations would have to be paired with an
argument for that, or the masks made part of a two-party sampling.

Done since: for a passive collector with honest clients and an honest
evaluator, `PINE-SECURITY-ARGUMENT.md` (1.6) bounds what the admission
copies, the verifier ciphertexts and the aggregate reveal beyond the
verifier messages and the sum, with worst-case honest noise from the
library's source. Decryption of admitted reports cannot fail (part 1 of
that file): there is no failure probability left to bound.

**Not done:** the same for reports of malicious clients (their noise is
bounded by admission, far above honest noise, so the flooding does not
hide it; it is their own); an active collector; an evaluator that
deviates; review. Gate: **not met.**

## 7. Collector state machine

Done: states `Idle` and `Checked` (the guide's collecting and sealed
states are the evaluator's: collecting, sealed, released). A check is
refused unless idle; the whole request is decoded and the cohort
authenticated before any record; batch, identities and nonces are
recorded before any decryption; a release needs the checked batch, its
verdict hash and count, is recorded before decryption, and happens once;
`abandon` is the operator's explicit, recorded cancellation; a batch
below the release threshold is closed by the check; after a restart
nothing is pending. All-rejected batches: verdicts are returned, nothing
can be released.

Limits: no permanently-failed state and no key lease (a failure after the
records leaves the batch burned and the collector idle); the ledger must
not be rolled back, and nothing detects a rollback; requests are handled
one at a time by `&mut self`, so concurrency is the caller's to
serialize; error texts and timing of secret-dependent steps are not
analysed (the verdict bits themselves are the documented reaction).

## 8. Evidence

| Guide item | Evidence |
|---|---|
| 1. another valid aggregate relabelled with the checked batch and count | **Accepted** (`known_limit_...`). Not repaired |
| 2. modified check ciphertext or verifier row | Not detectable without section 5. A modified final ciphertext likewise. A modified accepted set changes the verdict hash: refused, no decryption |
| 3. reordered, duplicated, substituted reports | Refused, no decryption (`a_cohort_...`). Omitted reports: accepted by design |
| 4. same nonce in another round, key; same ciphertext under another nonce | Refused by the evaluator (signature) and rejected by the proofs when re-signed (`a_cohort_...`, `parts_of_other_reports_...`). Another *profile* (parameters) changes the task hash the same way; not tested separately |
| 5. G/W/P mix-and-match, re-encryption, off-support coefficients | `parts_of_other_reports_...`, `coefficients_outside_the_layout_change_nothing` |
| 6. proof for one descriptor paired with another | No computation proofs exist. For signatures: another round and another key are refused |
| 7. malformed ciphertext in the last position | Refused, no decryption, nothing recorded (`a_malformed_ciphertext_...`). Malformed proofs: none exist |
| 8. crash at every durable transition, concurrency, rollback | **Not done.** Only re-creation of both parties from stored key and ledger |
| 9. altered masks, reused randomness, invalid encryption witnesses, noise growth | Partly: ciphertexts that are not honest encryptions (noise beyond and inside the admission bound) are tested. Altered masks and reused randomness: **not done** |

Challenge code: domain separation by task and key is exercised through
the cross-round and cross-key refusals; the reference vectors cover the
encoding, the wraparound tests and both circuits (`tests/pine_upstream.rs`);
circuits are compared on arbitrary field-valued inputs with the separate
port. Negative seed-consistency cases of the reference do not apply
(there are no seeds to compare). No test here is evidence of
random-oracle security.

## 9. Parameters

Enforced in code: the reference's field-size guards; `p > 2 N B` through
the batch limit `(p - 1) / (2 B)`; the integer norm is checked after
rounding and the client refuses a gradient beyond it; FieldPrio2 only
(p = 65537 fails PINE's guard for every bound above 1); the ring comes
from the library's 128-bit selection and is not forced. The collector
releases the sum and the accepted count; the averaging denominator is the
caller's policy and is not fixed here. Weighted averaging is not
supported.

Not done: any training run, honest or adversarial; whole-round
measurements with repeated samples, peak memory and recovery;
norm-valid poisoning is outside what the protocol addresses.
