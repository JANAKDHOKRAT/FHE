# PINE in the one-aggregator protocol

`src/pine.rs` and `src/pine/circuit.rs`: clients send encrypted
real-valued vectors (gradients) with a proof that the L2 norm is at most a
bound; one aggregator checks the proofs under encryption; the collector
learns the sum of the valid vectors. The validity circuits and the encoding
are PINE's (`draft-chen-cfrg-vdaf-pine`, reference commit 4d11ac8, kept in
`../../pine-bgv-port/upstream`); proving, querying and deciding are
prio 0.18.1's unchanged FLP code; the encryption is OpenFHE 1.3.1 BGV
through `../openfhe-tbgv-rs`.

**Status: research implementation, tested end to end with real
ciphertexts. Not production certified, and not secure against an evaluator
that deviates.** "Not proved" and "Not done" below list what is missing;
nothing in this file claims more than the tests and measurements named in
it.

## Parties and trust

The same as `ONE-AGGREGATOR.md`: one evaluator (holds reports and a secret
`verify_key`), one collector (holds the whole BGV secret key). They must
not collude and **both must follow the protocol**. Clients may be
malicious.

| Party | Learns |
|---|---|
| evaluator | ciphertexts, and one accept/reject bit per report |
| collector | per report the FLP verifier messages, then the sum of the accepted gradients, plus whatever the flooded noise of what it decrypts reveals (not bounded by a proof, see "Not proved") |

## Protocol

A report is `nonce || G || W || P`, each part one or more ciphertexts of
8192 coefficients:

| Part | Plaintext coefficients |
|---|---|
| `G` | the encoded gradient, then the bits of `v = |g|^2` and `u = B^2 - |g|^2` |
| `W` | per wraparound test: the bits of the shifted dot product and the success bit |
| `P` | the norm-equality proofs, then the main proofs |

1. **Client.** Encodes the gradient (`round(x * 2^f)`, ties to even),
   encrypts `G`, derives the 100 wraparound test vectors from the nonce and
   the bytes of `G`, runs the tests, encrypts `W`, derives the joint
   randomness from the nonce and the bytes of `G` and `W`, proves both
   circuits with prio's `Flp::prove`, encrypts `P`. If a wraparound test
   fails on an honest gradient the client starts again with a new nonce.
2. **Evaluator.** Refuses a nonce it accepted before for the task.
   Re-derives the test vectors and the joint randomness from the bytes it
   received, and the query points from its `verify_key` and the whole
   report. Each verifier element is an affine function of the report's
   plaintext; the dot products of the wraparound tests are linear in the
   gradient and are folded into it. The check request, built once per
   batch, carries a random batch identifier, the nonces, and per verifier
   element: the sum over the report's ciphertexts of one plaintext
   product, the element at coefficient 0, a fresh uniform mask on every
   other coefficient, noise flooding, switch to one tower.
3. **Collector.** Decodes the whole request, records the batch identifier
   and every nonce as used (refusing any it saw before), then decrypts
   coefficient 0 of each ciphertext, runs prio's `decide` on every proof,
   and returns one bit per report.
4. **Evaluator.** Once per batch: sums the `G` ciphertexts of the accepted
   reports, masks every coefficient that is not a gradient coordinate,
   floods, switches to one tower; sends it with the batch identifier and
   the accepted count.
5. **Collector.** Requires the batch it just checked and the count it
   accepted, records the release as used, then decrypts the gradient
   coordinates and decodes them (centered lift divided by `2^f`).

Depth 0: plaintext products and additions only, no evaluation keys.

### What the challenge derivation binds, and what that does not prove

PINE draws its randomness in two steps, each after the client is committed
to what the step tests. The reference commits through hashes of the
aggregators' secret shares, which the aggregators recompute and compare.
This protocol has no shares: the derivation hashes ciphertext bytes, as
`single.rs` does for Prio3's joint randomness.

Implemented, and tested in `tests/pine.rs`: changing any byte of `G`
changes the test vectors; changing any byte of `G` or `W`, or the nonce,
changes the joint randomness; every verifier row reads each part only from
that part's ciphertexts; coefficients outside the layout are multiplied
by 0. A part of another valid report, a fresh encryption of the same
gradient part, or another nonce makes a valid report invalid.

**Not proved:** that this derivation inherits the security of PINE or of
Prio3. Binding bytes is a property of the implementation; the security of
the two protocols is proved for their own derivations from shares. A proof
for this one (the ciphertext as a commitment under the collector's key, in
the random-oracle model, composed with the FLP and the wraparound tests)
has not been written. The table below is an accounting of known bounds
under that unproved step, not a theorem about this protocol.

## Single use: replays and releases

Each party keeps a ledger: a directory of empty marker files, created
exclusively and synced to disk before the party goes on (`Ledger` in
`src/pine.rs`).

| Rule | Enforced by | When |
|---|---|---|
| a report nonce is accepted once per task | evaluator | at ingestion, across batches and restarts |
| a batch identifier is checked once | collector | before anything in the request is decrypted |
| a nonce is checked once | collector | same |
| the sum of a checked batch is released once | collector | recorded before the aggregate is decrypted |
| one check request and one aggregate request per batch | evaluator | in memory |

A request refused by these rules leaves a checked batch releasable. A
batch that was checked but not released before the collector restarts is
lost (`with_keys` starts with nothing pending).

Limits of these rules:
* The ledger directory must be on a local file system that honours
  exclusive creation and `fsync`, be writable only by its owner, and never
  be rolled back or emptied while the keys are in use. Deleting it removes
  the protection. Markers are never removed.
* The nonces in a check request are the evaluator's statement. The
  collector cannot see reports, so it cannot tell whether a ciphertext
  belongs to the nonce listed with it. The rules stop repetition by an
  evaluator that follows the protocol (including after a crash or a
  restore of its own state); they do not constrain one that deviates.
* A client can still submit the same gradient twice under two nonces, and
  nothing identifies clients: there is no protection against fabricated
  (Sybil) reports.

## What a cheating client can hope for

| Event | Probability | Where it comes from |
|---|---|---|
| the queries miss an invalid proof | `(2 (P - 1) / (p - 2 P))^k` per report, `P` the wire-polynomial length, `k` the proofs of that circuit; the larger of the two circuits (`log2_query_soundness`) | prio's FLP (gadget of degree 2); one try per report |
| joint randomness under which an invalid measurement makes the main circuit 0 in every proof | `((bit_checked_len + 101) / p)^k` per offline attempt (`log2_joint_rand_per_attempt`) | Schwartz-Zippel on the three random combinations; a client can try nonces and encryptions offline |
| a squared norm that wraps the field modulus passes all wraparound tests | `2^-100` per offline attempt | each test detects a wraparound with probability at least 1/2: [ROCT23] as cited by the draft, **not re-proved here** |

The VDAF draft (section 9.7) asks circuits with joint randomness to aim
for `(circuit_soundness + flp_soundness)^PROOFS` close to `2^-128`. At
norm bound 1.0 with 15 fractional bits and chunk length 4 that expression
is `2^-99.6` with the reference's 5 main proofs and `2^-139.5` with 7
(`num_proofs` is a task parameter). The wraparound line stays at `2^-100`
whatever the proof count: it is fixed by PINE's 100 tests.

With the reference's proof counts for this field (5 main proofs, 1
norm-equality proof) the first line is weak: `2^-23` at dimension 1000
and `2^-18` at dimension 100000 (table below), because a single
norm-equality proof is queried once. It is an online probability (a failed
try is a rejected report), which is how the reference justifies it. Raise
`num_proofs_norm_equality` when that is not enough: 3 proofs give `2^-69`
at dimension 1000.

## What was checked, and against what

`cargo test --release -- --test-threads=1` (OpenFHE 1.3.1, ring 8192,
p = 4293918721):

* `src/pine/circuit.rs` (7 tests): the reference's parameter guards; the
  encoding (ties to even, refused floats, the bound); the distribution and
  layout of the test vectors; both circuits are 0 on honest inputs and
  nonzero for each kind of violation; the closed-form verifier maps equal
  prio's `query` on random points; prio proves and decides both circuits.
* `tests/pine_upstream.rs` (3 tests), against the reference's `Field32`
  test vectors:
  * for the four vectors with the reference's default 100 wraparound tests
    (8 reports), each measurement is recombined from its shares with the
    reference's XOF and tags, and must equal what this crate encodes from
    the vector's floats: the gradient, the norm bits, and the wraparound
    part produced from the stream the reference derives. Both circuits are
    0 on it with the reference's joint randomness and nonzero on modified
    measurements, and the two joint-randomness seeds equal the vector's.
  * for all eight vectors (16 reports) the gradient encoding and the
    decoded aggregate match. (Four vectors use 75 wraparound tests, which
    this crate does not offer.)
  * both circuits agree with `pine-bgv-port/port/pine-circuit`, written
    separately from the same reference, on random inputs.

  **Not compared with the reference's vectors:** proofs and verifier
  messages. The reference builds on VDAF draft 11 (a proof holds the
  coefficients of the gadget polynomial); prio 0.18.1 implements draft 18
  (it holds values, the Lagrange basis). Proving and verifying are prio's.
* `tests/pine.rs` (12 tests, real ciphertexts and keys): exact sums; the
  verifier the collector decrypts equals prio's `query` on the plaintext;
  rejected among honest reports, with the sum unchanged: a norm beyond the
  bound, a squared norm that wraps the field modulus (both ways of
  claiming the tests), a claimed bit that is not a bit; the binding checks
  above; coefficients outside the layout change nothing; malformed and
  replayed reports and wrong counts are refused; a gradient of 9000
  coordinates over two ciphertexts; the single-use rules, also after both
  parties are rebuilt from the stored key and the same ledger directory
  (objects re-created in one process, not a killed process); a request
  with a malformed ciphertext, or with one nonce twice, is refused before
  anything is recorded or decrypted.
  One test documents a limit instead of a protection:
  `known_limit_an_evaluator_that_deviates_can_substitute_the_sum`.
* `src/pine.rs` (1 test): the flooding margin of a dense row summed over 4
  ciphertexts, measured on real ciphertexts: 85.7 bits. This is a
  measurement of one random instance. It is not a worst-case bound and not
  a proof of privacy against the collector (see "Not proved").
* Every task creation compares both closed-form verifier maps with prio's
  `query` at a random point and refuses to start on a mismatch.

The 47 tests that existed before still pass (70 in total).

## Measured cost

`results/measure-pine.jsonl`, machine in `results/measure-pine-machine.txt`
(4 cores at 2.1 GHz, 2 OpenMP threads, one process, one run per line, the
ledgers on the local disk). Norm bound 1.0 with 15 fractional bits except
the first line (the reference's vector shape: 7 bits). Sizes in bytes,
MB = 10^6.

| dimension | chunk (main / norm eq.) | proofs (main / norm eq.) | ciphertexts per report | report | check request per report | client | evaluator per report | collector per report | query soundness | joint randomness per attempt |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 20 | 4 / 4 | 5 / 1 | 3 | 1.04 MB | 6.88 MB | 20 ms | 1.08 s | 54 ms | 2^-28.2 | 2^-107.6 |
| 1000 | 2 / 4 | 5 / 1 | 5 | 1.74 MB | 4.42 MB | 36 ms | 0.66 s | 38 ms | 2^-23.0 | 2^-104.3 |
| 1000 | 4 / 4 | 5 / 1 | 4 | 1.39 MB | 6.88 MB | 27 ms | 1.04 s | 51 ms | 2^-23.0 | 2^-104.3 |
| 1000 | 8 / 4 | 5 / 1 | 3 | 1.04 MB | 11.80 MB | 23 ms | 1.76 s | 90 ms | 2^-23.0 | 2^-104.3 |
| 1000 | 4 / 4 | 5 / 3 | 4 | 1.39 MB | 8.36 MB | 29 ms | 1.24 s | 66 ms | 2^-69.0 | 2^-104.3 |
| 1000 | 4 / 4 | 7 / 3 | 4 | 1.39 MB | 10.81 MB | 31 ms | 1.58 s | 92 ms | 2^-69.0 | 2^-146.0 |
| 10000 | 4 / 8 | 5 / 1 | 5 | 1.74 MB | 7.37 MB | 44 ms | 1.28 s | 60 ms | 2^-20.0 | 2^-104.3 |
| 100000 | 4 / 16 | 5 / 1 | 18 | 6.27 MB | 8.36 MB | 227 ms | 2.83 s | 83 ms | 2^-18.0 | 2^-104.3 |

The aggregate request is one ciphertext of 122,888 bytes per 8192 gradient
coordinates, plus 40 bytes. The collector's time includes decoding every
ciphertext twice (once before anything is decrypted) and the ledger
writes.

Reading the table:
* A gradient of 100000 coordinates is 400 kB as plain field elements and a
  6.27 MB report: about 16 times.
* The chunk length trades client upload against evaluator-to-collector
  traffic and evaluator time: a smaller chunk means longer proofs (more
  report ciphertexts) and fewer verifier elements (one ciphertext each).
* Going from 5 to 7 main proofs (the VDAF draft's `2^-128` guidance, see
  above) costs 20 more verifier ciphertexts per report here: 8.36 MB to
  10.81 MB and about a quarter more evaluator time.
* The collector's work does not grow with the dimension; the evaluator's
  grows slowly (it reads more ciphertexts per verifier element).

## Limits of the parameters

* Field: FieldPrio2 only. PINE needs `p >= 2600 * wr_bound`, which
  p = 65537 cannot meet for any useful bound.
* Encoded norm bound `B <= 37832` (from `p > 3 B^2 + 2`): about 15 bits of
  fixed-point precision at real bound 1.0.
* Reports per batch: `(p - 1) / (2 B)` (65520 at `B = 32768`), so that the
  sum does not wrap.
* The reference's `alpha = 8.7`, 100 wraparound tests and 100 required
  successes are fixed.

## Not proved

* **The challenge derivation.** See "What the challenge derivation binds":
  byte binding is implemented and tested; that the protocol inherits
  PINE's or Prio3's security from it is not proved.
* **Privacy against the collector.** The collector receives ciphertexts
  whose coefficients, except those it is meant to read, carry fresh
  uniform masks, and whose noise is flooded. That the flooded noise hides
  everything else (the evaluator's rows, the report's own noise) is not
  proved here:
  * the 85.7-bit margin above is measured on one random instance;
  * the conservative worst-case analysis of the same parameters in
    `bgv-flp-oblivious/fhe-flp/results/phase-analysis` on `main` derives
    69.7 bits per coefficient and 56.7 bits over a whole ciphertext for one
    product (53.0 for 13 products) and does **not** certify 64 bits over a
    whole ciphertext. A verifier element here sums one product per
    ciphertext a row reads, up to all of a report's (3 to 18 in the table);
  * flooding the phase does not by itself randomize the whole ciphertext;
    a circuit-privacy argument for this use is missing;
  * the FLP's zero knowledge is prio's and the VDAF draft's, for honestly
    generated proofs queried once; that a verifier message is all the
    collector learns per report rests on the points above.
* **The composition.** No proof covers FLP, wraparound tests, challenge
  derivation and encryption together. The table of probabilities is an
  accounting of known bounds, with the wraparound bound taken from the
  literature.

## Not done

* **Nothing authenticates the evaluator's computation.** The collector
  decrypts what it is sent. An evaluator that deviates can have the
  collector decrypt linear functions other than the verifier (and learns
  one accept/reject bit for each), and can replace the aggregate by a
  ciphertext of its choice: the batch identifier and the accepted count it
  must quote are no proof that the ciphertext sums the accepted reports.
  `known_limit_an_evaluator_that_deviates_can_substitute_the_sum` shows
  the substitution succeeding. Closing this needs a proof of the
  evaluator's linear computation that the collector can check without
  seeing reports, and clients that authenticate their reports; neither
  exists here.
* The evaluator learns the verdicts. `OBLIVIOUS-AGGREGATION-PLAN.md`
  describes hiding them; the implementation on `main`
  (`bgv-flp-oblivious`) does not cover PINE.
* The collector does not check the noise of what it decrypts
  (`HARDENING-PLAN.md`, W1).
* The single-use rules have the limits listed under "Single use": a
  trusted, never-rolled-back ledger directory; nonces as stated by the
  evaluator; no client identity. The restart test re-creates the objects
  in one process; it does not kill a process mid-request.
* Proofs and verifier messages are not compared with the reference's
  test vectors (different VDAF draft, see above).
* Side channels (timing of decisions, error messages) are not analysed.
* This is aggregation only: no training loop, no clipping policy, no
  differential-privacy noise, no client authentication.
* One run per measurement on a shared machine: the times are indications.
