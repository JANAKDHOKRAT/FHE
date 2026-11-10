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
ciphertexts. Not production certified.** "Not done" below lists what is
missing; nothing in this file claims more than the tests and measurements
named in it.

## Parties and trust

The same as `ONE-AGGREGATOR.md`: one evaluator (holds reports and a secret
`verify_key`), one collector (holds the whole BGV secret key). They must
not collude and must follow the protocol. Clients may be malicious.

| Party | Learns |
|---|---|
| evaluator | ciphertexts, and one accept/reject bit per report |
| collector | per report the FLP verifier messages (zero knowledge for valid reports), then the sum of the accepted gradients |

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
2. **Evaluator.** Re-derives the test vectors and the joint randomness
   from the bytes it received, and the query points from its `verify_key`
   and the whole report. Each verifier element is an affine function of the
   report's plaintext; the dot products of the wraparound tests are linear
   in the gradient and are folded into it. Per element: the sum over the
   report's ciphertexts of one plaintext product, the element at
   coefficient 0, a fresh uniform mask on every other coefficient, noise
   flooding, switch to one tower.
3. **Collector.** Decrypts coefficient 0 of each, runs prio's `decide` on
   every proof, returns one bit per report.
4. **Evaluator.** Sums the `G` ciphertexts of the accepted reports, masks
   every coefficient that is not a gradient coordinate, floods, switches to
   one tower.
5. **Collector.** Decrypts the gradient coordinates and decodes them
   (centered lift divided by `2^f`): the sum of the accepted gradients.

Depth 0: plaintext products and additions only, no evaluation keys.

### Why the challenges are bound

PINE draws its randomness in two steps, each after the client is committed
to what the step tests. Here the commitment is the ciphertext bytes
(decryption is a function of them), as `single.rs` does for Prio3's joint
randomness. `W` cannot depend on test vectors other than those `G` fixes,
and the proofs cannot change `G` or `W`: every verifier row reads each part
only from that part's ciphertexts, and coefficients outside the layout are
multiplied by 0. `tests/pine.rs` checks that a part of another valid
report, a fresh encryption of the same gradient part, or another nonce
makes a valid report invalid.

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
* `tests/pine.rs` (9 tests, real ciphertexts and keys): exact sums; the
  verifier the collector decrypts equals prio's `query` on the plaintext;
  rejected among honest reports, with the sum unchanged: a norm beyond the
  bound, a squared norm that wraps the field modulus (both ways of
  claiming the tests), a claimed bit that is not a bit; the binding checks
  above; coefficients outside the layout change nothing; malformed and
  replayed reports and wrong counts are refused; a gradient of 9000
  coordinates over two ciphertexts.
* `src/pine.rs` (1 test): the flooding margin of a dense row summed over 4
  ciphertexts, measured on real ciphertexts: 85.7 bits. A measurement of
  that instance, not a worst-case bound; a row over more ciphertexts loses
  up to one bit per doubling.
* Every task creation compares both closed-form verifier maps with prio's
  `query` at a random point and refuses to start on a mismatch.

The 47 tests that existed before still pass (67 in total).

## Measured cost

`results/measure-pine.jsonl`, machine in `results/measure-pine-machine.txt`
(4 cores at 2.1 GHz, 2 OpenMP threads, one process, one run per line).
Norm bound 1.0 with 15 fractional bits except the first line (the
reference's vector shape: 7 bits). Sizes in bytes, MB = 10^6.

| dimension | chunk (main / norm eq.) | proofs (main / norm eq.) | ciphertexts per report | report | check request per report | client | evaluator per report | collector per report | query soundness |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|
| 20 | 4 / 4 | 5 / 1 | 3 | 1.04 MB | 6.88 MB | 24 ms | 0.97 s | 31 ms | 2^-28.2 |
| 1000 | 2 / 4 | 5 / 1 | 5 | 1.74 MB | 4.42 MB | 31 ms | 0.55 s | 24 ms | 2^-23.0 |
| 1000 | 4 / 4 | 5 / 1 | 4 | 1.39 MB | 6.88 MB | 27 ms | 0.90 s | 34 ms | 2^-23.0 |
| 1000 | 8 / 4 | 5 / 1 | 3 | 1.04 MB | 11.80 MB | 22 ms | 1.53 s | 60 ms | 2^-23.0 |
| 1000 | 4 / 4 | 5 / 3 | 4 | 1.39 MB | 8.36 MB | 26 ms | 1.09 s | 42 ms | 2^-69.0 |
| 10000 | 4 / 8 | 5 / 1 | 5 | 1.74 MB | 7.37 MB | 45 ms | 1.05 s | 43 ms | 2^-20.0 |
| 100000 | 4 / 16 | 5 / 1 | 18 | 6.27 MB | 8.36 MB | 220 ms | 2.35 s | 43 ms | 2^-18.0 |

Joint randomness per offline attempt: `2^-104.3` (`2^-107.6` on the first
line). The aggregate request is one ciphertext of 122,888 bytes per 8192
gradient coordinates.

Reading the table:
* A gradient of 100000 coordinates is 400 kB as plain field elements and a
  6.27 MB report: about 16 times.
* The chunk length trades client upload against evaluator-to-collector
  traffic and evaluator time: a smaller chunk means longer proofs (more
  report ciphertexts) and fewer verifier elements (one ciphertext each).
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

## Not done

* Everything `ONE-AGGREGATOR.md` lists under "Not done" applies: the
  evaluator learns the verdicts; requests are not bound to a batch and
  nothing is durable across restarts; the collector does not check the
  noise of what it decrypts; an evaluator that deviates can make the
  collector decrypt other linear functions or change the sum.
  `HARDENING-PLAN.md` and `OBLIVIOUS-AGGREGATION-PLAN.md` describe these;
  the implementation of them on `main` (`bgv-flp-oblivious`) does not
  cover PINE.
* No security proof of the composition. The table of probabilities above
  is an accounting of known bounds, with the wraparound bound taken from
  the literature.
* Proofs and verifier messages are not compared with the reference's
  test vectors (different VDAF draft, see above).
* This is aggregation only: no training loop, no clipping policy, no
  differential-privacy noise, no client authentication.
* One run per measurement on a shared machine: the times are indications.
