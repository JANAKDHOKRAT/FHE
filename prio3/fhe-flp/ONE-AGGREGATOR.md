# One aggregator: BGV + Prio3's FLP, collector holds the whole key

`src/single.rs` is the one-aggregator version of `fhe-flp`. `DESIGN.md`
describes the threshold version, with n ≥ 2 aggregators sharing the key.

**Status: research implementation, tested end to end. Not production
certified.** See "Not done" below.

## Parties and trust

| Party | Holds | Learns |
|---|---|---|
| client | collector's public key | — |
| **evaluator** (the one aggregator) | reports, a secret `verify_key` | ciphertexts only, and one accept/reject bit per report |
| **collector** | the whole BGV secret key | per report, the FLP verifier message (what Prio3's aggregators learn; zero-knowledge); then the aggregate |

The evaluator and the collector must not collude, and both must follow the
protocol. This is the same assumption this repository's single-evaluator
packages make. Clients may be malicious.

The collector is involved **once per batch** (two messages) and never sees
a report ciphertext. Compared with the original-encoding package, the one
change is that the collector also decrypts the FLP check values at the end
of the batch, not only the total.

## Protocol

1. **Client.** Encodes the measurement exactly as Prio3 does
   (`encode_measurement`) and builds k proofs with prio 0.18.1's unchanged
   `Flp::prove`. Report = `nonce ‖ residues`:
   * types without joint randomness (Count, Sum, BitVec): **one**
     ciphertext of `z = input ‖ proofs` (coefficient encoding);
   * types with joint randomness (SumVec, Histogram, MultihotCountVec):
     **two** ciphertexts. The client first encrypts the input, derives each
     proof's joint randomness from TurboSHAKE128(nonce, SHA-256(input
     ciphertext)) — the input ciphertext plays the part of Prio3's joint
     randomness commitment — then proves and encrypts the proofs (at their
     coefficients `[|input|, |z|)`) in a second ciphertext.
2. **Evaluator, per report** (`ingest`). Parses the report, using the
   self-tested rebuild that never runs OpenFHE's deserializer. Refuses
   replayed nonces. Derives the FLP query randomness from its secret
   `verify_key`, the nonce and SHA-256 of the report, and the joint
   randomness exactly as the client did.
3. **Evaluator, at batch end** (`check_request`). Per report:
   * for each group of verifier rows, `ct × Q̃` (one plaintext
     multiplication, depth 0, no evaluation keys; coefficient `j·|z|` is
     verifier row `j`). With two ciphertexts it is
     `ct_in × Q̃_in + ct_proofs × Q̃_proofs`: each row's input part reads only
     the input ciphertext and its proof part only the proof ciphertext, so
     the proof ciphertext cannot change the input that fixed the joint
     randomness. The verifier constants go to the verifier coefficients and
     fresh uniform field elements to every other coefficient;
   * a **support check** per ciphertext: the ciphertext plus fresh uniform
     field elements on the coefficients an honest report may use (`z`, or
     the input, or the proofs), every other coefficient untouched;
   * every object is flooded (`t·E`) and switched to one tower.
4. **Collector** (`check`). Decrypts only the verifier coefficients and, for
   the support checks, every coefficient outside the honest support. It
   accepts a report only if all of those are 0 **and** Prio3's `decide`
   accepts every proof. One bit per report goes back.
5. **Evaluator** (`aggregate_request`). Sums the accepted (input)
   ciphertexts and maps the sum to the aggregate with prio's `truncate`:
   Count, BitVec, Histogram and MultihotCountVec output input coordinates;
   for Sum and SumVec (bits weighted by Prio3's powers of two) the sum is
   multiplied by the one plaintext `W = Σ_t w_t X^{-t}`, whose coefficient
   `j·bits` is output `j`. Every other coefficient is masked; flooded,
   switched to one tower: **one ciphertext** for every type.
6. **Collector** (`unshard`). Decrypts the output coefficients and runs
   Prio3's `decode_result`. It refuses if the count differs from the number
   of reports it accepted.

### Why the support check (a fixed soundness bug)

A client controls its whole plaintext polynomial, not only `z`. In a
product that packs several verifier rows, a coefficient above `z` meets the
rows packed below the one being read and shifts the verifier.
`tests/junk_coefficients.rs` builds a Count report for the **invalid input
2** whose extra coefficients make prio's `decide` accept every proof. Before
the support check the protocol (both versions) accepted it; now it is
rejected. The check is exact: an honest plaintext is 0 off its support, so
the collector learns nothing from it, and a single nonzero coefficient
anywhere is caught (tested at several positions).

The aggregate map has the same property by construction: each output
coefficient reads only input coefficients, whatever else the plaintext
holds (unit test in `src/single.rs`).

## Parameters (measured)

* Plaintext modulus = FLP field: prio's `FieldPrio2`, p = 4,293,918,721,
  or **p = 65537** (`src/f65537.rs`, below).
* OpenFHE 1.3.1 BGV, single key, `FIXEDMANUAL`, BV key switching (no P),
  uniform ternary secret, `HEStd_128_classic`, ring 8192.
* FieldPrio2: towers [60, 55, 55] (Q = 170 bits), worst-case flooding
  margin λ = 86.7 bits. p = 65537: towers [40, 40, 40] (Q = 120 bits),
  λ = 67.9 bits (`openfhe-tbgv-rs/tests/single_key.rs`).
* Proofs: the fewest reaching 2⁻¹²⁸ (`results/soundness.md`), joint
  randomness included (`chunk_length / p` per proof, as in the VDAF draft).
* Batch size: at most `(p − 1) / (largest output of one report)` so no
  aggregate wraps modulo p (65,536 for bit outputs at p = 65537, 655 for
  Sum(100)), and at most 2²⁴.

## Measured (`results/measure-single-variants.jsonl`; 8 reports each; 4 vCPU Xeon 2.8 GHz)

Every run checks the decrypted aggregate against the plaintext sum. The
public key is 394 KB; there are no evaluation keys. The aggregate request is
one reduced ciphertext: 81,928 B (p = 65537) or 122,888 B (FieldPrio2).

**p = 65537**

| Prio3 type | Proofs | Ciphertexts | Soundness (log2) | Joint-rand. attempt (log2) | Report | Check request per report | Evaluator check per report | Collector per report | Max batch |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Count | 9 | 1 | -135.0 | — | 245,776 B | 163,840 B | 33.6 ms | 2.5 ms | 65,536 |
| BitVec(10) | 12 | 1 | -132.5 | — | 245,776 B | 327,680 B | 89.0 ms | 5.5 ms | 65,536 |
| BitVec(100) | 16 | 1 | -128.0 | — | 245,776 B | 5,324,800 B | 1361.4 ms | 85.2 ms | 65,536 |
| Sum(100) | 11 | 1 | -133.0 | — | 245,776 B | 163,840 B | 23.5 ms | 1.6 ms | 655 |
| SumVec(10, max 3) | 11 | 2 | -131.0 | -158.6 | 491,536 B | 409,600 B | 81.5 ms | 3.9 ms | 21,845 |
| SumVec(100, max 1) | 12 | 2 | -129.5 | -158.3 | 491,536 B | 1,474,560 B | 411.8 ms | 14.6 ms | 65,536 |
| Histogram(100) | 12 | 2 | -129.0 | -158.3 | 491,536 B | 1,474,560 B | 425.3 ms | 13.4 ms | 65,536 |
| MultihotCountVec(100, weight 10) | 12 | 2 | -129.0 | -158.3 | 491,536 B | 1,474,560 B | 352.2 ms | 14.8 ms | 65,536 |

**p = 4,293,918,721 (FieldPrio2)**

| Prio3 type | Proofs | Ciphertexts | Soundness (log2) | Joint-rand. attempt (log2) | Report | Check request per report | Evaluator check per report | Collector per report | Max batch |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Count | 5 | 1 | -155.0 | — | 348,176 B | 245,760 B | 42.8 ms | 1.8 ms | 16,777,216 |
| BitVec(10) | 5 | 1 | -135.2 | — | 348,176 B | 245,760 B | 33.6 ms | 1.9 ms | 16,777,216 |
| BitVec(100) | 6 | 1 | -144.0 | — | 348,176 B | 860,160 B | 179.8 ms | 11.3 ms | 16,777,216 |
| Sum(100) | 5 | 1 | -140.5 | — | 348,176 B | 245,760 B | 37.9 ms | 2.8 ms | 16,777,216 |
| SumVec(10, max 3) | 5 | 2 | -139.6 | -152.1 | 696,336 B | 368,640 B | 54.9 ms | 2.8 ms | 16,777,216 |
| SumVec(100, max 1) | 5 | 2 | -134.0 | -146.0 | 696,336 B | 737,280 B | 112.9 ms | 5.2 ms | 16,777,216 |
| Histogram(100) | 5 | 2 | -133.8 | -146.0 | 696,336 B | 737,280 B | 144.8 ms | 5.0 ms | 16,777,216 |
| MultihotCountVec(100, weight 10) | 5 | 2 | -133.8 | -146.0 | 696,336 B | 737,280 B | 122.9 ms | 5.9 ms | 16,777,216 |

* **Report size.** One ciphertext (Count, Sum, BitVec) is **245,776 B** at
  p = 65537; two (the joint-randomness types) are 491,536 B. The second
  ciphertext is the price of keeping Prio3's circuits, which use joint
  randomness, unchanged: the input must be fixed before the proofs exist.
  `BitVec` is the same SumVec(max 1) encoding with a circuit that needs no
  joint randomness, and stays at one ciphertext.
* **Check traffic.** Prio3's own SumVec(100) circuit (chunked gadget,
  12 proofs) needs 1.47 MB per report at p = 65537, against 5.3 MB for
  BitVec(100) (16 proofs, one long gadget): pick per task.
* **Joint randomness, offline attempts.** The client can re-encrypt its
  input and recompute the joint randomness offline, as in Prio3. The column
  gives log2 of the chance that one attempt produces joint randomness under
  which every proof's range check misses (`(chunk_length / p)^proofs`);
  2^q attempts multiply it by 2^q. At p = 65537 it is 2⁻¹⁵⁸ per attempt
  (2⁻⁹⁴ after 2⁶⁴ attempts); Prio3 with one proof over Field128 is about
  2⁻¹²⁴ per attempt.

Comparison of report sizes:

| | Report | Trust |
|---|---|---|
| Original-encoding package (Fermat check, ring 32768) | 5,578,879 B (Count) to 7,405,695 B (SumVec100) | one evaluator, collector offline until the total |
| **This, one aggregator, p = 65537** | **245,776 B** (Count, Sum, BitVec); **491,536 B** (SumVec, Histogram, MultihotCountVec) | one evaluator, collector also decrypts the check values once per batch |
| `fhe-flp` threshold (`DESIGN.md`) | 419,856 B | n ≥ 2 aggregators sharing the key |
| Prio3 | 80 B (Count), 2,480 B (SumVec100) | two non-colluding aggregators, no FHE |

## Second field: p = 65537 (`--field 65537`)

The protocol is generic over the field (`FheField`). Besides FieldPrio2 it
runs in **GF(65537)**, the prime of the original-encoding package. prio
0.18.1 has no such field, so `src/f65537.rs` implements prio's public field
traits for it:
* It follows the conventions of prio's own field macro: fully reduced
  values, canonical little-endian bytes, decoding refuses values ≥ p, and
  random sampling masks to 17 bits and then rejects ≥ p.
* Arithmetic doesn't branch on element values.
* Tests:
  * every one of the 65,536 nonzero elements times its inverse is 1;
  * add, sub, mul, neg and pow agree with integer arithmetic;
  * `root(l)` is the principal 2^l-th root for every l ≤ 16, and `None`
    above;
  * encode/decode and serde round trips, with refusal of values ≥ p;
  * prio's `prove`/`query`/`decide` and our closed-form verifier map work
    in the field.
* GF(65537) has 2-power roots only up to 2^16. prio's NTT panics (measured)
  once a gadget's wire length reaches 2^16. `FlpPlan::new` refuses such
  circuits with an error, and a test checks both sides of the boundary.

Parameters for p = 65537:
* chain [40, 40, 40], Q = 120 bits, ring 8192;
* worst-case flooding margin λ = 67.9 bits
  (`openfhe-tbgv-rs/tests/single_key.rs`);
* proofs for 2^-128: Count 9, BitVec(10/25/50/100) 12/13/15/16, Sum(100)
  11, SumVec(10, max 3) 11, SumVec(100), Histogram(100) and
  MultihotCountVec(100) 12 (padded-degree bound plus joint randomness,
  `src/soundness.rs`; the draft script's formula would allow 14 for
  BitVec(50), which the padded construction does not support).

**Ring 4096 is not possible at our standard.** The best chain at ring
4096 within the 128-bit bound ([50, 55], 105 bits) gives a margin of only
λ = 53.9 (measured), below the 64 we require. The earlier ~110 KB figure
was an estimate that turned out wrong.

Measured: see the p = 65537 table above.
* **Count, Sum:** p = 65537 is 29% smaller than FieldPrio2 (245,776 vs
  348,176 B) at about the same cost. It is the better choice.
* **Vectors:** the report shrinks just as much, but each additional proof
  lengthens every verifier row. For BitVec(100), 16 proofs make z
  4,212 coefficients long, so only one row fits a product: 64 products per
  report, about 1 s of evaluator time and 5.3 MB of check traffic per
  report at batch end. Prio3's chunked circuits (SumVec, Histogram,
  MultihotCountVec) need 12 proofs and 1.47 MB. Pick the field per task.

**Why it isn't KB.** The flooded phase grows with 2·log p + log(row
length), and the 128-bit bound caps Q at 109 bits for ring 4096. Even with
p = 65537 the margin at ring 4096 is 54 bits, so ring 8192 (≥ 240 KB) is
the floor at λ ≥ 64.

## Prio3 variants covered

prio 0.18.1's types, encodings, circuits and decoding are used unchanged,
in both fields (`tests/single_variants.rs`, `tests/single.rs`,
`tests/single_p65537.rs`).

| Prio3 type | Ciphertexts | Aggregate under encryption | Tested |
|---|---|---|---|
| Count | 1 | input coordinate | end to end, verifier = prio `query`, invalid / tampered rejected |
| Sum | 1 | `Σ w_b · bit_b` (one plaintext product) | end to end, verifier = prio `query`, non-bit and tampered rejected |
| SumVec | 2 | same, per entry (one plaintext product for all entries) | end to end, verifier = prio `query` with joint randomness, non-bit and tampered rejected |
| Histogram | 2 | input coordinates | end to end, verifier = prio `query`, two-hot and all-zero rejected |
| MultihotCountVec | 2 | input coordinates | end to end (FieldPrio2), over-weight rejected |
| BitVec (SumVec with max 1, circuit without joint randomness) | 1 | input coordinates | end to end, closed-form verifier |

The binding of joint randomness is tested directly: a report whose proof
ciphertext also carries `good − bad` at the input coefficients (so that the
summed plaintext is a valid `z`) is rejected, and so is a valid report
whose input ciphertext is swapped for another's
(`the_proofs_cannot_change_the_input_that_fixed_the_joint_randomness`).
With the earlier design that simply added the two ciphertexts, the first of
these was accepted (checked before the fix).

## Not done (for production)

* **Semi-honest evaluator.** It could submit, say, a unit-vector query and
  have the collector decrypt one input coefficient. Neither the collector
  nor any proof checks that the evaluator's products are honest FLP
  queries. This is the non-collusion assumption; removing it needs a proof
  of correct evaluation.
* **Malformed client ciphertexts** (noise far beyond honest): argued, not
  proven, as in `DESIGN.md` and the other packages. (Plaintexts with
  coefficients outside the honest support are now rejected exactly; see
  "Why the support check".)
* **Joint randomness** is derived from the input ciphertext by the
  evaluator, not from a Prio3-style commitment checked by two aggregators;
  its offline-attempt bound is in the table above.
* No transport, persistence or batch policy. The verify key is generated
  by the evaluator alone. The OpenFHE and prio code paths are not
  constant-time. No independent review.

## Reproduce

```sh
cd prio3/openfhe-tbgv-rs && cargo test --release -- --test-threads=1   # incl. tests/single_key.rs, single self-test
cd ../fhe-flp && cargo test --release -- --test-threads=1               # incl. single*, junk_coefficients
cargo run --release --bin measure_single -- count                      # p = 4293918721
cargo run --release --bin measure_single -- count --field 65537
cargo run --release --bin measure_single -- sum --max 100 --field 65537
cargo run --release --bin measure_single -- sumvec --len 100 --max 1 --field 65537
cargo run --release --bin measure_single -- histogram --len 100 --field 65537
cargo run --release --bin measure_single -- multihot --len 100 --weight 10 --field 65537
```
