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
   (`encode_measurement`). It builds k proofs with prio 0.18.1's unchanged
   `Flp::prove` and encrypts `z = input ‖ proofs` as the coefficients of
   **one** BGV plaintext. Report = `nonce ‖ residues`.
2. **Evaluator, per report** (`ingest`). Parses the report, using the
   self-tested rebuild that never runs OpenFHE's deserializer. Refuses
   replayed nonces. Derives the FLP query randomness from its secret
   `verify_key`, the nonce and SHA-256 of the report.
3. **Evaluator, at batch end** (`check_request`). For each report and each
   group of verifier rows it computes four things:
   * `ct × Q̃`: one plaintext multiplication, depth 0, no evaluation keys.
     Coefficient `j·|z|` of the result is verifier row `j`.
   * Plus a plaintext that holds the verifier constants at those
     coefficients and **fresh uniform field elements at every other
     coefficient**. Those coefficients are one-time-padded.
   * Flooding: `t·E` with E uniform over 135 bits, which hides the noise.
   * BGV modulus switching down to one tower. This only shrinks the
     message; it is post-processing of the flooded ciphertext.
4. **Collector** (`check`). Decrypts only the verifier coefficients, runs
   Prio3's `decide` on every proof, and returns one bit per report.
5. **Evaluator** (`aggregate_request`). Sums the accepted reports, masks
   every coefficient except the output ones, floods and switches down.
6. **Collector** (`unshard`). Decrypts the output coefficients. It refuses
   if the count differs from the number of reports it accepted.

## Parameters (measured)

* Plaintext modulus = FLP field = prio's `FieldPrio2`, p = 4,293,918,721 (default; for
  p = 65537 see "Second field" below).
* OpenFHE 1.3.1 BGV, single key, `FIXEDMANUAL`, BV key switching (no P),
  uniform ternary secret, `HEStd_128_classic`.
* Ring 8192; towers [60, 55, 55], so Q = 170 bits (the limit at ring 8192
  is 218).
* Why three towers. Two towers (≈ 120 bits) leave a flooding margin of
  only about 37 bits after a worst-case product. With t ≈ 2³², OpenFHE's
  `FIXEDMANUAL` chain needs towers of at least 55 bits. The probe in this
  work: [60, 47] and [60, 50] fail; [60, 55] gives λ ≈ 32; [60, 55, 55]
  gives λ = 86.7.
* Flooding margin after the densest possible query product: **λ = 86.7
  bits**, i.e. statistical distance ≤ 2⁻⁸⁶ per revealed coefficient
  (`openfhe-tbgv-rs/tests/single_key.rs`).
* Proofs: the fewest reaching 2⁻¹²⁸ (Count 5, BitVec 5–6; `results/soundness.md`).

## Measured (`results/measure-single.jsonl`; 16 reports; 4 vCPU Xeon 2.8 GHz)

| Task | Proofs | Report | Evaluator per report | Collector per report | Check request per report |
|---|---|---|---|---|---|
| Count | 5 | **348,176 B** | 20.6 ms | 0.8 ms | 122,880 B |
| BitVec(10) | 5 | 348,176 B | 21.4 ms | 0.8 ms | 122,880 B |
| BitVec(25) | 5 | 348,176 B | 20.4 ms | 1.3 ms | 122,880 B |
| BitVec(50) | 6 | 348,176 B | 58.0 ms | 2.3 ms | 368,640 B |
| BitVec(100) | 6 | 348,176 B | 115.1 ms | 4.4 ms | 737,280 B |

The collector's public key is 394,161 B. There are no evaluation keys. The
aggregate request is 122,888 B per batch.

Comparison of report sizes:

| | Report | Trust |
|---|---|---|
| Original-encoding package (Fermat check, ring 32768) | 5,578,879 B (Count) to 7,405,695 B (SumVec100) | one evaluator, collector offline until the total |
| **This, one aggregator** | **348,176 B** (16–21× smaller) | one evaluator, collector also decrypts the check values once per batch |
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
* proofs for 2^-128: Count 9, BitVec(10/25/50/100) 12/13/15/16 (padded-degree
  bound, `src/soundness.rs`; the draft script's formula would allow 14 for
  BitVec(50), which the padded construction does not support).

**Ring 4096 is not possible at our standard.** The best chain at ring
4096 within the 128-bit bound ([50, 55], 105 bits) gives a margin of only
λ = 53.9 (measured), below the 64 we require. The earlier ~110 KB figure
was an estimate that turned out wrong.

Measured (`results/measure-single-fields.jsonl`; same machine; 16 reports
for Count, 8 for BitVec):

| p | Task | Proofs | Report | Evaluator per report | Collector per report | Check request per report |
|---|---|---|---|---|---|---|
| 4293918721 | Count | 5 | 348,176 B | 20.8 ms | 0.8 ms | 122,880 B |
| **65537** | **Count** | 9 | **245,776 B** | 24.2 ms | 1.3 ms | 81,920 B |
| 4293918721 | BitVec(10) | 5 | 348,176 B | 18.0 ms | 0.9 ms | 122,880 B |
| 65537 | BitVec(10) | 12 | 245,776 B | 64.3 ms | 2.3 ms | 245,760 B |
| 4293918721 | BitVec(100) | 6 | 348,176 B | 108.6 ms | 7.0 ms | 737,280 B |
| 65537 | BitVec(100) | 16 | 245,776 B | 967.7 ms | 48.5 ms | 5,242,880 B |

* **Count:** p = 65537 is 29% smaller at about the same cost. It is the
  better choice.
* **Vectors:** the report shrinks just as much, but each additional proof
  lengthens every verifier row. For BitVec(100), 16 proofs make z
  4,212 coefficients long, so only one row fits a product: 64 products per
  report, about 1 s of evaluator time and 5.2 MB of check traffic per
  report at batch end. Pick the field per task.

**Why it isn't KB.** The flooded phase grows with 2·log p + log(row
length), and the 128-bit bound caps Q at 109 bits for ring 4096. Even with
p = 65537 the margin at ring 4096 is 54 bits, so ring 8192 (≥ 240 KB) is
the floor at λ ≥ 64.

## Prio3 variants covered

| Prio3 type | Status |
|---|---|
| Count | **yes**: Prio3's exact encoding and circuit |
| SumVec with `max = 1` | **yes** (`BitVec`): Prio3's encoding; a circuit without joint randomness |
| Sum, SumVec with `max > 1`, Histogram, MultihotCountVec | **not yet.** Sum's aggregate is the decoded integer, not the bits. The other three use joint randomness, which needs circuits without it, as `BitVec` shows for bit vectors. |

## Not done (for production)

* **Semi-honest evaluator.** It could submit, say, a unit-vector query and
  have the collector decrypt one input coefficient. Neither the collector
  nor any proof checks that the evaluator's products are honest FLP
  queries. This is the non-collusion assumption; removing it needs a proof
  of correct evaluation.
* **Malformed client ciphertexts** (noise far beyond honest): argued, not
  proven, as in `DESIGN.md` and the other packages.
* No transport, persistence or batch policy. The verify key is generated
  by the evaluator alone. The OpenFHE and prio code paths are not
  constant-time. No independent review.

## Reproduce

```sh
cd prio3/openfhe-tbgv-rs && cargo test --release -- --test-threads=1   # incl. tests/single_key.rs, single self-test
cd ../fhe-flp && cargo test --release -- --test-threads=1               # incl. tests/single.rs, tests/single_p65537.rs
cargo run --release --bin measure_single -- count                      # p = 4293918721
cargo run --release --bin measure_single -- count --field 65537
cargo run --release --bin measure_single -- bitvec --len 100 --field 65537
```
