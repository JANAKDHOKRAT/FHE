# fhe-flp: Prio3's fully linear proofs, checked under threshold BGV

**Status: research implementation, tested end to end. Not production
certified.** "What is missing for production" below lists what a deployment
still needs.

This file describes the threshold version (n ≥ 2 aggregators share the
key). For one aggregator with a collector that holds the whole key, see
[ONE-AGGREGATOR.md](ONE-AGGREGATOR.md).

## Idea

Prio3 validates a client's input with a *fully linear proof* (FLP;
draft-irtf-cfrg-vdaf, BBCGGI19). The proof is cheap because the verifier
needs only **linear** functions of `(input, proof)` plus a tiny final check
(`decide`). Linear functions are also the cheapest operation in FHE: one
plaintext × ciphertext product, with no ciphertext × ciphertext product.

So the client builds Prio3's proof exactly as Prio3 does (prio 0.18.1's
`Flp::prove`, unchanged). It encrypts `z = input ‖ proof_1 ‖ … ‖ proof_k` as
the **coefficients of one BGV plaintext** under an n-of-n threshold key. The
aggregators evaluate the verifier homomorphically and decrypt only the
verifier message, which is exactly what Prio3's aggregators learn. They run
Prio3's `decide` and add the accepted ciphertexts.

The circuit has depth 0, so there are no relinearisation or rotation keys.
With BV key switching (no auxiliary modulus P) OpenFHE then selects
**ring 8192** at 128-bit HE-standard security. `fhe-prio3` needs depth 3 and
ring 32768.

## Protocol (`src/protocol.rs`)

| Step | Who | What |
|---|---|---|
| setup | aggregators | n-of-n threshold key (`keygen_first` / `keygen_next`), secret 32-byte `verify_key` |
| shard | client | `encode_measurement` → k × `Flp::prove` (randomness from a fresh seed via TurboSHAKE128) → encrypt `z` as a coefficient plaintext → report = `nonce ‖ packed residues` |
| prepare_init | each aggregator | rebuild the ciphertext (validated, self-tested); query randomness = TurboSHAKE128(`verify_key`; nonce, SHA-256(report)), one per proof; verifier map `z ↦ v` per proof; per group of rows one product `ct × Q̃`, where coefficient `j·|z|` of the product is `⟨row_j, z⟩`; flooded partial decryption **restricted to those coefficients** = verifier share; plus 5 support checks: `ct × R_t` with `R_t` secret (from `verify_key`), uniform on `[0, N − |z|)` and 0 above, partially decrypted at coefficient `N − 1` only |
| prepare_finish | each aggregator | rebuild the other parties' restricted partials, check they lie in the flooding range, fuse → verifier message, add constants; reject unless all 5 support checks fuse to 0; `Flp::decide` per proof; accept ⇒ add the ciphertext to the running sum |
| aggregate_share | each aggregator | flooded partial decryption of the sum restricted to the output coefficients |
| unshard | collector | fuse → `decode_result` |

Details that matter:

* **Only the requested coefficients are ever decrypted.** The shim zeroes
  every other coefficient of a party's partial before it leaves the
  function (`tbgv_partial_decrypt_coeffs`). Fusion refuses if anything
  outside the requested set is non-zero. Shares travel as just the kept
  residues (`tbgv_partial_export_coeffs` / `tbgv_partial_from_coeffs`).
* **Verifier map.** `Flp::query` is affine in `(input, proof)` once its
  randomness is fixed. For Count and BitVec (one `Mul` gadget) the map has a
  closed form, derived from prio's `query` / `QueryShimGadget` and checked
  against `Flp::query` at random points every time a task is created. It is
  also unit-tested, including the case where the gadget point lies on the
  2W-th roots of unity. Other types fall back to reading the map off
  `Flp::query` column by column. That costs `|input|+|proof|+1` queries per
  proof, and each query is O(n²) in prio 0.18.1.
* **Query randomness** is derived as in Prio3 (secret verify key, nonce),
  with one difference: a gadget point that is a root of unity of the
  wire-polynomial order is resampled from the same stream. `Flp::query`
  refuses such points, which in a 32-bit field would reject an *honest*
  report with probability ≈ W/p per proof (2⁻²⁵ for BitVec(100)).
* **No joint randomness.** Input and proof share one ciphertext, so there
  is no input commitment to derive joint randomness from. `Task::new`
  refuses such types. `BitVec` (`src/bitvec.rs`) is Prio3SumVec's language
  with `max = 1` and a circuit without joint randomness: one range-check
  output per element, compressed by the *verifier's* query randomness. The
  proof is then O(len), not O(√len). This costs nothing here while `z` fits
  in the ring, because the report is one ciphertext of fixed size.

## Parameters (measured, `results/`)

* Plaintext modulus = FLP field = prio's `FieldPrio2`, p = 4,293,918,721
  (the same prime `fhe-prio3` uses).
* OpenFHE 1.3.1 BGV, `NOISE_FLOODING_MULTIPARTY`, `FLEXIBLEAUTOEXT`,
  uniform ternary secret, depth 0, BV key switching, `HEStd_128_classic`.
  Result: N = 8192, Q = 203 bits (limit at N = 8192: 218), towers
  [47, 60, 60, 36].
* The BV digit size is 30 (`DIGIT_SIZE`). It never drives key switching.
  It only sizes the last tower, which the plaintext product drops: 36 bits
  instead of 16 with digit 1. That raises the worst-case flooding margin
  from 52 to 75 bits for 4% larger reports.
* Proofs: the fewest that reach 2⁻¹²⁸ (Count 5, BitVec(100) 6); the tests
  use fewer.

## Security argument

**Privacy against any coalition that excludes one honest aggregator.**
1. The report is an RLWE ciphertext under the joint key, with N = 8192 and
   log Q = 203 ≤ 218 (HE standard, ternary secret, 128-bit classical). BV
   has no P, so every sample under this context, key-switching keys
   included, lives modulo Q. No key-switching key is generated anyway.
2. Aggregators decrypt only the verifier coefficients. Fused, these are
   *exactly* prio's `Flp::query` output, which is Prio3's combined verifier
   message. `tests/protocol.rs` checks equality with both the plaintext
   query and the two-share Prio3 computation. The FLP's zero-knowledge
   property (BBCGGI19, as Prio3 uses it) covers it.
3. Partial decryptions carry OpenFHE's flooding: uniform noise over
   Q′ = Q/q₀, scaled by t. The honest phase after the **densest possible**
   query product is 75.4 bits below the flooding range
   (`openfhe-tbgv-rs/tests/linear_coeffs.rs`, measured over the product's
   own towers). So each revealed coefficient is within statistical distance
   2⁻⁷⁵ of one with no key-dependent noise.
4. The collector receives only the output coefficients of the sum.

**Robustness against malicious clients (honest aggregators).** If the
ciphertext decrypts consistently (see the next paragraph), acceptance of an
invalid input is bounded by Schwartz–Zippel on prio's padded construction
(`src/soundness.rs`, `results/soundness.md`). Per proof that is
Σ degree·(W − 1)/(p − W) with W the padded wire length, plus 1/p for
compressed outputs, raised to the power `PROOFS`; this is never below the
draft script's Σ calls·degree/(p − calls). Count with 5 proofs gives 2⁻¹⁵⁵
and BitVec(100) with 6 gives 2⁻¹⁴⁴. The query
randomness comes from a key clients never see and there is no joint
randomness, so there is no offline search; the bound is per submitted
report.

**Plaintext support (fixed).** The bound above holds for the verifier of
`z`. A client controls its whole plaintext; in a product that packs several
verifier rows, a coefficient above `z` meets the rows packed below the one
read and shifts the verifier. `tests/junk_coefficients.rs` builds a Count
report for the invalid input 2 that prio's `decide` accepts this way; the
protocol accepted it before this fix. Each aggregator now also computes
`ct × R_t` for 5 secret polynomials `R_t`, uniform on `[0, N − |z|)` and 0
above: coefficient `N − 1` of the product is `Σ_{i ≥ |z|} z_i R_t[N−1−i]`,
a uniform combination of the coefficients above `z` only (0 for honest
reports, so nothing is revealed). A nonzero coefficient above `z` passes all
five with probability `p⁻⁵ < 2⁻¹⁵⁹`, adding to the error above. The
aggregate is read off coefficients `[0, |input|)` and is not affected.

**Not proven: arbitrary (malformed) ciphertexts.** A client may submit a
ciphertext whose noise is far from honest. If the product's phase wraps
modulo Q, the decrypted verifier need not match the plaintext that the sum
accumulates. The aggregators reject any fused verifier outside the flooding
range, as `fhe-prio3` does. A wrapped value passes that check for one
coefficient with probability ≈ n·t/q₀ ≈ 2⁻¹⁴, and every coefficient of
every group must pass. This is an argument, not a proof. The same item is
open in `fhe-prio3` and in the original-encoding package.

## Measured results (this container: 4 vCPU Xeon 2.80 GHz, OpenFHE 1.3.1)

Soundness ≥ 2⁻¹²⁸ everywhere. Two aggregators. Times are per report per
aggregator. Medians and means are not mixed: `fhe-flp` reports the mean
over 16 reports, `fhe-prio3` its own simulate output, and `prio3-baseline`
the median over 30. All three were run in this session (`results/`).

| | Prio3 (prio 0.18.1) | `fhe-prio3` (depth 3, ring 32768) | **`fhe-flp`** (depth 0, ring 8192) |
|---|---|---|---|
| Count report | 80 B | 2.73 MiB | **419,856 B (410 KiB)** |
| SumVec(100, max 1) / BitVec(100) report | 2,480 B | 2.73 MiB | **419,856 B** |
| Count aggregator time | 0.004 ms | 598 ms | **90.4 ms** |
| SumVec(100) aggregator time | 0.04 ms | 919 ms | **137.9 ms** (BitVec(100)) |
| aggregator↔aggregator per report | verifier share 32 B (Count), 288 B + 32 B message (SumVec(100)) | 2.73 MiB mask + 0.87 MiB verifier | **526 B (Count), 610 B (BitVec(100))** |
| evaluation keys | none | 44 MiB (Count), 121 MiB (SumVec(100)) | **none** |
| public key | none | 5.5 MiB | 0.50 MiB |
| client time | 0.004–0.07 ms | 60–68 ms | 8.3–8.4 ms |

* Against `fhe-prio3`: reports 6.8× smaller; aggregators 6.6× (Count) and
  6.7× (SumVec(100)) faster; inter-aggregator traffic per report
  6,200–7,200× smaller; no evaluation keys.
* The 5 support checks (above) cost about 55 ms of `prepare_init` and
  14 ms of `prepare_finish` per report and 105 B of share; before them the
  aggregator times were 15.0 ms (Count) and 66.8 ms (BitVec(100)), but
  that version accepted the invalid report of `tests/junk_coefficients.rs`.
* Against the original-encoding package's binary SumVec(100) (7,405,695 B,
  single-key evaluator, a different trust model): 17.6× smaller report.
* Against Prio3: still 169× (SumVec(100)) to 5,250× (Count) larger reports
  and 3,400–22,600× slower aggregators. One RLWE ciphertext (2·N·log Q bits)
  is the floor for single-ciphertext public-key encryption. Prio3 avoids it
  because its shares are plain field elements split across non-colluding
  aggregators.

Not used, though measured or computed:
* p = 65537 would save about 8% of the report (log Q 187), but it needs
  9–16 proofs and is not one of prio's fields.
* Sending the report already switched below the 36-bit tower would save
  about 18%, at the cost of flooding margin.

## What is missing for production

* **Transport and state.** No DAP integration, persistence, batching
  policy or minimum batch size. Duplicate nonces are refused only within one
  aggregator process.
* **Key ceremony.** `key_ceremony` runs the n-of-n generation in one
  process (simulation). Real parties run `keygen_first` / `keygen_next`
  each on its own machine. The `verify_key` must be generated jointly.
  `fhe-prio3`'s CRS ceremony is not wired in.
* **Malicious aggregators.** No verifiable decryption, unlike `fhe-prio3`'s
  commitments and blinded checks. Robustness and correctness assume honest
  aggregators, as in the semi-honest model. Privacy needs one honest
  aggregator.
* **Malformed ciphertexts.** Not proven (above). Neither are side channels:
  neither prio's FLP nor OpenFHE is constant-time.
* **Review.** No independent cryptographic review.

## Reproduce

```sh
# OpenFHE 1.3.1 (as fhe-prio3/README.md), then:
cd prio3/openfhe-tbgv-rs && cargo test --release -- --test-threads=1   # incl. linear_coeffs, self-tests
cd ../fhe-flp && cargo test --release -- --test-threads=1               # incl. tests/protocol.rs, tests/junk_coefficients.rs
cargo run --release --bin soundness                                     # results/soundness.md
cargo run --release --bin measure -- count --reports 16
cargo run --release --bin measure -- bitvec --len 100 --reports 16
cd ../prio3-baseline && cargo run --release -- --reports 30
cd ../fhe-prio3 && cargo run --release --bin simulate -- --type sumvec --length 100 --max 1 --reports 4
```

## Files

* `src/protocol.rs`: task, client, aggregator, collector; query
  randomness; verifier map; query polynomial.
* `src/bitvec.rs`: the BitVec circuit and the closed-form verifier map for
  single-`Mul` circuits.
* `src/codec.rs`: canonical residue packing (wrong length, out-of-range
  residues and non-zero padding are refused).
* `src/soundness.rs`, `src/bin/soundness.rs`: soundness formulas and table.
* `src/bin/measure.rs`: end-to-end measurement.
* `tests/protocol.rs`: equality with prio's query and Prio3's combined
  verifier; rejection of invalid inputs, tampered proofs, flipped ciphertext
  bits, malformed, replayed and duplicate-party messages; refusal of
  unsupported tasks.
* `../openfhe-tbgv-rs`, all additive:
  * `Context::new_linear`, `coef_plaintext`;
  * `SecretShare::partial_decrypt_coeffs`, `Context::fuse_coeffs`;
  * `PartialDecryption::export_coeffs` / `from_coeffs`;
  * `verify_linear_rebuild_once`;
  * `tests/linear_coeffs.rs`, with the flooding-margin measurement.
* `results/`: raw measurement output, the baseline JSON, `fhe-prio3`
  simulate output, the soundness table and machine information.
