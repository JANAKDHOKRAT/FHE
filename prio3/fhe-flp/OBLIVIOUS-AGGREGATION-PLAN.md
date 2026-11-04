# Plan: verdict-oblivious aggregation, and its measured cost

Status: **plan only — nothing below is implemented yet.**
Companion to [`HARDENING-PLAN.md`](HARDENING-PLAN.md) (W1 noise gate, W2
binding, W3 verdict-leak evidence). Same ground rules, same reading step.

**Goal.** In the one-aggregator protocol (`src/single.rs`) the evaluator
currently receives one accept/reject bit per report and sums the accepted
reports itself. That bit is a *reaction oracle* (HERE, Lasagne): a
malicious evaluator that crafts check entries learns one bit about a
client's input per entry (attack W3a in the hardening plan). This plan
removes the per-report verdict from everything the evaluator sees, keeps
Prio3's encodings, prio's FLP, p = 65537 / FieldPrio2 and the
one-aggregator architecture unchanged, and **measures what that costs**.

---

## 0. Ground rules (non-negotiable)

* **Real, not demo.** The verdict-oblivious flow *replaces* the
  verdict-revealing flow in the production API. The old flow survives only
  as a clearly named measurement baseline (or is measured from the
  previous commit), never as a selectable "fast mode".
* **Real crypto in every test** — real OpenFHE ciphertexts, real keys,
  real noise, no mocks, no simulated decryptions, no hard-coded verdicts.
* **Evidence, not claims.** Every privacy claim below has a test that
  would fail if the claim were false; every cost number comes from a
  measurement run committed to `results/`.
* **Nothing breaks.** All existing tests in `prio3/openfhe-tbgv-rs` and
  `prio3/fhe-flp` keep passing; none is deleted, skipped, `#[ignore]`d or
  loosened. Tests whose message formats change are migrated, not dropped.
* **No assumptions.** Every bound and capacity (packing, noise, batch
  size) is derived in a comment from the code it depends on, or measured.

---

## 1. Read first

1. Everything listed in `HARDENING-PLAN.md` §1 (repository survey and the
   files to read in full).
2. In addition, in full:
   * `src/single.rs`: `AggMap` / `agg_map` (Select vs Convolution
     outputs), `support()`, `pad()`, `mask()`, `finish()`,
     `check_request`, `check_with_verifiers`, `aggregate_request`,
     `unshard`;
   * `src/protocol.rs`: `query_poly` (the negacyclic sign rule used again
     below), `max_batch`, `output_map`;
   * `tests/single_variants.rs`, `tests/junk_coefficients.rs`;
   * `results/measure-single-variants.jsonl` and `ONE-AGGREGATOR.md`
     tables (the baseline to compare against).

Facts to confirm while reading (they drive the design):

* The collector already decrypts, per report, a **support-check
  ciphertext**: the report ciphertext plus a fresh uniform pad on its
  honest support, flooded and switched to one tower.
* For **Select** tasks (Count, BitVec, Histogram, MultihotCountVec) the
  outputs are input coefficients; for **Convolution** tasks (Sum, SumVec)
  outputs are weighted sums `W·x` and the per-bit sums must **not** be
  revealed (Prio3 reveals only the weighted totals).
* A report that fails the support check may hold arbitrary values in
  every coefficient.

---

## 2. Design

### 2.1 Chosen design: masked reveal with encrypted verdict weights

Notation: report `i` has input `x_i`; `o_i = W(x_i)` is its output vector
(length `L = output_len`; `W` is prio's linear `truncate`); `v_i ∈ {0,1}`
its verdict; `p` the plaintext modulus. Goal: the collector obtains
`S = Σ_i v_i·o_i` and nothing else beyond what it learns today; the
evaluator obtains no function of any `v_i`.

1. **Check request (evaluator → collector)**, per report, as today, plus a
   *masked output* `y_i = o_i + r_i` with `r_i` fresh, uniform in
   `F_p^L`, known only to the evaluator:
   * **Select tasks: free.** Use the support-check pad's values on the
     output coefficients as `r_i`; the collector decrypts those
     coefficients of the support-check ciphertext it already receives.
     The evaluator must keep `r_i`.
   * **Convolution tasks:** one more reduced ciphertext per report:
     `ct_i × W + mask` (mask: `r_i` on the output coefficients, fresh
     uniform elsewhere), flooded, switched to one tower.
   * **No packing of several reports into one ciphertext.** A rejected
     report can hold arbitrary values in every coefficient; packed
     neighbours would absorb them into their `y_j`. Every `y_i` comes from
     a ciphertext that contains report `i` only.
2. **Collector:** gate (W1), decide verdicts as today, compute
   `T = Σ v_i·y_i` in the clear, **send no verdict bits**. Instead send
   `E(V)`: fresh encryptions under its public key of
   `V = Σ_i v_i·X^(i·L)` — `⌈n·L / N⌉` ciphertexts (packing `N / L`
   verdicts per ciphertext).
3. **Evaluator:** for each verdict ciphertext, one plaintext product
   `E(V)·P` with `P[(c − i·L) mod N] = ± r_i[c]` (the negacyclic sign rule
   of `query_poly`: negative index → `N + index`, value negated), so that
   coefficient `c < L` of the product is `Σ_i v_i·r_i[c]`. Sum the
   products, put fresh uniform masks on every coefficient except
   `[0, L)`, flood, switch to one tower → `E(U)` with `U = Σ v_i·r_i`.
   Send `E(U)` (this replaces today's aggregate request).
4. **Collector:** gate (W1), decrypt coefficients `[0, L)` of `E(U)`,
   output `S = T − U`, decode with prio's `decode_result` using its own
   accepted count.

Depth: every evaluator operation is plaintext×ciphertext or addition — no
ciphertext×ciphertext product, **no evaluation keys**, same modulus chain,
**client reports unchanged**.

Why it is private (to be written as a proof sketch in the code docs and
checked by tests):
* evaluator's view: report ciphertexts and `E(V)` — RLWE ciphertexts
  under the collector's key; it never receives a decryption, a verdict,
  the accepted count or `S`;
* collector's view: verifier messages (as today), `y_i = o_i + r_i` (one
  -time padded; for Convolution tasks only output-domain values, never
  per-bit sums), and `U`, which equals `Σ v_i y_i − S` — determined by
  what it already holds and the output it is entitled to.

### 2.2 Rejected alternative (record it, with the reason)

**Encrypted verdict multiplier:** collector returns `E(v_i)` per report;
evaluator computes `Σ ct_i ⊗ E(v_i)` (three-element ciphertexts, decrypted
with `(1, s, s²)`, no relinearisation key). Rejected because it needs a
ciphertext×ciphertext product (an extra modulus tower: larger **client**
reports), one fresh ciphertext per report from the collector, and breaks
the "depth 0" property. If time allows, measure it once for comparison;
do not ship it.

### 2.3 What this does not fix (write it down)

* A malicious evaluator can still compute a wrong `E(U)`, omit reports,
  insert self-made (Sybil) reports, or use a crafted query so that the
  **collector** decrypts something other than a verifier. Those need
  verification of the evaluator's linear work (HARDENING-PLAN §5).
* If the final aggregate `S` is ever shown to the evaluator, differencing
  through `S` (omitting or isolating a target) is possible again. `S` is
  the collector's output only; the API must not return it to the evaluator.

---

## 3. Cost measurement

Measure **both** the current (verdict-revealing) protocol and the new one
**in the same session, on the same machine, from the same build flags**
(baseline from the previous commit via `git worktree`, or a clearly named
baseline module). Record `results/machine.txt`.

* Tasks: Count, BitVec(10, 100), Sum(100), SumVec(10, max 3),
  SumVec(100, max 1), Histogram(100), MultihotCountVec(100, w 10).
* Fields: p = 65537 and FieldPrio2.
* Batch sizes: n = 16, 256 and 1024 where `max_batch` allows (Sum(100) at
  p = 65537 allows 655).
* Per run, record (JSON lines, `results/measure-oblivious.jsonl`):
  * bytes: report; evaluator→collector check request (per report and
    total); collector→evaluator message (`E(V)` total, vs verdict bitmap
    today); evaluator→collector final message (`E(U)`, vs aggregate
    request today);
  * time: evaluator check request; collector check (incl. gate);
    collector `E(V)` encryption; evaluator `E(U)`; collector final
    decryption and decode; end-to-end per batch;
  * correctness: decoded aggregate equals the plaintext sum of the valid
    measurements (asserted, not just printed).
* Report a table in `ONE-AGGREGATOR.md`: absolute numbers and the
  oblivious/baseline ratio per column, with the expected shape stated
  *before* running (Select tasks: ≈ +0 bytes per report, +`⌈nL/N⌉` fresh
  ciphertexts per batch; Convolution tasks: +1 reduced ciphertext per
  report) and the measured result next to it. If they disagree, explain.

---

## 4. Attacks to run as tests

### 4.1 Five technical attacks

| # | Attack | How (real) | Expected | Pass criterion |
|---|---|---|---|---|
| T1 | **Crafted-query verdict oracle** (HARDENING W3a) re-run | evaluator inserts a unit-vector check entry on a client's `x` | evaluator receives no verdict | test asserts the evaluator's received messages carry no verdict field and the W3a attacker's guess accuracy over ≥ 100 real reports is consistent with chance (report the observed rate and a binomial bound) |
| T2 | **Length / count side channel** | compare collector→evaluator messages for batches with different numbers of accepted reports | message size and structure depend only on `n` and the task | byte-for-byte length equality across verdict patterns; no count field |
| T3 | **Poisoned rejected report** | a malicious client report with large values in every coefficient (fails support check) inside a batch of valid reports | `v = 0` removes it; no packing means no spill-over | decoded aggregate equals the sum of the valid reports exactly |
| T4 | **Reflecting `E(V)`** | evaluator feeds a received `E(V)` ciphertext back as a report or inside a check entry | W2 digests and the W1 gate; collector never decrypts it as a report | refused, or decrypted only into a value the collector discards; no verdict reaches the evaluator |
| T5 | **IND-CPA-D on `E(U)`** | evaluator amplifies `E(U)` by repeated doubling before sending | W1 gate | request rejected as a whole, collector revoked, no output |

### 4.2 Five human / operational attacks

| # | Attack | Scenario | Expected | Pass criterion |
|---|---|---|---|---|
| H1 | **Curious collector operator** | reads `y_i` hoping to see individual values | `y_i` one-time padded | test: over many real reports with fixed `x`, the decrypted `y_i` values pass a uniformity test and differ between runs; mask reuse is detected by an assertion in debug builds |
| H2 | **Result shared with the evaluator** | an operator wires `S` back to the evaluator service | API gives `S` only to the collector | the evaluator type has no method that returns `S`; documented |
| H3 | **Out-of-order / retry** | operator sends `E(U)` before the check, twice, or for another batch | collector state machine | each refused; the first valid run still decodes correctly |
| H4 | **Mismatched layout** | evaluator built with another task (other `L`, other output map) | task binding (W2) | refused with a clear error |
| H5 | **Batch larger than the packing / field allows** | `n` above `max_batch`, or `n·L` needing more `E(V)` ciphertexts than declared | refused before any decryption | refused; no wrap-around modulo p |

---

## 5. Things NOT to do

* Do not send verdict bits, an accepted count, or `S` to the evaluator.
* Do not let the collector→evaluator message size depend on the verdicts.
* Do not reuse a mask `r_i` across reports or batches; draw it from
  `OsRng` through the XOF, per report.
* Do not pack several reports into one `y` ciphertext (T3).
* Do not reveal input-domain (per-bit) sums for Sum/SumVec; mask in the
  output domain.
* Do not encrypt `V` deterministically or reuse `E(V)` ciphertexts.
* Do not give the evaluator evaluation keys; the design is depth 0.
* Do not skip masking of the non-output coefficients of `E(U)` (they hold
  other linear combinations of the `r_i`, which would leak `x` to the
  collector).
* Do not skip flooding or the W1 gate on any new ciphertext.
* Do not claim protection against omission, Sybil reports, wrong `E(U)` or
  crafted queries that make the collector decrypt non-verifiers (§2.3).
* Do not compare costs measured on different machines or builds.
* Do not change Prio3 encodings, prio's FLP, the fields, or the
  one-aggregator architecture.
* Do not commit without `cargo fmt --check`, `cargo clippy --release
  --all-targets` (zero warnings) and both crates' full test suites.

---

## 6. Knowledge from the literature and how it applies

(Details and how much of each paper was read: `HARDENING-PLAN.md` §6.)

* **HERE** (ePrint 2026/2422): the one-bit-forge reaction attack is
  exactly what per-report verdicts enable; HERE's random-encoding fix
  targets equality reactions in single-client delegation and does not
  cover a validity predicate on client data — hence this design removes
  the verdict from the evaluator's view instead.
* **Lasagne** (ePrint 2026/857): "the client must prevent the server from
  learning whether the proof is acceptable" — the requirement this plan
  implements for the evaluator.
* **PEAR** (PoPETs 2025): its server discards invalid reports itself, so it
  learns validity bits; Prio3's aggregators learn them too. After this
  change our evaluator learns *less* than either — state this, with the
  caveats of §2.3.
* **Viand et al.** (arXiv 2301.07041): never hand the evaluator evaluation
  keys (Enc(s²) is decryptable with an oracle) — the chosen design needs
  none; the rejected alternative avoids relinearisation keys for the
  same reason.
* **IND-CPA-D attacks** (2024/127; 2026/2546 abstract): the collector now
  decrypts more objects (`y_i`, `E(U)`); every one goes through the W1
  gate with worst-case bounds.
* **PEEV** (2026/1871): verify-then-decrypt ordering and purge on failure
  apply to the new messages.
* **Lighthouse** (2026/346): the evaluator no longer decides which reports
  are opened (the collector's verdicts select them under encryption), which
  removes the evaluator-side selective-opening choice; the proof sketch
  must still cover the collector's adaptive decryptions.
* **FOVA** (2026/643): masking-and-unmasking with randomness known to one
  side is the same pattern as `T − U`; FOVA also shows how a verifier could
  later check the evaluator's `E(U)` from randomness (future work, §2.3).

---

## 7. Definition of done

1. §1 reading recorded in the commit message.
2. Design §2.1 implemented in `src/single.rs` (and any shim support), the
   verdict-revealing flow removed from the production API.
3. All ten attacks of §4 exist as tests with doc comments: scenario,
   expected result, observed result.
4. Every existing test still passes (migrated where formats changed);
   counts before/after recorded.
5. `cargo fmt --check`, `cargo clippy --release --all-targets` (zero
   warnings), `cargo test --release -- --test-threads=1` pass in both
   crates.
6. §3 measurements committed (`results/measure-oblivious.jsonl`,
   `results/machine.txt`) and the comparison table in `ONE-AGGREGATOR.md`
   filled from them.
7. `ONE-AGGREGATOR.md` "What each party learns" and "Not done" updated.
8. Committed and pushed to `janak/fhe-prio3`.
