# Hardening plan: collector gating, request binding, verdict-leak evidence

Status: **plan only — nothing below is implemented yet.**
Scope: the one-aggregator protocol in `prio3/fhe-flp/src/single.rs` (evaluator +
collector holding the whole BGV key) and the shim it uses,
`prio3/openfhe-tbgv-rs`.

This is a work order. Whoever executes it (human or agent) follows the steps in
order, does not skip the reading step, and does not mark anything done without
the evidence listed under "Definition of done".

---

## 0. Ground rules (non-negotiable)

* **Real, not demo.** Every change goes into the production code paths
  (`SingleTask`, `Evaluator`, `SingleCollector`, the C++ shim) — no parallel
  "secure" copy, no feature flag that is off by default, no mock collector.
* **Real attacks, real crypto.** Every attack test runs against the real
  OpenFHE ciphertexts produced by the real protocol, with real keys and real
  noise. No simulated decryptions, no hard-coded verdicts, no assertions that
  pass because the attack code was crippled.
* **Evidence, not claims.** If an attack succeeds, the test says so and the
  docs say so. A test that *documents a working attack* is named for what it
  shows (e.g. `crafted_query_learns_input_bit`) and its assertion is the
  attacker's success rate — it is never weakened to make the suite green.
* **Nothing breaks.** Every existing test in both crates still passes; no
  existing test is deleted, skipped, `#[ignore]`d or loosened.
* **No assumptions.** Every bound (noise, batch size, probability) is either
  derived in a comment from the code it depends on or measured by a test; the
  comment says which.

---

## 1. Read the repository first

Before writing any code, read and take notes on the following. Record in the
PR/commit message what was read.

### 1.1 Whole-repository survey (what exists, where)

| Path | What it is | Read |
|---|---|---|
| `README.md` | thesis context: OpenFHE benchmarks (BGV/BFV/CKKS) | README |
| `benchmark/`, `keys/`, `linear_regression/`, `tesi/` | thesis benchmarks, key showcase, CKKS regression, thesis material | READMEs only (not touched by this work) |
| `optimization/`, `optimbgv/` | Fermat / Boolean validation studies behind the ITASEC paper (p = 65537, ring 32768) | READMEs, `START-HERE.md`; not touched |
| `prio3/README.md`, `prio3/PRIO3_VS_BGV.md` | why Prio3 cannot simply be run under FHE | in full |
| `prio3/fhe-vdaf-1*`, `fhe-vdaf-2`, `fhe-prio3*`, `fhe-paper-core`, `openfhe-bgv-rs`, `prio3-baseline` | earlier prototypes, threshold work, Prio3 baseline | READMEs; not touched |
| `prio3/openfhe-tbgv-rs/` | C++ shim + Rust bindings used by `fhe-flp` | **in full** (see 1.2) |
| `prio3/fhe-flp/` | the crate this plan changes | **in full** (see 1.2) |

### 1.2 Files to read in full (they are changed or relied on)

* `prio3/fhe-flp/src/single.rs` — evaluator, collector, `finish()` (flood
  then mod-switch), `check_request`, `check_with_verifiers`,
  `aggregate_request`, `unshard`.
* `prio3/fhe-flp/src/protocol.rs` — `FlpPlan` (query randomness from the
  evaluator's `verify_key`, `linear_map`, `query_poly`, `decide`,
  `max_batch`), `NONCE_LEN`.
* `prio3/fhe-flp/ONE-AGGREGATOR.md`, `DESIGN.md` — current trust model and
  the "Not done" list (semi-honest evaluator; unit-vector query).
* `prio3/fhe-flp/tests/*.rs` — especially `junk_coefficients.rs`
  (style of an attack test that proves `decide` would accept).
* `prio3/openfhe-tbgv-rs/wrapper/tbgv.cpp`:
  `tbgv_context_new_single`, `tbgv_ciphertext_flood`,
  `tbgv_ciphertext_mod_reduce`, `tbgv_decrypt_coeffs`,
  `tbgv_ciphertext_from_residues` / rebuild path.
* `prio3/openfhe-tbgv-rs/tests/single_key.rs` — how the worst-case
  flooding margin (λ = 67.9 bits at p = 65537, 86.7 at FieldPrio2) was
  measured.

Facts already established from that reading (verify they still hold):

1. `finish()` floods with width `w = floor(log2 Q) − ceil(log2 t) − 2`, i.e.
   adds `t·(e − 2^(w−1))`, `e` uniform in `[0, 2^w)`, to `c0`, then
   mod-switches to **one tower**. The collector therefore only ever decrypts
   **one-tower, two-element** ciphertexts (`reduced_meta`).
2. The collector decrypts with OpenFHE `Decrypt` (`tbgv_decrypt_coeffs`); it
   performs **no check of the ciphertext's noise/phase** before using the
   result.
3. The check request is `u32 count || per report: groups·ct || parts·ct`.
   It carries **no batch identifier, no report digests, no task binding**.
4. The collector keeps only `accepted: Option<u64>`; `unshard` accepts any
   aggregate request whose count equals it — any number of times.
5. The evaluator chooses the query polynomial `Q~` (its own `verify_key`);
   the collector cannot check it. The evaluator **learns one verdict bit per
   checked entry**.

---

## 2. Work items

### W1 — Collector noise check with gating ("verify before trusting a decryption")

**Why** (see §6.1). IND-CPA-D attacks recover BGV/BFV secret keys from observable
decryption outcomes of crafted ciphertexts (Cheon et al., ePrint 2024/127;
Stehlé's talk shows key recovery on OpenFHE BFV with p = 2^16+1 using
additions only; Choe–Kang–Stehlé, ePrint 2026/2546). Our collector's verdict
bits and aggregate are such outcomes.

**What to build.**

1. Shim function `tbgv_phase_inf_norm(ctx, sk, ct, out_max, out_q)`:
   for a **one-tower, two-element** ciphertext compute `c0 + c1·s mod q0`
   in coefficient form, centre each coefficient in `(−q0/2, q0/2]`, return the
   maximum absolute value and `q0`. Refuse any other shape (multi-tower,
   three-element, wrong encoding) with an error — never "best effort".
2. A **derived honest bound `B`**, written next to the code: the largest
   centred phase an honestly produced, flooded and mod-switched ciphertext
   can have — from `w`, `t`, the tower being dropped, OpenFHE's BGV
   `ModReduce` rounding (with the ternary secret, ring `N`), and the honest
   pre-flood noise bound measured in `single_key.rs`. Add a test that
   produces the densest honest products of every task and asserts
   `phase ≤ B` with the measured slack printed.
3. **Gating in the collector.** Before *any* decrypted value is used:
   structural checks (length, metadata, canonical residues — already
   present), then `phase ≤ B` for **every** ciphertext in the request. Only
   if all pass are values decrypted and `decide` run.
4. **The gate's own outcome must not become an oracle.** A failing gate
   depends on the secret key too. Therefore a gate failure:
   * rejects the **whole request** (never a per-report verdict),
   * puts the collector into a permanent `Revoked` state for this key
     (every later call errors), and
   * is reported as an incident.
   Leakage is then bounded by "which request first tripped the gate" — at
   most `log2(#requests)` bits per key lifetime. Document this bound.
5. **Width trade-off.** With `w` as today the honest phase can reach about
   `q0/4`, so a wrapped malicious ciphertext lands under `B` with
   probability ≈ 1/2. Evaluate reducing `w` by `k` bits (detection
   ≈ `1 − 2^−(k+1)`, statistical hiding drops from λ to λ − k). Pick `k` so
   λ − k ≥ 64 at both fields; record the choice and the numbers.

### W2 — Binding to report hashes, batch ID and task

**Why** (see §6.2): Flamingo's cross-round decryption attack and Lighthouse's
decryption-policy and selective-opening lessons.

**What to build.**

* `BatchId` (32 random bytes chosen by the evaluator per batch) and a
  `task_binding = SHA-256(task_id ‖ field ‖ type params ‖ num_proofs ‖ ring ‖ moduli)`.
* Check request = `version ‖ task_binding ‖ batch_id ‖ count ‖ per report:
  report_digest (SHA-256 of the report's ciphertext bytes, nonce excluded) ‖ ciphertexts`.
* Collector state (persisted interface: a trait the deployment backs with
  storage; the in-memory implementation is the default for tests):
  * refuses a wrong `task_binding` or version;
  * refuses a `batch_id` it has already checked;
  * refuses a `report_digest` seen in **any** earlier batch, or twice in one;
  * records `(batch_id → accepted digests, verdict hash, count)`.
* Aggregate request = `batch_id ‖ verdict_hash ‖ count ‖ ciphertext`.
  Collector refuses: unknown batch, wrong verdict hash or count, a second
  aggregate for the same batch, and a count below a task **minimum batch
  size** (new task parameter, as in DAP).
* Evaluator dedupes reports by ciphertext digest (not only nonce).

**What W2 does not stop (write it down):** a malicious evaluator inventing
fresh reports (Sybils), choosing its own query `Q~`, or omitting accepted
reports from the sum. Those need verification of the evaluator's linear work
(future work; see §5).

### W3 — Evidence test for the verdict leak

**Why** (see §6.3): HERE's reaction / one-bit-forge attack and Lasagne's
stated one-bit leakage when the prover learns acceptance.

Two real attacks, run end to end against the real collector:

* **W3a — crafted query (strongest).** For a real client Count report, the
  evaluator builds a check entry whose "verifier" coefficients are
  `(x, 0, 0, 0)` (a unit-vector query on the input coefficient, constants 0)
  instead of `Q~·z`. Prio3's `decide` accepts iff `x = 0`. The evaluator
  learns `x` from the verdict bit.
* **W3b — derived report.** The evaluator re-encrypts / shifts a client's
  ciphertext (`ct + Enc(Δ)`, fresh nonce) and submits it as a new report
  with honestly computed queries, to learn validity of a modified input.

Each test reports the attacker's success rate over ≥ 100 independent client
reports and asserts the **observed** rate. Expected (to be confirmed, not
assumed): W3a succeeds 100% under today's trust model; W3b is blocked for
Count by the FLP unless the proof is also adjusted. The docs
(`ONE-AGGREGATOR.md`, "Not done") are updated with the measured result.

---

## 3. Attacks to run as tests

### 3.1 Five technical attacks (protocol / cryptographic)

| # | Attack | How (real) | Expected defence | Pass criterion |
|---|---|---|---|---|
| T1 | **Crafted-query verdict oracle** (W3a) | evaluator replaces `Q~` by a unit-vector query on `x` | none today (semi-honest assumption) | test measures and asserts the real leak rate; docs updated |
| T2 | **IND-CPA-D noise amplification** | evaluator doubles an honest reduced ciphertext `k` times (additions only) until its phase passes `B`, submits it in a check request | W1 gate | request rejected as a whole, collector `Revoked`, no verdict returned |
| T3 | **Replay** | resubmit a previous check request, or one report's ciphertext under a new nonce in a later batch | W2 | refused: duplicate `batch_id` / duplicate `report_digest` |
| T4 | **Aggregate mismatch / double aggregate** | aggregate request for an unknown batch, with a wrong count or verdict hash, or a second aggregate for the same batch | W2 | each refused; the first valid aggregate still decodes correctly |
| T5 | **Malformed ciphertext shapes** | 3-element ciphertext, extra tower, non-canonical residue, truncated bytes, coefficients outside the support | existing codec + metadata checks + support check + W1 | refused **before** any decryption result is used |

### 3.2 Five human / operational attacks

| # | Attack | Scenario | Expected defence | Pass criterion |
|---|---|---|---|---|
| H1 | **Ballot stuffing** | a client (or a script) submits the same report twice, or copies another client's report | evaluator digest dedupe + collector cross-batch digest set | second copy refused; aggregate counts it once |
| H2 | **Retry after a crash** | operator re-runs the collector on the same check request "to be safe" | W2 batch registry | second run refused, no new verdicts produced |
| H3 | **Differencing by a curious insider** | evaluator operator asks for two aggregates of the same batch (with and without a target), or two overlapping batches | one aggregate per batch; digest seen once ever; minimum batch size | second aggregate and the overlapping report refused; small batches refused |
| H4 | **Misconfiguration** | evaluator and collector run different task parameters (proofs, field, task id) | `task_binding` | refused with a clear error, not silently wrong verdicts |
| H5 | **Tiny batch to single out a person** | operator closes a batch with one real report plus self-made reports | minimum batch size stops the naive case; Sybil reports are **not** stopped | test shows the naive case refused and documents the Sybil limitation honestly |

---

## 4. Things NOT to do

* Do not mock the collector, the shim or OpenFHE in any test.
* Do not compute the noise bound from OpenFHE's heuristic estimates; derive
  it (worst case) and test it.
* Do not return per-report "gate failed" information — that is the oracle.
* Do not keep using a key after the gate trips.
* Do not trust the evaluator's own `count` or its notion of which reports
  were accepted; compare against the collector's records.
* Do not decrypt before the structural and phase checks pass.
* Do not dedupe by nonce alone (nonces are client-chosen and free).
* Do not claim W2 stops Sybils, query manipulation or omissions — it does not.
* Do not weaken, skip or delete an existing test; do not `#[ignore]` a slow
  one to make the suite pass.
* Do not change Prio3 encodings, prio's FLP, p = 65537 / FieldPrio2, or the
  one-aggregator architecture.
* Do not add "secure" options that default to off.
* Do not use `unwrap()` on attacker-controlled input in library code; every
  refusal is an `Error` with a specific message.
* Do not persist or log secret keys, decrypted verifiers or masks.
* Do not report a number (bound, rate, size) that a test did not produce.
* Do not commit without `cargo fmt`, `cargo clippy --all-targets` (no
  warnings) and both crates' full test suites passing.

---

## 5. Out of scope (recorded as future work, not silently ignored)

Tools for each item are summarised in §6.5.

* Verifying the evaluator's linear work (Freivalds-style checks from HERE,
  ePrint 2026/2422; randomness recomputation as in FOVA, ePrint 2026/643)
  — needed to stop T1, Sybils and omissions.
* Verdict-oblivious aggregation (collector returns encrypted verdict bits)
  — removes the per-report verdict oracle entirely.
* Client well-formedness proofs (LZKSA-style lattice ZK, CCS 2025).
* Selective-opening-aware security proof (Lighthouse, ePrint 2026/346).

---

## 6. Knowledge from the literature and how to apply it

What each paper teaches that changes *how* W1–W3 are built. "Read" says how
much of the paper was actually read for this plan; nothing here is taken
from a paper that was not opened, except where marked *abstract only*.

### 6.1 Applied in W1 (noise check and gating)

* **Cheon, Choe, Passelègue, Stehlé, Suvanto — IND-CPA-D attacks on exact FHE**
  (ePrint 2024/127, CCS'24; read: Stehlé's NewTPQC 2024 talk in full).
  * Exact schemes (BGV/BFV, TFHE) are *not* automatically CPA-D secure:
    the equivalence to IND-CPA needs **negligible decryption failure**;
    libraries run at 2^-15 … 2^-50 with **heuristic** noise analysis.
  * Concrete attack on **OpenFHE BFV, N = 2^12, p = 2^16 + 1, q = 2^60**:
    start from Enc(0), repeat `x ← x + x` 44 times. OpenFHE bounded the
    noise as growing linearly in the number of additions while it doubles,
    so decryption failed and the **secret key was recovered instantly,
    with additions only**.
  * Countermeasures they give: tiny failure probability, **no heuristic
    noise analysis** (worst-case bounds), and diligence in KeyGen, Enc,
    Eval *and* Dec.
  * → W1: derive `B` from worst-case bounds of our own code path (never
    from OpenFHE's estimates); T2 reproduces the doubling attack against
    our collector; the gate must fire before the decryption result is used.
* **Choe, Kang, Stehlé — New IND-CPA-D attacks on BFV and BGV**
  (ePrint 2026/2546; *abstract only* — paper not yet read).
  * Bootstrapping-failure, **noise-skewing** (crafted plaintexts make
    plaintext×ciphertext products outgrow heuristic bounds) and
    mask-skewing attacks; noise-skewing recovers OpenFHE keys in minutes to
    hours; flooding sized by average-case noise estimates is breakable from
    one decryption output.
  * → W1: our evaluator performs plaintext×ciphertext products with
    attacker-influenced plaintexts in the threat model, so `B` must bound
    the **worst-case** product noise; read this paper before fixing `B`.
* **Viand, Knabenhans, Hithnawi — Verifiable FHE** (arXiv 2301.07041;
  read: abstract, §3.4 key recovery, §5 instantiations, Table 2).
  * A malicious server turns *any client reaction* into a (partial)
    decryption oracle; with an oracle it can decrypt evaluation keys
    (e.g. BGV relinearisation key = Enc(s²)) and recover `s`.
  * Their "Small" workload `NoiseFlood(x·v + w)` is exactly our per-report
    check (plaintext product + plaintext addition + flooding). Proving it
    with generic ZK at N = 8192, log q = 137 costs **minutes** (Groth16,
    Rinocchio) to **hours** (Bulletproofs, Aurora) per proof; TEE ~0.15 s.
  * → W1: keep the collector key free of evaluation keys (we already have
    none); generic SNARK verification is not a per-report option.
* **Ahmed, Gouert, Tsoutsos — PEEV** (ePrint 2026/1871; read: intro, §4,
  results, conclusion).
  * **Atomic verification and decryption gating**: verify *before*
    decrypting; on failure abort and purge the ciphertext "to prevent
    reaction side-channels". Rinocchio + SEAL BGV; sum of squares over 16
    values ≈ 1.7 s.
  * → W1 step 3–4: ordering (structural checks → phase gate → decrypt →
    decide) and "purge + revoke" on failure.

### 6.2 Applied in W2 (binding)

* **Flamingo** (S&P'23, arXiv 2308.09883; read: §4.4–4.5).
  * Attack: a malicious server asks decryptors to decrypt a client's
    pairwise mask in round t and its individual mask in round t′ and
    recovers the input. Fix: clients **sign (ciphertext, round)**,
    decryptors check the round and **sign the labels**; a cross-check makes
    decryptors agree.
  * → W2: every collector action is bound to `(task_binding, batch_id,
    report_digest)`; a digest is decryptable in exactly one batch.
* **Garg, Kavousi, Kolonelos, Tairi, Wang — Lighthouse** (ePrint 2026/346;
  read: abstract, intro, §1.2 overview, threat discussion).
  * The decrypting committee never sees what it decrypts, so it uses
    **one-of-two** decryption plus a **SNARK proving the request satisfies
    the policy**.
  * A server that decides *after* seeing ciphertexts which ones get opened
    needs **selective-opening** security; Flamingo's and TACITA's proofs
    missed this.
  * → W2: the collector's registry is the policy (one batch, one aggregate,
    digests once); → §5: any security proof must be selective-opening aware.

### 6.3 Applied in W3 (verdict-leak evidence)

* **Kang, Pohle, Spiessens — HERE** (ePrint 2026/2422; read: abstract,
  intro, technical overview).
  * Names the problem: **reaction attacks**; the *one-bit forge attack*
    replaces Enc(b) by Enc(0) and learns b from accept/reject; low-entropy
    inputs (unit vectors, bits) leak completely.
  * Their fix (random encodings: Shamir shares at d+1 points under d+1
    keys, IND-CPA-E) protects **equality-type** reactions in single-client
    delegation; our verdict is a **validity predicate on client data**, and
    additive shifts pass through Shamir sharing — so it does not close our
    leak as is (our analysis; to be confirmed).
  * → W3: test exactly the one-bit-forge shape (W3a/W3b) on Count, whose
    input is one bit.
* **Zhang et al. — Lasagne** (ePrint 2026/857; read: abstract, intro,
  §3 definitions, limitations).
  * FHE-SNARK ("blind proof") VCoED; 4–12 min for a 2^20-gate circuit,
    27 s for a 2-layer face-matching circuit.
  * States the limitation outright: if the prover learns whether its proof
    was accepted it learns 1 bit; "the client must prevent the server from
    learning whether the proof is acceptable".
  * → W3: our evaluator learns every verdict by design — W3 measures what
    that costs; §5 records verdict-oblivious aggregation as the fix.

### 6.4 What NOT to build (from the literature)

* **Cheon, Jang — Cryptanalysis on lightweight verifiable HE**
  (Asiacrypt'25, arXiv 2502.12628; read: abstract, intro, attack summaries,
  conclusion).
  * REP and PE (Veritas, CCS'24) and vADDG are **broken**: probability-1
    forgeries in O(log t) (Euler/equality-test circuits); vADDG's 80-bit
    parameters give ≈10 bits.
  * Limiting the server's depth is *not* a proven defence ("requires more
    thorough analysis"; noise-overflow tricks may still work).
  * → Do not use hidden-secret plaintext encodings (REP/PE style) for
    verification. If a future design relies on the evaluator being
    linear-only (no evaluation keys, two-element ciphertexts enforced), it
    needs its own proof.
* **Chatel et al. — Veritas** (arXiv 2207.14071; read: abstract, threat
  model). Its model **excludes decryption oracles** and assumes **trusted
  clients** — both false here.

### 6.5 Inputs for §5 (future work) — tools that exist

* **HERE's vCOED_MVI** random linear (Freivalds) check: verifier keeps
  `(r, s = r·A)`, checks `s·c_u = r·c_v`; ≈2× the cost of one
  plaintext-matrix × ciphertext-vector product. Candidate for verifying the
  evaluator's `Q~·z` products.
* **Zhu, Gong, Zhang, Gueron, Qian — FOVA** (ePrint 2026/643; read:
  abstract, intro, §3 construction, conclusion, Appendix A).
  * Verifiable *linearly* homomorphic encryption from Paillier: the
    verifier recomputes the aggregate from the clients' **encryption
    randomness** (`Y′ = (1+N)^y · Π r_i^N`) and compares; detects forgery
    and omission above a threshold; needs a **trusted dealer**; not
    post-quantum; input validation only via Paillier range proofs to an
    extra semi-honest verifier.
  * RLWE encryption is also linear in its randomness → a lattice analogue
    is plausible (not verified).
* **Lu, Lu — LZKSA** (CCS'25, ePrint 2025/1141; read: abstract, intro,
  contributions, conclusion). Seven RLWE-based ZK protocols: correct key
  use, L∞/L2/cosine bounds; prover ≤ 0.15 s per client (CIFAR-10); built
  on masking-based SecAgg (Bell et al.); malicious server listed as future
  work. → candidate for client well-formedness proofs.
* **Azimi, Pilaram, Mohajeri — PQ-DVSA** (ePrint 2026/2394; read: abstract,
  intro). RLWE masking, clients verify the server's aggregation result
  under bounded collusion, dropout resilient, trusted authority, **no input
  validation**.
* **Perez et al. (FBK Trento) — SecAgg++** (ePrint 2026/2497; read:
  abstract, intro). ML-KEM-based masking, honest-but-curious server,
  multi-round, no validation.
* **Fiore, Nitulescu, Pointcheval — FNP20** (PKC'20, ePrint 2020/132; read:
  abstract, intro). SNARK over quotient polynomial rings for VC on
  RLWE-encrypted data; publicly verifiable; **bilinear groups — not
  post-quantum**.
* **Acharya et al. — PEAR** (PoPETs 2025; read in full earlier). Single
  server + analyst, FL-PCP + inner-product FE; private against a
  malicious server; class groups (not post-quantum); the FHE baseline
  verifies the FL-PCP under BFV and filters by Fermat exponentiation,
  20–100× slower than PEAR.

### 6.6 Additional "do not" items derived from the literature

* Do not size flooding or the gate from average-case noise estimates
  (2026/2546, abstract).
* Do not assume decryption failures are harmless "because the scheme is
  exact" (2024/127).
* Do not let the evaluator obtain evaluation keys of the collector's key
  (Viand et al.: Enc(s²) is decryptable with an oracle).
* Do not rely on depth limits alone as a security argument (Cheon–Jang).
* Do not reveal acceptance/rejection per report to a party that can
  craft inputs, unless the leak is measured and documented (HERE, Lasagne).

---

## 7. Definition of done

1. §1 reading recorded in the commit message.
2. W1, W2 implemented in the production paths; W3 tests added.
3. All ten attacks of §3 exist as tests, each with a doc comment stating the
   scenario, the expected result and the observed result.
4. `cargo fmt --check`, `cargo clippy --release --all-targets` (zero
   warnings) and `cargo test --release -- --test-threads=1` pass in
   **both** `prio3/openfhe-tbgv-rs` and `prio3/fhe-flp`; test counts before
   and after are recorded (none removed).
5. `ONE-AGGREGATOR.md` updated: new message formats, the gate and its
   leakage bound, the binding guarantees and their limits, the measured
   W3 results.
6. Measurements re-run (`measure_single` for every task, both fields) and
   `results/` updated, so sizes in the docs match the new formats.
7. Committed and pushed to `janak/fhe-prio3`.
