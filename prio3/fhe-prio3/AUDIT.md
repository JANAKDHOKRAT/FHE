# FHE-Prio3: internal adversarial audit and external audit package

**This is not an external audit.** The authors of the code wrote it, attacking
their own design. It has two purposes: to record what the internal review
found and what was done about it, and to give an independent auditor a
starting point (scope, invariants, the riskiest code, how to reproduce every
claim). An independent review by people who did not write the code is still
required before this protects real users' data.

The security claims, assumptions and proof sketches are in `SECURITY.md`.
The protocol is specified in `FHE_PRIO3_SPEC.md`.

## 1. Scope and trusted base

| Component | Language | Role | Risk |
|---|---|---|---|
| OpenFHE 1.3.1 | C++ | BGV-RNS, threshold decryption, noise flooding | Trusted (A6). Pinned: `openfhe-tbgv-rs/build.rs` refuses other versions, and a start-up self-test (`openfhe-tbgv-rs/src/selftest.rs`) checks exact rebuild of every exchanged object. |
| `openfhe-tbgv-rs/wrapper/tbgv.cpp` | C++ | FFI shim: ceremony steps, packed residues, `mult_monomial`, `zero_encryption`, `monomial_slots`, `fuse_magnitude` | **Highest**: memory-unsafe, reviewed only by its authors |
| `openfhe-tbgv-rs/src` | Rust (`unsafe` FFI) | safe wrappers, lifetimes, key installation | High |
| `fhe-prio3/src/packed.rs` | Rust | the only parser of received ciphertext bytes | High (fuzzed) |
| `fhe-prio3/src/vdec.rs` | Rust | verifiable decryption | High |
| `fhe-prio3/src/aggregator.rs`, `collector.rs` | Rust | protocol state machines | High |
| `fhe-prio3/src/ceremony.rs` | Rust | distributed key generation | High |
| `fhe-prio3/src/seal.rs`, `attest.rs` | Rust | sealing to collectors, material attestation | Medium (standard primitives) |
| `fhe-prio3-node` | Rust | HTTP/TLS transport, SQLite persistence | Medium: liveness and authentication, no cryptography of its own |

## 2. Method

1. For every place a decryption is consumed, we asked what a malicious
   aggregator gains by sending a wrong partial decryption. Each answer was
   turned into a test that first shows the attack **working** on the
   unverified path and then shows it stopped
   (`tests/malicious_aggregator.rs`).
2. For every new message that makes an honest party decrypt something, we
   asked whether a malicious sender (collector, leader, aggregator) could
   have it decrypt something else.
3. For every "commit, then reveal" step, we asked whether a retry, a
   restart or a replay lets a party change its commitment or collect a
   second set of samples.
4. We re-derived the arithmetic the soundness argument depends on
   (`SECURITY.md` Lemma 1) from OpenFHE's source
   (`DCRTPolyImpl::ModReduce`, `MultipartyBGVRNS::MultipartyDecryptFusion`),
   and measured the margins it needs
   (`openfhe-tbgv-rs/tests/vdec_primitives.rs`).

## 3. Findings

Severity is the impact before the fix. Status is as of this document.

| ID | Finding | Severity | Status |
|---|---|---|---|
| F-1 | **Silent-mode count forgery.** The valid count gates release (`min_batch_size`). An aggregator could shift its count partial so that a batch with one valid report read as full, making the honest aggregators release that one report's data to a colluding collector. A privacy break, not only a correctness one. | Critical | **Fixed.** Every aggregator verifies the count with its own blinded checks (`count_share` … `count_finish`). Test: `silent_count_forgery_is_caught_before_any_release`. |
| F-2 | **Verdict forced acceptance.** A rushing aggregator that saw the other partials first could choose its own so an invalid report's check fused to zero. | High | **Fixed.** Partials are committed before they are revealed (`prepare_masks` → `prepare_reveal` → `prepare_finish`). Test: `verdict_forced_acceptance_needs_an_adapted_partial_and_is_refused`. |
| F-2b | **Verdict mask cancellation**, found during this review. Masks were sent in the clear, so an aggregator that saw the honest masks first (the leader relays them) could send `Enc(r) − honest mask` and fix the combined mask. `r = 0` forces acceptance of invalid reports. A known `r` reveals the check value `E_j`: for a malleated related report that is a linear function of the honest input's bits, up to `k` field elements per forged report instead of the one bit the spec claimed. | Critical (privacy in verdict mode) | **Fixed.** Masks are committed before any is revealed (`prepare_init` → `prepare_mask_reveal` → `prepare_masks`). The node gains `/v1/mask-commits`. Test: `verdict_mask_cancellation_needs_the_honest_mask_and_is_refused`. |
| F-3 | **Released aggregate forgery.** A shifted partial changed the collector's result undetected unless the plausibility checks happened to catch it. | High | **Fixed.** The collector verifies with blinded checks (`release_challenge` … `release_finish`). The unverified `unshard*` API was removed. Test: `a_shifted_release_partial_is_caught_by_the_collector`, `tests/vdec.rs`. |
| F-4 | **Decryption oracle through checks** (introduced by a naive verifiable decryption). A verifier could pass a victim's ciphertext, plus blinding, off as a "check" and have it decrypted. | High | **Prevented by design.** Aggregators rebuild every check from their own accumulators and the opening, and reveal only if the bytes match. Tests: `aggregators_refuse_forged_or_repeated_release_checks`, `aggregators_refuse_a_check_that_is_not_one`. |
| F-5 | **Repeated challenges.** Each answered challenge is another flooded partial decryption of the same accumulators. | Medium | **Fixed.** One challenge per (batch, collector), persisted. Another is refused ("refusing a second set"). |
| F-6 | **Wrap-around shifts.** A shift of the size of the modulus changes the fused value non-linearly, outside the checks' algebra. | Medium | **Fixed.** Every fusion must stay below `q_0/4` (`vdec::fuse_checked`). Test: the wrap case in `tests/vdec.rs`. |
| F-7 | **Changing shares after committing.** An aggregator restored from a snapshot and given different count shares would re-decrypt and change its commitments. | Medium | **Fixed.** `count_commit` validates every share before storing anything and refuses different shares after a commit. Test: `tests/wire.rs` count cases. |
| F-8 | **Release challenges are not signed by the collector.** Whoever reaches `/v1/release-commit` first with the inter-aggregator token (in practice, a malicious leader) can have its own challenge answered. The collector's challenge is then refused. | Low (liveness only: reveals are sealed to the collector, and a substituted opening yields nothing readable) | **Open.** A malicious leader can stop the protocol in other ways too. A fix is to sign challenges with a collector signing key declared in the task. |
| F-9 | **No attribution.** A failed check shows that some aggregator cheated, not which one. | Low (design) | **Open.** Attribution needs per-share proofs (see F-10). |
| F-10 | **Key contributions are not proven well formed.** Oversized noise that still decrypts correctly could exceed what the noise flooding hides, and let whoever fuses a decryption read the encryption randomness. Measured: a public key inflated by 2^299 does exactly that (verdict parameters). | Medium (assumption A3) | **Bounded, not proven** (F-13, F-14). Keys the ceremony accepts leave every protocol decryption point 65 bits or more below the flooding (measured, verdict mode). A proof still needs lattice zero-knowledge proofs; see the decision in §4. |
| F-11 | **Verdict-mode validity oracle** through ciphertext malleability. | Medium (by design) | **Open, documented** (spec §4.3). Silent mode removes the per-report bit. |
| F-13 | **`vdec`'s `q0/4` bound did not bound noise against the flooding.** Partial decryptions are revealed at full precision. The bound looked only after the reduction to `q0`, and allowed noise up to 2^13 times the flooding range. | High (with F-10) | **Fixed.** Every fusion now checks the full-precision value against the exact support of `n` flooded partials (`vdec::check_flooding`): count, release and ceremony abort; the per-report verdict rejects the report (a client's malformed ciphertext is indistinguishable there, and must not make aggregators abort). No false rejection is possible. Every inflation that lets the fuser read the randomness is refused. Tests: `openfhe-tbgv-rs/tests/key_noise_gap.rs`. |
| F-14 | **The ceremony checked keys only at depth 1.** Public-key noise that passed its joint key check exceeded the flooding by 2^13 at the depth-3 verdict check value, the per-report decryption. A first deep check (a squaring chain) still let the check value come within 7 bits of the flooding. | High (with F-10) | **Fixed.** The ceremony runs the protocol's own circuit on the test ciphertexts to each decryption point, amplifies the noise by 2^64 and checks it against the flooding. It also checks a full-depth squaring chain slot by slot. Accepted inflations: public key 2^59, eval-mult 2^116/2^123, rotations 2^130. With those keys the margin is 65.0 bits or more at every point, singly or all together. Tests: `tests/ceremony.rs`, `tests/key_noise_protocol.rs`, `tests/ceremony_sweep.rs`. Silent-mode thresholds are not measured (memory); an honest silent ceremony passes. |
| F-15 | **Offline grinding of the validity challenge.** The challenge was an XOF of public data (task configuration and a hash of the ciphertexts). A client could compute it for any candidate report and re-encrypt until an invalid measurement passed, without contacting anyone: about `(p/2)^k` encryptions, `2^124` in verdict mode but only `2^78` in silent mode. Prio3 avoids this by deriving its query randomness from a verify key only aggregators hold. | Medium (silent-mode robustness below 128 bits against offline work) | **Fixed.** The challenge is keyed with a 32-byte verify key the ceremony generates jointly (contributions exchanged under pairwise X25519, agreement signed in round 9) and stores with each key share. Each submitted report is now one attempt. An aggregator colluding with a client can still hand over the key (as in Prio3). Tests: `challenge_is_bound_to_report_task_and_verify_key`, `aggregators_with_different_verify_keys_accept_nothing`, `tests/ceremony.rs` (split key, key never on the wire), `keys::tests`. |
| F-12 | **Samples per ciphertext grow with `n`.** In the count round, each aggregator decrypts `(n − 1)·κ` checks of the count ciphertext. | Informational | Bounded and fixed per task (SECURITY.md §5). Flooding parameters must cover it (A2). |

## 4. Decision: zero-knowledge proofs of key noise (F-10)

**Needed?** Only for privacy against an aggregator that is malicious
*during key generation*. The joint key check catches contributions that
break decryption. It cannot catch noise that is too large for the flooding
yet small enough to keep decryption correct.

**Why not implemented.** A sound implementation needs a lattice proof system
(for example Lyubashevsky–Nguyen–Plançon 2022, or LaBRADOR) instantiated for
OpenFHE's key formats across the whole RNS chain at ring dimension 65536,
with a security analysis of the instantiation. No audited implementation of
that exists. Writing one here without that analysis would be the kind of
unverified cryptography this project refuses to ship.

**What we do instead.** Bound it and measure the bound (F-13, F-14):
the ceremony only accepts keys whose noise, carried through the protocol's
own circuit and amplified by 2^64, stays inside the flooding. Accepted keys
leave every decryption point 65 bits or more below the flooding in verdict
mode. What stays assumed is recorded as assumption A3. Bind every contribution
to a signed transcript, so a deviation is attributable after the fact.
Recommend that deployments that cannot trust aggregators during setup run
the ceremony under stronger procedural controls (independent operators,
recorded builds) until such proofs exist.

**2026-09-30 assessment of building such proofs on LaZer** (IBM's lattice
proof library): `design-notes/key-proofs/README.md`. Compatible with the
ceremony and invisible to clients; blocked today by LaZer's proof-modulus
limit (our key moduli are 350 and 1277 bits against a 2^225 statement
limit), which forces a per-tower lifting with one shared commitment that
does not exist yet. One reference proof was built and measured there
(20,279 bytes, 105 ms prove, 53 ms verify). Decision unchanged: not built.

## 5. Invariants an auditor should check

1. No honest party partially decrypts a received ciphertext except:
   (a) the verdict `u`, which it computed itself from masks that were all
   committed before its own was revealed;
   (b) the batch accumulators, which it computed itself;
   (c) checks, which it reveals only after rebuilding them from its own
   ciphertexts and an in-range opening.
   Everything else it decrypts (the others' checks, before the opening) it
   commits to and never reveals unless (c) holds.
2. Each accumulator is released at most once per collector. Each release
   challenge and each count round is answered at most once. All of this is
   persisted before the answer leaves the node.
3. Every commitment is bound to task, batch or report, verifier, check
   index and committer (`count_context`, `release_context`,
   `verdict_context`). No digest can be moved between contexts.
4. Every received ciphertext is parsed by `packed.rs` against an exact
   expected shape before it reaches OpenFHE.
5. Verification randomness (`vdec::draw`) comes from `OsRng` and is never
   revealed before every commitment it opens is in.
6. `min_batch_size` is enforced on a **verified** valid count.

## 6. Where to spend audit time

1. `tbgv.cpp`: `tbgv_zero_encryption`, which truncates the public key to
   the reference's towers and checks the moduli; `tbgv_ciphertext_mult_monomial`,
   the negacyclic shift per tower; `tbgv_fuse_magnitude`, which must match
   OpenFHE's fusion step for step; and every function that builds OpenFHE
   objects from received residues.
2. `vdec.rs`: `build` (range checks, determinism), `verify` (every slot,
   every check, groups), `check_count`.
3. `aggregator.rs` count and release rounds: the order of store, commit and
   reveal under retries and restarts.
4. `ceremony.rs`: commit-before-reveal, the CRS, the joint key check.
5. The node's handlers: authentication of each route, and body limits.

## 6a. Internal audit of the shim, 2026-09-30

**This is still not an external audit.** It is a pass by the authors over
`openfhe-tbgv-rs/wrapper/tbgv.cpp` with three instruments, recorded so an
external reviewer can start from its results rather than repeat them.

*Manual review, findings and fixes (all in the same change):*

1. Three helper blocks (`namespace { .. }` at the key ceremony, the
   verifiable-decryption helpers and the file-static full-precision
   helpers) were opened inside the `extern "C"` region, which gives C
   linkage to C++ helpers returning C++ types (`clang -Wreturn-type-c-linkage`).
   The region is now closed before each helper block and reopened after.
2. Eight exported functions called OpenFHE or allocated without the
   `TBGV_TRY`/`TBGV_CATCH` guard, so a C++ exception (out of memory in
   `std::string`, a throwing getter) would have unwound into Rust, which is
   an abort at best: `tbgv_context_plain_mod`, `tbgv_context_ring_dim`,
   `tbgv_context_mult_depth`, `tbgv_context_log2_q`, `tbgv_pubkey_tag`,
   `tbgv_ciphertext_key_tag`, `tbgv_ciphertext_same_context`,
   `tbgv_context_num_towers`. All are guarded; the integer ones return 0
   and the string ones NULL with the error set.
3. `tbgv_context_mult_depth` computed `towers - 2` on an unsigned value:
   a context with fewer than two towers would have returned about 2^32.
   Guarded.
4. `tbgv_fuse_magnitude` started its ModReduce loop at `sizeQl - 1`: a
   partial decryption with zero towers would have wrapped the index.
   Guarded (such an object cannot come from the wire, whose builder
   refuses `num_towers = 0`, but the function no longer relies on that).
5. Not changed, recorded: every handle-taking export dereferences its
   handle without a NULL check; the Rust owner types (`Context`,
   `PublicKey`, `Ciphertext`, ..) construct only from non-NULL returns and
   are the only callers, so a NULL cannot reach the shim from safe code.

*clang-tidy 18* (`bugprone-*`, `cert-*`, `clang-analyzer-*`,
`performance-*`, minus the two style checks named in the CI comment): 13
warnings before, 0 after. Besides the linkage finding above they were a
float infinity narrowed to double, three needless copies of big integers,
a `memcpy` into a binary buffer flagged as a C-string copy (replaced by
`std::copy_n`) and a signed-char-to-integer conversion on the `int8_t`
noise coefficients, which is numeric use (annotated).

*AddressSanitizer + UndefinedBehaviorSanitizer* (gcc 13, shim compiled
with `-fsanitize=address,undefined -fno-sanitize-recover=undefined`, the
runtimes linked into the Rust test binaries and `libasan` preloaded; leak
detection off because OpenFHE's static tables are never freed): every
suite of `openfhe-tbgv-rs` (unit, `crs_ceremony`, `key_noise_gap`,
`openfhe_loader_facts`, `raw_residues`, `threshold`, `vdec_primitives`)
passed with no report. The protocol crate's `wire` suite, which feeds the
shim its hostile residues and the seeded mutation fuzz, passed the same
way: 7 of 7, no report, 739 s. (Method note for whoever repeats this: the
`libasan` preload must be applied to the test binary only, not to the
`cargo` invocation; preloading it into `rustc` deadlocks the compiler.
Build with `cargo test --no-run` and run the binary under `LD_PRELOAD`.)
OpenFHE itself is not instrumented in these runs, so an error inside
OpenFHE's own code would be seen only where it touches memory the shim
allocated.

*What this pass does not do:* prove memory safety, review OpenFHE, or
replace an external audit. The trusted base is unchanged.

## 7. Reproducing every claim

```sh
# shim, including the vdec primitives and margins
cargo test --release --manifest-path openfhe-tbgv-rs/Cargo.toml -- --test-threads=1
# protocol, attacks, verifiable decryption, ceremony
cd fhe-prio3
for t in wire protocol policy upgrade bounds mitigations vdec malicious_aggregator ceremony; do
  cargo test --release --test $t -- --test-threads=1
done
# multi-process deployments over TLS
cd ../fhe-prio3-node && cargo test --release -- --test-threads=1
```

CI (`.github/workflows/prio3.yml`) runs the same suites and the fuzz
targets on every push.

## 8. The OpenFHE pin

OpenFHE is pinned to 1.3.1 on purpose. Lemma 1 of `SECURITY.md` depends on
the exact fusion and ModReduce arithmetic, and the packed format depends on
the exact object layout. Moving to another version requires:

1. adding it to `TESTED_OPENFHE_VERSIONS` in `build.rs`;
2. re-reading `DCRTPolyImpl::ModReduce` and
   `MultipartyBGVRNS::MultipartyDecryptFusion` for changes, and updating
   `tbgv_fuse_magnitude` if they changed;
3. passing the start-up self-test, `vdec_primitives` and every suite above.

OpenFHE security advisories are tracked by CI: the nightly `OpenFHE pin
against upstream` job (`.github/scripts/openfhe-pin-check.sh`) fails when
the pinned tag no longer resolves to the pinned commit, when upstream has
published a security advisory after the pinned release, or when upstream's
latest release is newer than the pin. The last of these is expected to be
red until the pin is moved through the three steps above (at the time of
writing upstream is at v1.6.0); on pull requests it annotates without
failing. Rust dependencies are checked by `cargo-deny` on every change
(`prio3/deny.toml`: RustSec advisories including unmaintained crates,
licenses, wildcard and duplicate versions, sources).
