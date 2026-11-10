# PINE–BGV: challenge binding and aggregate authentication repair guide

Reviewed baseline: `2aa1ec0` on `janak/fhe-prio3`.
Scope: source/diff review, not an independent rerun of the new tests or a cryptographic certification.
This document is a staged engineering and proof plan. It is not itself a completed protocol or security proof.

## 1. What the update actually fixes

The update adds whole-request canonical decoding before decryption, persistent
batch/nonce/release reservations, and consumed evaluator sessions. The collector
records release before decrypting and loses pending volatile batches on restart.
These are useful protections against repeated operations under the documented
filesystem assumptions. They do not authenticate how a ciphertext was computed.

`tests/pine.rs::known_limit_an_evaluator_that_deviates_can_substitute_the_sum`
constructs a second evaluator's aggregate, copies the first batch identifier
onto it, and obtains the other sum from the collector. A passing result for
this test means the attack succeeded, not that the system resisted it.

The retitled challenge section correctly distinguishes deterministic byte
binding from an inherited PINE security theorem. More precisely, a byte change
is expected to change derived challenges except with collision probability;
finite tests cannot prove that every byte change changes every challenge.

## 2. Freeze the security contract first

Preserve the topology: clients, one BGV evaluator, and a separate collector
holding the complete BGV secret key. Do not add a second aggregation server or
split the key without explicitly changing the architecture.

Write separate experiments for:

1. Malicious clients, honest evaluator and collector.
2. Malicious evaluator, honest collector: authorized-output integrity and
   client privacy, including collector reactions.
3. Honest evaluator, malicious collector: privacy of individual reports given
   the permitted aggregate and public metadata.

Evaluator/collector collusion is excluded. The party holding the full key must
not receive raw individual report ciphertexts: it could decrypt them directly.
Protect this boundary with deployment isolation as well as a protocol model.
Specify whether active collector attacks are in scope; do not silently assume
honesty in the implementation while claiming malicious-collector privacy.

List permitted leakage: cohort identities or size, dimensions, aborts, timings,
verdicts, accepted count and aggregate. Current per-report verdict replies are
not verdict-oblivious. Changing them requires updating both protocol and proof.

Deliverable: a threat-model document and precise authorized-release function.
Gate: no undefined corruption cases or undocumented leakage.

## 3. Define a canonical transcript and an authenticated cohort

Define one versioned binary descriptor containing:

- protocol/circuit version and hash; field and BGV parameters; public-key digest;
- model hash, round identifier, scale, integer norm bound, chunk/proof counts;
- authorized identities and aggregation/denominator policy;
- batch identifier, ordered report commitments, and release policy.

Use explicit lengths, canonical field/residue encodings and domain separation.
Reject duplicate identities/nonces, mismatched versions and noncanonical values.
Commit to exact `G`, `W` and `P` bytes and their boundaries, not concatenations
with ambiguous parsing. Bind key identity independently of parameter identity.

An evaluator-supplied list is not evidence of admission. Clients or an
independently authorized admission service must authenticate the intended
reports, with a defined inclusion/dropout deadline and omission policy.
Client signatures on ciphertext digests can let the collector verify inclusion
without receiving raw decryptable reports. Analyze the leakage of that metadata.
Authentication does not establish ciphertext well-formedness or honest training.

Gate: show that a malicious evaluator cannot substitute the cohort while still
presenting an authorized descriptor. If omissions are allowed, specify which.

## 4. Challenge binding: choose and prove an explicit construction

### Existing implementation

The current sequence is approximately:

    G fixed -> derive wraparound seed from nonce and G bytes
    W fixed -> derive verification randomness from nonce, G and W bytes
    P fixed -> derive secret-keyed FLP query points from the full report

Separating G/W/P read paths is necessary. It does not alone prove equivalence
to PINE's distributed Fiat–Shamir construction. Upstream recomputes randomness
parts from blinded secret shares and compares corrected seeds in `prep_next`.

### Route A: preserve upstream preparation semantics

Specify how each original verifier's private state is represented under BGV.
Securely evaluate the actual share hashing/XOFs, corrected-seed comparisons,
wraparound dot products and both FLP verifiers on those same states. Specify who
knows the virtual verifier secrets, how they are generated, and what is opened.
This is a substantially larger circuit than the present affine FLP query.
Hash/XOF operations and private challenge-dependent arithmetic cannot simply be
replaced by public plaintext coefficient products.

Proof obligations: faithful simulation of preparation, a reduction to the pinned
PINE protocol, encryption/evaluation correctness, and a privacy simulation for
each real party. Preserving formulas alone is insufficient.

### Route B: retain ciphertext-derived challenges as a new adaptation

Keep the current arithmetic only after specifying a new protocol and proving it.
A candidate proof must handle maliciously chosen ciphertexts, chosen randomness,
adaptive oracle queries, nonce changes, reencryption, auxiliary padding and
multiple keys/tasks. It must show that the adversary fixes the relevant input
before obtaining the corresponding random challenge in the chosen model.

A proposed client knowledge proof must explicitly relate G/W/P to their
plaintexts and admissible encryption witnesses. An equality
`C = Enc(pk,m;r)` does not certify that r was honestly sampled. State bounds on
every admitted error/randomness value and prove security for all admitted values.
Do not demand that proof bytes be fixed before a challenge they legitimately
need; specify the stages and bind each witness at the right stage.

Derive a concrete grinding bound in the stated random-oracle/PRF model. Include
all offline attempts and online reports. The 100 wraparound checks do not become
stronger merely because the number of main FLP proofs increases.

Gate for either route: a complete, reviewed security argument with named
assumptions, adversary model, failure terms and concrete parameter restrictions.
Neither route is established by this guide. Do not call Route B unchanged PINE.

## 5. Authenticate computation before the collector decrypts

Define the exact relation to be proved. A schematic relation is:

    R(D, C_check, C_final; W) = 1

where D is the authorized descriptor, and W contains committed reports,
intermediate computation and any permitted private witnesses. The relation must
establish exact parsing, membership/order, correct query generation, BGV query
evaluation, masking, reduction and output extraction. It must also establish
that the final ciphertext aggregates exactly the accepted contributions.

The current protocol has two phases: the collector first decides acceptance,
then the evaluator aggregates. Therefore one final proof is too late to protect
the first decryptions. Define a proof for check requests and another for the
final computation, bound to the same descriptor and authenticated verdict state.
If verdicts are encrypted, the relation must authenticate their ciphertexts and
correctly enforce the encrypted filtering operation.

Select a concrete proof system only after defining this relation. State the
needed soundness/knowledge and zero-knowledge properties, setup requirements,
adaptive-security model, and whether post-quantum security is required. A proof
system using pairing assumptions does not inherit BGV's post-quantum claims.
Benchmark the actual modular/RNS operations, not merely a plaintext norm circuit.

Do not send the collector raw report ciphertexts so it can recompute the sum:
with its full secret key, that destroys the intended individual-input privacy.
Do not treat a public hash, evaluator signature, matching count or matching batch
identifier as a proof of correct computation. The attacker controls those labels.

Gate: the substituted-sum test must be rejected before decryption. Add an
instrumented decryption counter to establish the ordering, not just an error code.

## 6. Specify randomness ownership and ciphertext privacy

For every mask, prover seed, challenge and flooding value, record its generator,
recipient, distribution, lifetime and what happens if it is biased or reused.
A proof that computation used some randomness does not establish random sampling.
Publicly revealing masks or flooding coins to the full-key collector can defeat
the intended hiding; a public beacon is not a universal randomness repair.

Provide a simulator for the collector's full view, including evaluated ciphertexts,
proofs, metadata and failure behavior. Ordinary BGV IND-CPA does not provide this
against a recipient holding the secret key. A worst-case circuit-privacy argument
must cover admitted adversarial inputs, every supported task size, accumulated
queries and the actual flooding/modulus-reduction path.

Also justify negligible decryption failure. A measured noise margin or an
honest-input phase guard is not an authorization proof or a universal defense
against chosen-ciphertext/reaction attacks.

Gate: explicit sanitization/privacy theorem and its parameter budget. If missing,
leave production status red even when aggregate substitution is prevented.

## 7. Collector state machine and failure handling

Use explicit states: collecting, sealed, check-authorized, checked,
final-authorized, release-reserved, released or permanently failed.

- Parse and preflight the entire request before secret-dependent processing.
- Authenticate D and verify the appropriate computation proof before decryption.
- Reserve batch/report/key use durably with atomic operations.
- Bind final authorization to the stored checked batch and verdict state.
- Reserve release durably before producing a plaintext result.
- Define restart semantics and protect retained state against rollback.
- Refuse a new check while another batch is pending, or implement explicit,
  authenticated cancellation; do not silently replace a pending batch.
- Define the all-rejected case, cohort denominator and retry rules.

The current code replaces pending state when a new request reaches processing;
that behavior deserves an explicit availability policy. Nonce reservations do
not authenticate client identity, prevent reencryption or enforce cohort policy.
Never make secret-dependent failures an unrestricted diagnostic oracle.

## 8. Required regression and adversarial evidence

Preserve the historical successful-substitution test as evidence against the
legacy path. For the repaired path, assert refusal and zero decryptions for:

1. Another valid aggregate relabelled with the checked batch/count.
2. Modified check ciphertext, verifier row, final ciphertext or accepted set.
3. Reordered, omitted, duplicated or substituted reports.
4. Same nonce in another round/key/profile; same ciphertext under another nonce.
5. G/W/P mix-and-match, reencryption and changed off-support coefficients.
6. Proof for one descriptor paired with another descriptor or output.
7. Malformed ciphertext/proof in the last request position.
8. Crash at every durable transition; concurrent duplicate requests; rollback.
9. Altered masks, reused randomness, invalid encryption witnesses and selected
   noise-growth/doubling cases within the applicable attack model.

For challenge code, test domain separation, canonicalization, upstream vectors,
negative seed-consistency cases and arbitrary field-valued circuit inputs.
These tests support the argument; they do not prove random-oracle security or
absence of all attacks. Cite and implement each paper attack only where its
preconditions apply. Record excluded attacks and reasons.

## 9. Parameters and end-to-end qualification

Treat these separately: integer-norm wraparound, aggregate signed decoding,
FLP interpolation domains, BGV correctness and lattice security.

For equal-weight updates with integer norm <= B, N submitted reports and
scale S, enforce p > 2NB for centered decoding. Check the post-rounding integer
norm; clipping before rounding is insufficient. Specify whether rejected reports
remain in the averaging denominator. Weighted FedAvg needs different bounds.

Assess small primes and rings per explicit profile. The bound-16 profile fails
p=65537's PINE guard; that does not establish impossibility for every bound.
Do not force smaller rings while disabling the library security selection.

Run honest and adversarial training with exact quantized-reference comparisons,
then measure whole rounds at increasing dimensions/cohort sizes. Include client
proof generation, verification proofs, keys, all traffic, peak memory, failures,
recovery and repeated timing samples. Norm-valid poisoning remains possible.

## 10. Release sequence

1. Review threat model and descriptor/admission design.
2. Resolve challenge-construction proof obligations.
3. Specify and instantiate both authorized-evaluation proof relations.
4. Establish randomness, privacy and correctness bounds.
5. Implement the collector state machine and rejection-before-decryption tests.
6. Pass reference, arithmetic, encrypted and adversarial tests for each profile.
7. Qualify actual training and deployment behavior.
8. Obtain independent cryptographic review; record remaining assumptions/limits.
9. Publish only the claim supported by these results.

Do not mark these items complete because a heading, interface or test stub exists.
The current update fixes operational issues; the two requested cryptographic
repairs remain substantive work. No concrete secure proof-system instantiation
or completed composition proof is supplied by the current implementation.
