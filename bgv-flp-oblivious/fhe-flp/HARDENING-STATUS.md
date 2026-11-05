> Historical development document. For current guard implementation and release status, see ../README.md. Earlier statements that the phase guard is absent are superseded. Benchmark timings below predate the guard.

# Hardening status — NOT PRODUCTION READY

Baseline: c577887, isolated checkout of janak/fhe-prio3. Existing workspace changes preserved. The supplied HARDENING-PLAN is treated as an engineering proposal, not evidence of its security assertions.

## Implemented locally

- Evaluator detects an exact replay of canonical ciphertext bytes with a changed nonce within the same evaluator instance. State is inserted only after parsing and randomness derivation succeed. This is a partial W2 change only: a fresh re-encryption is not recognized, and a new evaluator instance loses the set. No collector persistence, cross-batch protection, authenticated participation or Sybil resistance is provided.

## Not implemented / security gates still open

- W1: no derived worst-case phase bound and no phase gate. Collector check requests now receive a complete canonical-residue preflight before any ciphertext is opened; this is structural validation only, not a noise or authorization gate. Test observations of noise cannot establish a universal worst-case bound. A norm threshold alone does not prove that an evaluator formed an authorized query or that an arbitrary attacker-controlled ciphertext is safe to decrypt. The suggested detection probability and key-lifetime leakage bound require an explicit adversarial model and proof; they are not established by the plan.
- W2 baseline: no durable request/task/batch binding or cross-restart release protection. The new experimental `single::oblivious` flow adds task/key/batch binding and a durable fail-closed reservation ledger; see `OBLIVIOUS-STATUS.md` for exact scope and limitations. No minimum cohort policy or authenticated participant uniqueness is claimed.
- W3: two end-to-end real-ciphertext attack tests have been added (results below); no independent security proof. Honest evaluator remains an assumption, distinct from non-collusion. Existing collector verdict disclosure and decryption requests can expose information if that assumption fails.
- No production readiness claim, deployment, commit or push. All required checks and workload measurements remain necessary.

## Collector preflight

Every reduced ciphertext in a check request is decoded for length, canonical residue and padding before any ciphertext in that request is decrypted. A real-ciphertext test corrupts the trailing ciphertext and confirms refusal and that the original request still succeeds. This validates rejection behavior; it does not instrument or prove the absence of every side channel. The change performs a second decode during subsequent opening; production performance impact has not been measured.

## Exact check-request replay (partial W2)

A collector instance remembers SHA-256 digests of successful complete check requests and rejects an identical request before decryption. A real-ciphertext test confirms an identical retry is rejected while a valid aggregate remains usable. This is not durable across restarts or keys and does not detect a freshly randomized check request for the same report. The in-memory set grows with successful requests; resource limits and durable transactional retention/expiry are not implemented. It does not prevent fresh report submissions, aggregate forgery, Sybils, omission or unauthorized evaluation.

## Real-ciphertext attack results (OpenFHE 1.3.1; ring 8192; p=65537)

- Crafted query: the evaluator replaces an FLP query with an encrypted unit query of a Count bit. In 100 independently encrypted reports, the collector verdict revealed the bit in 100/100 cases. This is an actual attack when the evaluator deviates, outside the honest-evaluator trust assumption. The collector preflight and in-memory digest checks do not prevent it.
- Shifted report: the evaluator adds a fresh encryption of 1 to a Count report while leaving its proof unchanged, then sends the resulting report through honest verification. 0/100 were accepted. This does not establish security for arbitrary ciphertext modifications or a probability bound.

Tests use actual ciphertexts, a real secret key and real noise; not mocks. Both tests were run directly. The malicious-query test asserts attacker success, and no mitigation of this oracle is claimed.

## Aggregate release control (partial W2)

One aggregate request passing the length and accepted-count checks consumes the current in-memory release before decryption, including when decryption or decoding fails. Repeated release is refused. This state is rearmed by a new successful check and lost on restart. It does not bind the ciphertext to the accepted reports or prevent a malicious evaluator from supplying a substituted aggregate, replaying a rerandomized check, or tricking the collector into opening a crafted ciphertext. Durable transactional batch state, task binding, authenticated request provenance, cohort policy and evaluator correctness remain unresolved. An attacker can cause denial of service by consuming the release with a malformed ciphertext.

## Additional evidence

- `substituted_aggregate_with_same_count_is_accepted` uses real encryptions: after two Count=1 reports pass verification, a malicious evaluator supplies a ciphertext summing two other Count=0 reports. The collector accepts and outputs 0 rather than the checked reports' true total 2. This successful substitution is outside the honest-evaluator assumption; exact one-use control and matching count do not prevent it.
- `known_fake_reports_reveal_the_remaining_input_in_released_total` uses real encrypted Count reports, demonstrates both target bit values, and confirms that an observer controlling two known zero reports in a three-report aggregate can infer the target from the output. This does not require breaking ciphertext encryption and is not prevented by cohort size alone.
- Reran 16 measurement configurations (eight supported task variants, two fields, eight reports each). Raw commands, exit codes, stdout and stderr are retained separately at `/workspace/fhe-flp-hardening-evidence/measurements.json`; no baseline results overwritten. These runs measured only the current partial hardening and cannot substantiate production security.

## External source access

Initial proxy retrieval of ePrint 2024/127 and 2026/2546 failed. Subsequently the user supplied the full 2026/2546 PDF, which was reviewed. The full 2024/127 text remains unavailable; the supplied talk was reviewed. A bound or IND-CPA-D leakage guarantee has not been derived.

## Uploaded literature reviewed

Targeted primary-source review is recorded in `/workspace/fhe-flp-hardening-evidence/PAPER-REVIEW.md`. PEEV verifies a computation proof before decryption; a phase check alone is not that verification. The uploaded 2026/2546 full text reinforces the need for proven worst-case or explicit-tail noise analysis. The previously stated full-text access blocker for 2026/2546 is resolved; the full 2024/127 paper remains unavailable, though Stehle's uploaded slides cover it. No new cryptographic guarantee is established.

## Encrypted-verdict candidate

See `OBLIVIOUS-STATUS.md` and `src/single/oblivious.rs`. This is a real local
implementation with tests, not a completed production release. It returns fresh
encrypted verdicts, masks in the output domain, and persists replay reservations.
The original W1 gate and its proof are still OPEN. Existing baseline attack tests
remain; no test success should be interpreted as arbitrary-ciphertext security.
