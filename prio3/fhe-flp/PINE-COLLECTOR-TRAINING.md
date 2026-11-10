# Collector protection and training integration

**Production gate: CLOSED.** This change implements collector interaction limits
and functional training integration. It does not establish the required theorem
that the collector's entire view reveals only permitted information. The existing
aggregate-substitution attack remains possible. Restricting scope to these two
items does not remove their dependency on computation authentication.

## What is implemented

`src/pine/collector_session.rs` provides a fresh full-key collector for one task.
The architecture remains PINE encoding and FLP verification, one BGV evaluator,
and a separate collector with the full decryption key. PINE circuits, challenge
rules, masking widths, and admission thresholds are unchanged.

The session:

- restricts a task to an explicit report/byte budget, at most one check and one
  aggregate request;
- reserves task creation, check and release with exclusive files and fsync
  **before** their processing; no second session/key can serve that descriptor
  in the same ledger;
- permanently closes a failed interaction, including malformed aggregate
  requests, and permits no release below the signed threshold;
- returns a single public refusal type instead of exposing detailed library
  errors, internal noise values or verifier messages;
- counts admission phase measurements as secret-key operations, alongside
  plaintext openings. The old `decryptions()` counter only counted the latter.

These controls bound reactions and fail closed. They do not make timing constant,
stop a malicious evaluator's first chosen-ciphertext query, or authenticate
computation. The caller must authenticate the evaluator channel and enforce
receive-size limits **before buffering**. Local audit counters are not endpoints.
The lower-level `PineCollector` API is retained for compatibility/tests; exposing
it alongside the session bypasses the new interaction limits.

`src/pine/training.rs` provides local multiclass softmax training, bounded PINE
update preparation, model/round/configuration binding, accepted-client averaging,
and immutable checksummed checkpoints. Clients need only their local data,
current model, task, public encryption key and signing key. The evaluator needs
no local training data or decryption key. The collector needs no client dataset.
The training APIs can be used by separate role processes; network deployment and
operator isolation are not supplied by this change.

## Safe arithmetic and exact quantization

For each local delta d, first clip its real norm to B / 2^f, then use PINE's
round-to-nearest, ties-to-even encoding q_j = round(2^f d_j). Rounding can increase
the norm, so check S = sum(q_j^2) in checked u128 arithmetic. If S > B^2, let
D = ceil(sqrt(S)), computed with an integer square root, and replace

    q'_j = trunc(q_j B / D).

Truncation is toward zero. Consequently |q'_j| <= |q_j| B / D and
sum(q'_j^2) <= S B^2 / D^2 <= B^2. This is an integer argument, independent of
floating-point estimates of sqrt(S). Check the resulting integer norm again and
round-trip the dyadic measurement through the actual PINE encoder. This proves a
bound on the quantized update; it does not prove a bound on an original unrounded
update, nor exclude norm-valid poisoning.

For a released sum, check the exact task descriptor, model digest, round,
optimizer configuration, accepted count, dimension, finite values, quantization
grid, signed-decoding capacity, and the triangle-inequality norm bound n B.
Then apply

    new_model = old_model + server_learning_rate * sum / accepted_count.

This is **equal client weighting**, not sample-count weighting. Rejected clients
contribute neither to the numerator nor the denominator. Coordinate/norm checks
on the output do not prove that it is the authorized sum.

The existing BGV admission derivation still governs safe encrypted arithmetic
under an honest evaluator. This change does not infer safety from canonical
serialization alone. See `PINE-COLLECTOR-SOURCE-CHECK.md` for the two previously
unread library operations. The arbitrary-evaluator gap remains.

## Failures and recovery

A bad check consumes the task's check opportunity. A bad aggregate consumes the
release opportunity. Restarting a session with the same descriptor/ledger is
refused before a new key is generated. This deliberately sacrifices availability
to avoid repeated decryption queries. Use a new task/round and key after an
aborted session; do not delete or roll back the old ledger to retry it.

Training checkpoints use create-new, a checksum, file fsync and directory fsync.
Completed checkpoints can be loaded and validated; applying an old release to a
newer state is refused. Incomplete files are rejected, not silently used as a
model. Checkpoint checksums detect accidental corruption, not malicious disk
rewrites. Operators must protect files and prevent rollback/concurrent model
writers. Exactly-once recovery across the release-to-checkpoint crash window is
NOT implemented: a lost release cannot be recovered by re-querying the collector.
The qualification runner refuses to overwrite a previous run.

## Permitted view and remaining privacy obligation

The existing threat model permits collector knowledge of identities, signed
commitments, per-report decisions, FLP verifier messages, accepted count and the
aggregate, plus specified metadata. The actual collector also receives masked
admission copies and evaluated ciphertexts, including their noise and one
original ciphertext component. Proving that this extra view can be simulated
from permitted information remains necessary.

The earlier per-copy masking and per-check flooding estimates do not themselves
prove this joint statement. A proof must handle shared encryption randomness,
report digests/signatures, wraparound retries, all correlated verifier messages,
and composition over all ciphertexts, batches and rounds. Merely hiding an error
string does not remove timing or decision leakage. Fresh keys and request caps
limit reuse; neither is a proof of chosen-ciphertext security. The evaluator can
still submit a substituted check or aggregate: the known-limit test continues to
record this attack, rather than asserting it has been repaired.

Privacy against an active full-key collector also remains outside the current
claim. An operator with that key who obtains a raw report can decrypt it. No
software wrapper on that same collector prevents this.

## Real-data qualification and reproduction

`train_pine` is an end-to-end correctness runner, **not a privacy-isolated
production service**: all roles and the plaintext reference reside in one
process so their results can be compared. It uses actual OpenFHE BGV ciphertexts,
PINE proofs, signed reports and the bounded collector session; no encryption or
validation is mocked.

    python3 scripts/fetch_training_digits.py /tmp/pine-digits.csv
    cargo build --release --bin train_pine
    cargo run --release --bin train_pine -- /tmp/pine-digits.csv /tmp/NEW-pine-training-run 5 4
    cargo test --release --test pine_training -- --test-threads=1

Set OpenFHE library search paths as required by the existing build. The fetcher
pins and hashes the real scikit-learn copy of the UCI handwritten digit dataset;
attribution is in the script. There are 1,797 images, with every fifth row held
out before partitioning the other 1,437 among four clients. Pixels are scaled
by 1/16. The 10-class linear softmax model has 650 parameters. Each round performs
five local full-batch steps at learning rate 0.5, clips/quantizes at B=32768,
f=15, and averages client deltas with server learning rate 1. Proof counts are
7 main / 4 norm-equality. This does not remove the documented wraparound/grinding
bound of the current challenge protocol.

Each round independently sums client integers, checks exact encrypted-sum
equality, computes the plaintext model update separately, checks model equality,
and reads back its new checkpoint. It records all outcomes, accuracy and traffic.
A finite real-data run demonstrates those configurations, not every model size,
every dataset, convergence, or production security. Test proof counts are lower
than the qualification runner's counts to keep regression runs short.

See `results/collector-training/` for source provenance, test logs and measured
rounds. No private keys, report ciphertexts, client examples or local updates are
stored in that committed evidence.
