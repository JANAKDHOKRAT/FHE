# PINE in the one-aggregator protocol: threat model

Stage 1 of `PINE-SECURITY-FIX-GUIDE.md` (its section 2). This file fixes
what the protocol is meant to achieve and against whom. It claims nothing
about what is achieved: `PINE-REPAIR-STATUS.md` records that, experiment
by experiment.

## Parties and topology

* **Clients.** Each holds a gradient and an Ed25519 signing key whose
  verification key is one of the task's authorized identities.
* **Evaluator.** One server. Receives reports, holds a secret
  `verify_key`, computes on ciphertexts. Holds no decryption key.
* **Collector.** One server. Holds the complete BGV secret key. Never
  receives a report ciphertext.

The topology is fixed: no second aggregation server, no key sharing. A
change to either is a change of architecture, not a repair.

**The boundary that everything depends on:** whoever holds the BGV secret
key must never obtain a report ciphertext. A collector that receives one
decrypts the gradient. The protocol never sends one; the deployment must
also keep it from happening (separate operators, no shared storage or
logs, clients talk to the evaluator only over a channel the collector
cannot read).

## Task

Everything the parties must agree on is the task descriptor
(`src/pine/descriptor.rs`): application identifier, model hash, round,
PINE parameters, release threshold, authorized identities; together with
the constants the code fixes (wraparound parameters, field, BGV ring and
moduli) and the collector's public key. A task is one round: one report
per identity.

## Authorized release

For a task with authorized identities `I` and a batch of reports
submitted by a set `S` of them, let `V` be the subset whose encoded
gradient `g_i` is valid (integer L2 norm at most `B` over the integers).
The collector may output

    F = (sum of g_i for i in A, |A|)   if |A| >= min_accepted, else nothing

for a set `A` of accepted reports, once per batch, where:

* against malicious clients only, `A = V` except with the probability of
  the soundness accounting in `PINE.md`;
* reports the evaluator never forwards are not in `S` (omission, below).

The denominator of an average is the caller's policy and is not part of
the release: the collector outputs the sum and the accepted count.

## Permitted leakage

| To | What |
|---|---|
| evaluator | every report (ciphertexts under the collector's key), each report's identity, nonce and signature, the batch composition, **one accept/reject bit per report**, timing and errors of the collector's replies |
| collector | per report: identity, nonce, digests of the report's parts, signature; **which identities reported in which batch and each one's verdict**; the FLP verifier messages; then `F`; timing and sizes |
| network observer | sizes and timing (channels are assumed confidential and authenticated) |

The verdict per report is leaked to the evaluator, and the verdict per
identity to the collector. Hiding either changes the protocol
(`OBLIVIOUS-AGGREGATION-PLAN.md`) and its proof.

## Experiments

Each is a separate claim. Evaluator and collector colluding is excluded
from all of them: together they hold the key and the reports.

### E1: malicious clients; honest evaluator and collector

*Goal (verifiability):* the released sum is the sum of the honest
clients' gradients and of valid gradients of some malicious clients, one
per malicious identity at most.

*Adversary:* controls any subset of authorized identities; sees the public
key and the descriptor; chooses arbitrary report bytes, including
ciphertexts that are not honest encryptions (arbitrary noise, arbitrary
coefficients); may compute offline without limit on attempts short of the
stated bounds; sees whether its reports are accepted only through the
application, if at all.

### E2: malicious evaluator; honest collector and clients

*Goals:* (a) authorized-output integrity: the collector outputs only `F`
for the batch the evaluator presents, for reports signed by authorized
clients; (b) client privacy: the evaluator learns nothing about an honest
client's gradient beyond the permitted leakage, **including through the
collector's reactions** (verdicts, errors, timing).

*Adversary:* controls the evaluator completely: chooses which reports to
forward, crafts check and aggregate requests arbitrarily, adaptively, over
many batches; may hold client keys of its own (malicious clients
colluding with it).

*Known to fail today:* goal (b). The collector's one bit per report is a
reaction to ciphertexts the evaluator chooses (`PINE-REPAIR-STATUS.md`,
section 5).

*Unavoidable in this topology:* omission. The evaluator can drop any
report; the collector cannot know. A release threshold limits what a
release over few reports reveals; it does not detect targeted omission.

### E3: honest evaluator; malicious collector

*Goal (privacy):* the collector learns nothing about an honest client's
gradient beyond the permitted leakage and `F`.

*Adversary, as specified here:* **passive**. The collector follows the
protocol and tries to learn from everything it receives (ciphertexts
including their noise, metadata, sizes). An **active** collector, which
answers with false verdicts to steer what is aggregated, is in scope of
E3 only in this form: by answering "accept" for exactly one honest report
it obtains that report's gradient as the "sum". The release threshold is
enforced by the collector itself and therefore does not bind a malicious
one. **Privacy against an active collector is not a goal this protocol
can meet without a change** (the evaluator would have to enforce a
threshold on encrypted verdicts or the release would have to be
verifiable by a third party). This is stated so that no implementation
detail is read as covering it.

## Out of scope

* Evaluator and collector colluding.
* Fabricated identities: the list of authorized identities comes from the
  application. Who is on it, and whether a key holder is a real client,
  is not decided here.
* What a valid gradient does to a model (poisoning within the norm
  bound), differential privacy of the released sum, the training loop.
* Compromise of a client's signing key.
* Side channels of the implementation (timing of field arithmetic and
  decisions, error texts).
* Post-quantum security of the signatures: Ed25519 authenticates the
  cohort and is not post-quantum; the encryption's security does not
  extend to it.
