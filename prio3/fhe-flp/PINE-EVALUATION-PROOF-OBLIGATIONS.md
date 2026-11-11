# The missing evaluator proof and collector privacy obligation

Status: implementation obligations, **not an implemented proof relation or a
security theorem**. Neither a hash/signature of the evaluator's answer nor the
separate-process runner fixes the known aggregate-substitution attack.

## Concrete candidate examined

RISC Zero's zkVM can prove a pinned guest program's execution with private
inputs and a public journal. Its official documentation identifies the guest
program, not arbitrary host code, as the part being proved:
https://dev.risczero.com/api/zkvm

A plausible engineering route is a guest that verifies the exact PINE/BGV
computation on private report ciphertexts and publishes only commitments to the
collector's prescribed request bytes. This supplements PINE encoding and FLP
validation; it does not replace their predicate with a generic norm proof.
It introduces no additional aggregation server and no key sharing.

This route is NOT built or benchmarked here. Calling the existing C++ OpenFHE
library on the host and passing its answer to a guest would not prove that
computation. The checked BGV arithmetic and its correspondence with OpenFHE's
encoding must be implemented inside the proved computation. Its cost is unknown.

Release/version selection requires checking upstream advisories and pinning
both program and verifier. For example, the upstream advisory
https://github.com/risc0/risc0/security/advisories/GHSA-g3qg-6746-3mg9
documents an underconstrained-circuit flaw in older versions. An audit of a VM
does not audit this application's relation. Production builds must disable
fake/dev-mode receipts and refuse wrong image IDs or unresolved assumptions;
upstream documents `disable-dev-mode` at https://github.com/risc0/risc0 .

## Statement required before checking a batch

Public information must fix the protocol/version, canonical task bytes, trusted
public-key identity and cryptographic parameters, batch ID, ordered authenticated
cohort commitments, challenge setup, and exact output request digest/length.
The private witness contains the full report bytes and necessary evaluator state
and random coins. It must never be supplied to the collector as plaintext.

The checked computation must establish ALL of the following:

1. Strictly parse every report under the task's canonical residue encoding.
   Check task/key identity, lengths, coefficients, component counts, tower levels
   and expected metadata. A ciphertext from another context is not interchangeable.
2. Recompute each part digest and the exact commitment signed by its authorized
   client. Match the collector's authenticated ordered cohort, with no duplicates.
   A signature on a digest is insufficient unless its private preimage is linked.
3. Derive the wraparound vectors, joint randomness, and query points with the
   prescribed domains and transcript. Fix all data/proof parts at their required
   stages; the evaluator cannot replace challenge setup through a private witness.
4. Compute the actual affine query maps for BOTH PINE circuits and all proof
   repetitions. Use all encoded coordinates and handle unused coefficients as the
   implementation specifies. Checking only valid witnesses is insufficient.
5. Compute every masked admission copy from those same original ciphertexts.
   Constrain masks, flooding support, all RNS arithmetic, transforms, modulus
   reductions and output extraction. Passing canonical output residues alone is
   not proof that these operations were performed.
6. Bind the exact serialized check request to the public digest the collector
   checks, so it cannot be replaced after proof verification.

Only THEN may the collector measure admission phases and open verifier values.
Verifying a proof after these key-dependent operations leaves the reaction attack
surface open. The current collector does not have this prerequisite.

## Statement required before aggregate release

Link to the SAME proved batch, its signed cohort and the collector's actual
verdicts. Check the accepted count and threshold; include each accepted gradient
exactly once, each rejected gradient zero times. Compute the sum, masking,
flooding, reductions and coordinate selection, and bind the exact final request
bytes. Preserve the single-use ledger and round/model binding.

The collector must reject a substituted ciphertext even when its claimed batch,
count and verdict digest are all copied from an authorized request. This is the
working attack recorded by the existing known-limit regression test.

## Why a correct-execution proof alone is insufficient

- **Challenges:** the evaluator currently owns `verify_key`. Constraining a
  chosen key's hash does not prove it was uniform, unpredictable at the right
  time, or independent of colluding clients. The adversarial-evaluator protocol
  needs an explicit challenge setup and reduction, not a private arbitrary seed.
- **Randomness:** a witness proving existence of a mask/flooding seed does not
  prove honest sampling. State which corruption case guarantees randomness and
  how its ownership/distribution is enforced in the others.
- **Collector view:** ZK hides the witness of the execution proof. It does not
  automatically hide information in the ciphertexts, admission copies, noise,
  commitments, signatures, decisions and timing that the collector also receives.
  A simulator must cover that joint view, including wraparound retries and
  correlations, and account for all ciphertexts and rounds.
- **Keys/roles:** the full-key collector must not receive original reports. A
  colluding evaluator can send them regardless of this protocol. Collusion is
  excluded by the current architecture's threat model; process separation does
  not make that assumption disappear.

## Honest completion criterion

Completion requires an implemented exact relation, real proofs on actual BGV
requests, negative tests rejecting substituted checks and aggregates BEFORE
secret-key work, a justified challenge protocol and joint-view privacy argument,
and measurements of the complete proof/verification path. None of those can be
replaced by a successful training run or by a generic zkVM example.

The process-separation code is useful independently, but this note deliberately
does not relabel the two open cryptographic claims as solved.
