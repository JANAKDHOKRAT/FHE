# Source reading coverage

This log records inspected ranges, not whole-repository audit completion.

At main 19db638:
- fhe-flp/src/lib.rs: complete.
- fhe-flp/src/soundness.rs: complete.
- fhe-flp/src/codec.rs: complete, including tests.
- fhe-flp/src/single.rs: lines 1–610.
- fhe-flp/src/single/oblivious.rs: lines 1–530.
- fhe-flp/src/single/oblivious/phase.rs: complete.
- fhe-flp/src/protocol.rs: lines 1–180.
- Package README, build.rs, OBLIVIOUS-STATUS: inspected; status output partially truncated, so not claimed complete.

At research 4a4ad7f:
- prio3/README.md: complete.
- node README: lines 1–100.
- ONE-AGGREGATOR and HARDENING-PLAN: partial, combined output truncated.

Verified observations:
- single.rs separates input and proof ciphertext contributions before query evaluation for joint-randomness types.
- Single evaluator queries are keyed; joint randomness derives from nonce and input ciphertext bytes.
- Single collector checks off-support plaintext coefficients; this differs from the old unweighted-residual baseline.
- Oblivious collector reserves batch/report identities before secret-dependent work; leases persist on failure.
- Task/key/batch metadata binding is implemented, but no proof authenticates evaluator computation.
- PhaseBound explicitly bounds an inspected honest computation path; it disclaims CPA-D/circuit-privacy proof.
- No PINE verifier or PINE randomness/consistency integration was found in the inspected modules.

Pending: remaining ranges, native wrapper, tests, binaries, other source modules, research implementations, and individual historical diffs. Commit inventories are not equivalent to reading those diffs.
