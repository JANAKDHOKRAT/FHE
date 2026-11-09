# Not production qualified

Implemented: two FieldPrio2 PINE arithmetic circuits, configurable chunked
ParallelSum square/multiplication gadgets, fixed-point encoding preflight,
FLP proof/query/decide tests and chunk-invariance tests.

The actual_bgv test evaluates affine query rows using OpenFHE 1.3.1 ciphertexts
and decrypts coefficient zero with the full secret key. It compares each row
against prio query for an honest witness/proof and arbitrary input/proof values,
with arbitrary off-support plaintext. This is a local arithmetic verification
harness, not a deployed protocol: challenges are fixed test values, the test
process owns both public and secret keys, and circuit privacy is not established.
It uses one ciphertext per row to avoid cross-row contamination.

Missing: full reference-vector differential checks, secure transcript/challenge
binding, transport and role separation, authenticated evaluation, privacy proof,
training orchestration and full adversarial/performance qualification. No release
API is exposed. No production or complete-PINE claim follows from these tests.
