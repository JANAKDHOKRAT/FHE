# Count authentication hardening

This implements durable admission and authenticated releases for the paper's
**honest evaluator / noncolluding collector** model. It is a tested security
component, **not a complete production-security certification of BGV Count**.
Arbitrary-ciphertext security and collector output-only privacy remain open.

Use `count_auth::count::Ingress` and `count_auth::count::Collector`. The raw
paper-core API remains unchanged for baseline reproduction and does not acquire
these protections automatically. Do not expose that raw collector as a service.

## Enforced behavior

- Strict Ed25519 verification with an explicitly provisioned eligible-client
  roster, at most 32 keys per batch. Enrollment must establish which real
  principals receive keys; multiple enrolled keys are not Sybil resistance.
- One **authenticated attempt** per client per batch. Bad signatures consume no
  quota. A valid signature on a malformed payload consumes only that client's
  attempt, never an accepted-report count. This prevents repeated expensive
  parsing by the same registered client. Stored duplicates are refused before
  payload validation. Crash rollback and concurrent processes share SQLite's
  transaction, not an in-memory replay set.
- Signatures bind the complete ciphertext payload, client key, policy scope,
  task, profile, key epoch, batch, roster and release policy. Recomputed report
  IDs do not authorize changed ciphertexts or metadata.
- Fixed-width bounded transport frames; declared lengths and client/scope are
  checked before payload allocation. The Count payload has only group/u32,
  ciphertext length/u32 and packed ciphertext bytes. It never uses an arbitrary
  nested-vector deserializer on incoming network data.
- SQLite WAL, synchronous FULL, immediate transactions, local private owner-only
  store directories and NOFOLLOW database opens. One admission database per
  batch. Do not use independent database replicas or NFS WAL as a shared ledger.
  Local privileged storage rollback/replacement is outside this trust model;
  filesystem backups must not restore an old live key epoch and admission state.
- Minimum distinct-client batch size >=2, maximum <=32, frozen at policy setup.
  This is a release floor, not differential privacy or a defense against every
  overlapping-query attack. The policy issuer is trusted.
- Seal freezes accepted rows in a transaction, recomputes the actual Count
  through OpenFHE, derives the actual number of admitted reports, and signs
  count, transcript commitment, ciphertext and policy scope together.
- Collector verifies the signature and policy before reaching its secret key.
  Relabeling a two-report result as 32 reports fails. Exact release retries
  return the durable cached count; a conflicting signed release for the same
  scope is refused. A crash cannot commit a receipt without its result.
- OpenFHE context/key operations through this component use a common mutex;
  constructors release it before database operations to avoid lock inversion.
  Do not concurrently bypass it with direct raw OpenFHE key-table mutation.

Signatures protect against transport/storage substitution by parties without the
release key. They do not prove an evaluator computed honestly: that evaluator
trust assumption is retained at the user's explicit instruction.

## Parameter screening and actual wire size

The wired Count path currently accepts only p=786433, n=65536, depth22,
HYBRID digits4, four groups, projected exact Count, operational cap<=32. It
pins a fingerprint of the **actual full QP primes**. Different contexts require
new screening. Pin the recorded OpenFHE 1.3.1 build and its defaults.

The independent lattice-estimator run screened primal-uSVP, primal-BDD, dual
and dual-hybrid using both ADPS16 and MATZOV, unlimited LWE samples, uniform
ternary secrets, sigma=3.19f and the full QP modulus. The minimum modeled work
was 2^143.664 and 2^175.434 respectively. These are heuristic costs, not proven
security bits. Ring-specific attacks, KDM/circular assumptions and untested
attack families are not certified by this exercise.

The 5.89 MiB profile remains valid as a historical correctness benchmark, but
is refused by this authenticated path: its ADPS16 estimate was approximately
2^97.236, despite approximately 2^130.240 under MATZOV and the library's named
128-bit setting. Cost-model dependence is retained, not hidden by selecting a
favorable estimator model.

The actual authenticated report measured in the end-to-end test is
**16,793,800 bytes**: 16,793,656 ciphertext bytes + 8 Count framing bytes +
136 authentication framing bytes. The release was 1,310,916 bytes. Do not
quote the old 5.89 MiB upload for this parameter/profile choice. No timing
speedup claim is made for the authenticated layer.

## Evidence and reproduction

`tests/count_integration.rs` uses actual OpenFHE encryption, evaluation and
decryption, durable restart, report replay, signed-release tampering and exact
retry. `tests/durable_auth.rs` exercises eight competing processes, abrupt exit
inside a write transaction, failed sealing/decryption, minimum/maximum bounds,
policy mismatch, conflicting signed releases, length/registry/signature attacks,
and database directory/symlink protection. Two ignored test functions are child
workers that the process test explicitly launches; they are not omitted checks.

After setting the pinned OPENFHE_DIR and LD_LIBRARY_PATH:

```sh
export CARGO_TARGET_DIR=/workspace/fhe-build/count-optimization
cargo test --release --locked --manifest-path optimization/count/count-auth/Cargo.toml -- --nocapture
cargo clippy --release --locked --manifest-path optimization/count/count-auth/Cargo.toml --all-targets -- -D warnings
```

Runtime signing and collector keys are supplied by trusted provisioning; they
are not generated from hardcoded demo seeds. Fixed seeds in unit tests are
public test fixtures. Production transport must authenticate policy/material
provisioning, enforce read deadlines, body/connection/rate limits and key
storage/access controls. This crate is not an HTTP/TLS deployment.
