# Attack assessment: no blanket security pass

These tests target our local code and keys only. Tests of hostile encoded
plaintexts are not a proof of security for arbitrary ciphertexts. These baseline architecture limits are not asserted to be new regressions from
projection. Acceptance of an all-zero ciphertext alone is not a demonstrated
security exploit. A production
release is NOT GREEN while the gaps below remain. Do not push this experiment
as a production-ready improvement.

| Attack | Execution / evidence | Security interpretation |
|---|---|---|
| Nonbinary Count input | native_tasks: 2, p-1, floor(p/2), plus algebra exhausts both fields | Expected contribution zero; finite encrypted cases plus exact field argument |
| Cancellation + group reuse | native_tasks: 2/5 and -1/5 in separate reports sharing group 0; opposing nonzero residuals; mixed with valid/invalid reports | Must not combine report values before projection; group collision flush remains mandatory |
| Cross-slot + second-row injection | native_tasks: valid authorized value, p-1 in other group and second row | Expected aggregate ignores injected data |
| Replay + duplicate group | native_tasks: exact same report submitted twice at group 0 | ACCEPTED and counted twice: no anti-replay/participation policy; documented deployment gap |
| Wrong parameters/key | fingerprint mutation in native_tasks; library unit guards check key epoch and context identity | Refuses mismatched metadata. Public fingerprints are not proof of honest encryption; a malicious client can copy them |
| Malformed wire + content ID recomputation | native_tasks: magic/version/reserved/fingerprint corruption and truncation, IDs recomputed | Expected rejection before admission; state checked for tested header cases. Existing packed unit tests cover residue/length/padding/canonicality |
| Arbitrary adversarial ciphertext | NOT established by honest-encryption input tests or parsing | OPEN SECURITY GAP. Need protocol-level security argument or appropriate proofs; do not call tested plaintexts malicious-ciphertext certification |
| Overflow + collision + maximal values | native_tasks: mixed batch filled to 32 with ones, reused groups, 33rd refused; collector oversized metadata refused | Bounded correctness evidence. Arithmetic N<p alone is not noise-capacity evidence |
| Flood/concurrent admission | Header mutation tests exercise local rejection only; no authenticated bounded network service exists here | NOT qualified as DoS-safe or concurrency-safe. External service admission and serialized context/key management required |
| Malicious evaluator / collector oracle | Architecture audit: collector receives no proof of correct evaluation or authorized release; owns full key | OUTSIDE honest-evaluator/noncollusion protection. No authenticated aggregate provenance or output-only FHE proof supplied |

The production gate cannot be turned green by relabeling open cases as passed.
A local correctness gate and an encryption-parameter table check are separate
from end-to-end deployment security. Preserve all failure logs.
