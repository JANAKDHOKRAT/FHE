# Snapshot provenance

Published as a new folder only. Destination repository baseline: `0f6068193b16bd526ca6cd4d75bf5fd6900cf494`.
Development baseline: `c577887`; this package also contains previously uncommitted
hardening work. It does not replace `prio3/`, `optimization/` or `optimbgv/`.

The saved measurement source manifest identifies the earlier pre-guard sources,
not the current package. `SHA256SUMS` identifies the current package. Historical
machine paths are provenance, not installation requirements. New test logs were
produced from the packaged paths, using OpenFHE 1.3.1 and two OpenMP threads.

The historical hardening plans are requirements/proposals, not security proofs.
Current status is in README.md and fhe-flp/OBLIVIOUS-STATUS.md. In particular,
no 64-bit noise-hiding certificate, full circuit-privacy proof or production
approval is claimed. Publication was explicitly requested after this limitation
was explained.
