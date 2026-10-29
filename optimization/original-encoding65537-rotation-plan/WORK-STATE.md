# Original-encoding research: current state

User requires original measurement encodings, p65537, ring32768, retained nominal
library security target, no fabricated success. Unused slots must be IGNORED,
not constrained: user explicitly confirmed this. No new results are committed or
pushed; old optimbgv and previous studies remain unchanged.

Completed encrypted finite five-report runs in evidence/:
- low-count-1: report5578879, eval199258085 (mult only)
- low-histogram-3: report5881983, eval660697159
- low-sumvec-10: report6652031, eval795981403
- low-sum-7 (Sum100 weighted bits): report6340735, eval726766219
- vector-25: report7086207, eval2219081020
- vector-50: report7389311, eval4228417619
All keep original encodings and have smaller evaluator key sets than the
selected lookup baseline. Report bytes can be larger. These are finite functional
observations, not production certification or matched runtime benchmarks.
Histogram8's previous HYBRID22/unit-rotation pass is preserved in
../original-encoding65537-revisit/evidence/histogram-full-digits.jsonl:
report6488191, eval795981379. It was not rerun in this directory.

Stock-library length100 candidate remains refused. A separate OpenFHE1.4.2 fork
was made at /workspace/fhe-deps/openfhe-bound-prime-study, installed at
/workspace/fhe-deps/install-bound-prime-study. Only BV/FLEXIBLEAUTOEXT prime
selection was changed to select just above the SAME numerical lower bounds,
instead of powers of two. ALL ring/security checks remain enabled. Actual primes
were independently checked against rational upper bounds. See prime-diagnostic/.
The fork is built with OpenMP; original SDK/source are untouched. Do not install
over or modify a running shared library.

Length100 custom parameters: depth23, BVdigit8, pre-multiplication add budget1,
key-switch budget7, uniform ternary, default sigma/alpha. Standard check accepts
actual881-bit Q. Four-report mixed/zero/one/tail-invalid test, poisoned unused slots
and second row. Three rotation keys [1,8,-11]. Five indicator centers
[0,66,-67,-63,70], with at most six post-indicator rotations, plus preceding
relinearization = seven switches. Pre-indicator rotations are spread over the
16 squaring stages, at most7 initially and6 after preceding relinearization.
Every used shift in [-99,99] is covered. Canonical window construction requires
at most six rotations at a level; it uses UNROTATED canonical operands, not
post-rotated cached windows. D plus all-other membership products remains exact.

ACTIVE final length100 executable:
/workspace/fhe-validation/bound-prime-vector100-shared
Source: prime-diagnostic/vector100-shared-windows.cpp
Logs: prime-diagnostic/vector100-shared.jsonl/.stderr/.process.json
Unified exec session31627. Launched16:45UTC (approx), OMPthreads3.
Fixtures (public synthetic only; no SK):
/workspace/fhe-validation/original-rotation100-shared-fixtures-20261029
Final result is NOT established until final EXPLORATORY_TASK_PASS + zero process
exit, four REPORT_PASS records, all full-slot checks, aggregate and wire roundtrip.
Slot-check count includes5 indicator centers +100 contributions +2 report checks
per report, then2 aggregate checks =4*107+2=430.

Earlier length100 schedules were intentionally stopped INCOMPLETE for repeated
exponent/window work, not claimed as passes. Their sources, partial logs, process
exit records and status explanations are retained. Initial prime-selection fork
build warning and bad NextPrime seed-alignment attempt are retained too; both
were fixed before the active run. Do not count any partial schedule as a task pass.

Key budget for active parameters was already measured in the superseded run:
rotation4797859683 + mult1599286553 =6397146236, below lookup7429158368.
The active executable RE-MEASURES and enforces this before evaluation. Actual
report/output bytes must come from its final record/fixtures, not extrapolation.

Remaining work: finish active length100; record failures if any; verify mathematical
rotation/window schedules and actual prime bounds; collect actual metrics and
primal-only independent screens; write final README/results/reproduction scripts,
source/binary/dependency provenance, hashes and finite-evidence verifier. Verify
previous folders unchanged. No automatic publish to optimbgv or GitHub.

Security caveats remain: no arbitrary-malicious-ciphertext robustness, collector
circuit privacy, negligible noise-failure theorem, production service or complete
independent128-bit assessment. EvalAddCount is a pre-multiplication planning
budget; terminal additions have finite correctness evidence, not a full failure
bound. ADPS16>=128 is NOT the user's paper admission rule but failures must be
disclosed. Patched SDK must be labelled distinctly. Timing overlapped compilation,
other diagnostics and tests: do not claim controlled runtime comparisons.

## Active run update16:59UTC
The FINAL selected100 source is prime-diagnostic/vector100-late-shared.cpp,
binary /workspace/fhe-validation/bound-prime-vector100-late. It shares the first
13 of16 power stages across the5 centers, then applies at most6 rotations per
remaining stage followed by squaring. Budget7 includes preceding relinearization.
It retains canonical window sharing and wire/fixture checks. Earlier schedules
were preserved as intentionally incomplete, not cryptographic failure or pass.
ACTIVE logs: prime-diagnostic/vector100-late.jsonl/.stderr/.process.json.
Fixtures: /workspace/fhe-validation/original-rotation100-late-fixtures-20261029
OMP3, fork SDK only, full4-report test. Do not restart for further optional tuning.
All smaller workloads now passed, including improved Sum100 eval726766219.

## Reproduction review 2026-10-29T17:32:22.436015+00:00
Stock and research build.sh modes compiled successfully; rebuilt context matches retained actual q exactly. Original SDK clean; fork diff equals saved patch. Published optimbgv unchanged. Seven selected cases completed, including retained prior Histogram8.
Active100 native session13243 PID26505, watch session92204. At snapshot 1 complete report(s), 109 successful full-slot checks. No final all-task pass yet.
finalize_evidence.py watch waits for native child returncode0 and EXPLORATORY_TASK_PASS, then runs unchanged Rust inspector with --require-aggregate, requires summarize.py --require-all, and writes evidence/qualification.json, public-fixtures.json and RESULTS.md. Production gate stays NOT GREEN; no commit or push. Do not restart FHE for optional tuning.

## Background continuation 2026-10-29T17:42:38.903762+00:00
Native FHE remains session13243, PID26505. Final evidence watcher is now session72577 (replaces earlier watcher only, not FHE run). Completed reports=1, full-slot checks=143. Native log still lacks final pass; no production or128-bit certification.
New docs README.md, REPRODUCE.md; build.sh stock/research both compile. summarize.py validates selected raw logs, exits, exact size formula, actual published baseline byte references and hashes; --require-all refuses pending100. Reference uploads50=6496383 and100=6815871, not universal6176895. Count reference packs4 groups; new Count per-report evaluates separately.
Watcher finishes native qualification, independently parses aggregate via unchanged Rust inspector, generates evidence/qualification.json, evidence/public-fixtures.json and RESULTS.md. Recheck those files; do not infer success merely from this progress snapshot. Published optimbgv untouched; no commit/push.
