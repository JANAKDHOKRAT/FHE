# Comparison with the professor’s uploaded ZIP

This comparison uses files checked byte-for-byte against the uploaded ZIP.
It does not substitute new benchmark runs for the professor’s saved results.

## Three different paths in the ZIP

| Path | Plaintext/encoding choice | What the ZIP establishes |
|---|---|---|
| BGV sizing | Default p786433, provisional depth | Actual serialized report sizes and round trips; complete-circuit support is not established by sizing alone |
| BFV optimized sizing | p65537, task-specific depths18/21/22/22 | About6–7MiB candidate reports; bitness/Fermat/gating kernel tested, complete one-coordinate Count predicate; not full multi-task protocol qualification |
| BinFHE STD128/GINX | Boolean/bit-level construction, distinct encryption moduli; the functional validator tests messages in Z4 | Count input vector8245bytes; binary-vector validation/masking/addition diagnostics at lengths10/25/50/100, N4, and an honestly encrypted invalid-message check |

The p65537 BFV experiment and the small Boolean reports are separate experiments.
Boolean circuits use gates and integer adders rather than our prime-field Fermat
zero test. Their ciphertext and bootstrapping moduli are not interchangeable with
our plaintext p. Small input ciphertexts can coexist with large setup keys.

## What our work achieved

We also tested p65537. Projected exact BGV Count ran at ring32768/depth18 and
produced6176895-byte serialized reports (5.89MiB). The complete measured batches,
invalid-field-value cases and slot/masking checks passed. This is a genuine
correctness/size result; it is not a globally smallest secure profile certificate.

Independent lattice estimates using actual full QP showed model dependence:
that small profile was approximately97.24 bits of modeled work under ADPS16,
and130.24 under MATZOV for the checked primal-uSVP/dual-hybrid attacks. These
are heuristic attack costs, not an exact measured security level. The current
authentication path therefore refuses it under our more conservative criterion.

The separate authenticated BGV path uses p786433/ring65536/depth22/digits4 and
pins the screened QP fingerprint. Its actual framed report is16793800bytes
(16.02MiB). Four screened attack families gave minimum modeled costs143.664
under ADPS16 and175.434 under MATZOV. This assessment is not a complete proof,
does not cover every attack family, and must not be transferred to the professor’s
different BFV/BinFHE profiles merely because a plaintext prime matches.

We added strict client authentication, durable per-client attempt/replay control,
minimum/maximum batch policy, signed releases binding the actual report count
and ciphertext, and durable idempotent collector retries. Actual BGV tests,
eight-process replay contention, restart and abrupt-exit tests passed. These
are engineering improvements in our implementation, not inherent advantages
of BGV; equivalent wrappers could be added to the Boolean backend.

## Which is better?

- **Recorded input bytes:** the professor’s Boolean Count input is much smaller:
  8245bytes, before authentication/collection metadata, versus our16.02MiB framed
  report. Adding our small authentication envelope does not explain that large
  difference. We have not beaten Boolean FHE on Count upload size.
- **Arithmetic/SIMD structure:** BGV can perform the same arithmetic operation
  across many packed slots. The benefit depends on packing and workload. A single
  client report still contains a whole ciphertext; unused slots cost bytes.
  This is a reason to investigate throughput, not evidence that we already win.
- **Functional evidence:** the ZIP includes Boolean binary-vector computation
  diagnostics, not just ciphertext sizing. Its BFV optimization is explicitly a
  sizing/kernel study. Our BGV study adds complete-circuit batch qualification and
  repeated measurements. Different coverage is not proof one backend is superior.
- **Operational hardening:** our new wrapper adds tested replay/release controls.
  The ZIP itself lists nonce/task/replay wrapping as future work. This does not
  prove our whole cryptographic protocol is more secure.
- **Runtime:** no controlled speed winner is established. His saved run used M2Max,
  OpenFHE1.4.2, one timed batch and different timer boundaries. Our measurements
  used Xeon/OpenFHE1.3.1 and different repetitions/parameters. Matching L alone
  does not make those timing comparisons controlled.
- **Malicious-client and collector privacy guarantees:** neither the professor’s
  diagnostics nor our current implementation establishes arbitrary-ciphertext
  bounded-noise security and collector output-only privacy. Our production gate
  stays open. The user explicitly retained the honest-evaluator assumption.

Conclusion: smaller-prime arithmetic optimization is shared ground. Boolean FHE
currently has the clear recorded upload-size advantage. Our contribution is a
qualified arithmetic implementation, explicit parameter/model assessment and
operational hardening. No overall performance or security victory is demonstrated.

## Audit pointers inside the ZIP

- README.md, “Candidate report-size optimisation” and Boolean experiment sections.
- scripts/optimize_reports.py: BFV p65537 and task depths.
- fhe/report.cpp: arithmetic contexts, fully split batching guard and optional kernel.
- docs/boolean-input-experiment.md:8245-byte Count vector and separate setup costs.
- docs/binary-computation.md and fhe/boolean_benchmark.cpp: binary-vector computation.
- benchmarks/snapshots/2026-10-25/environment.json: hardware and timing limitations.
