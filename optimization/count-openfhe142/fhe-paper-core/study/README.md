# Controlled complete-circuit parameter study

This is a research qualification harness, not a production-security certification.
It runs actual OpenFHE encryption, validation, masking, aggregation and collector
decryption. It never substitutes plaintext timings, synthetic key sizes, or a
smaller forced ring for a failed security check. Existing production contexts and
historic results are untouched.

## First experiment: Count exact, one setting changed

Compare three configurations: retained `NOISE_FLOODING_MULTIPARTY`; omission of
that setting (OpenFHE 1.3.1 defaults to `FIXED_NOISE_MULTIPARTY`); and omission
plus one extra context level to satisfy the unchanged threshold rebuild guard.
All retain
`HEStd_128_classic`, p=786433, the complete exact circuit, the existing packing,
FLEXIBLEAUTOEXT, and **the existing one-party threshold key-generation path**.
The candidate is not a native single-key implementation. OpenFHE documents
flooding as the stronger multiparty mode. Retaining an encryption-security label
is not a proof of equal protocol security; never deploy the candidate in a
threshold system on the strength of this study. Neither mode establishes
collector output-only privacy or arbitrary-malformed-ciphertext security here.

Each build is copied into a fresh result directory with a file-hash inventory.
The experimental source edits are removal of one exact, uniquely matched
mode assignment and, for the headroom profile only, adding one requested context
level. The application circuit depth is unchanged; the additional capacity is
recorded and paid for. Failure to match either assignment aborts. Build targets and processes are isolated
because OpenFHE caches context/evaluation keys globally. No secret keys are
written by the study.

Before timing, each candidate must pass `study_count`: honest 0/1 inputs, values
2, p-1 and floor(p/2), the last packing group, cross-group slot contamination,
and repeated-group flushing. The decrypted result must be exactly 4 over eight
submitted reports (invalid reports are masked, not removed from metadata count).
This qualifies that finite test set, not all possible invalid inputs.

Then two independent key setups per profile process six timed four-report
batches each. Profile order reverses on alternate rounds. Each result is checked
against plaintext expectations by the existing measurement binary. Raw samples,
all evaluator rotation and multiplication key bytes, public key bytes, setup,
process peak RSS, component timings, wall time, realized parameters, binary and
linked-library hashes are retained. Client report serialization is included as
its own size metric. Process peak RSS covers all simulated roles, not evaluator
memory alone. Timing excludes network and has no warm-up; within-key batches
are correlated. Report per-setup observations/ranges; do not interpret the
existing binary's nominal median CI as evidence of independent samples.

## Run (Linux, pinned OpenFHE 1.3.1 and configured Rust)

Activate the environment used to build the retained paper-core implementation:
`OPENFHE_DIR`, library search path, Cargo/Rust paths, and `OMP_NUM_THREADS`.
Then from any directory:

```sh
python3 /path/to/FHE/prio3/fhe-paper-core/study/run.py \
  --out /absolute/new/result-directory --processes 2 --batches 6 --full-suite
```

Output directories must not exist; historical results are never overwritten.
Each command has a 2400-second timeout; timeout/interruption kills its process
group and records failure. A failed qualification rejects that profile: it is never benchmarked and
has no cost result. Other profiles continue. `completed_with_rejections` means
some profiles failed, not that every candidate passed. Command failures during
measurement abort the study. Inspect `manifest.json`, not process exit alone.

`--full-suite` additionally runs existing complete encrypted Histogram exact,
bounded Sum randomized, and SumVec exact adversarial-encoding tests per profile.
That is broader correctness coverage, not full performance coverage of those
tasks. The default experiment measures only Count exact. A failed candidate is
an experimental result; it must not be repaired by disabling security checks.

## Further stages, not claimed completed

* Native single-key generation/relinearization/rotation setup and scoped
  collector privacy analysis.
* Derive smaller-field profiles with matching global Q*p^-t soundness targets,
  aggregate bounds, full slot-layout support and complete depth accounting.
* Expand each workload/mode's boundary and invalid-input qualification before
  measuring a full workload matrix. Do not infer these from Count.
* Independent process/key repetitions, warm-up, larger batches and packing
  sweeps, controlled host load, and matched Boolean/Prio3 measurements.
* Independent security assessment, ciphertext admission/parser analysis, key
  custody, authentication/replay/release controls before production use.

After completion, run `python3 study/summarize.py /absolute/result-directory`
from the crate directory. It refuses unfinished studies and altered logs or
measurement JSON; it checks each timed batch has a verified-output record.
The generated table uses ranges across key setups, not nominal confidence
intervals over correlated within-key batches.

## Interpreting a startup rejection

The retained packed-wire self-test uses throwaway two-party threshold keys even
in this one-collector application. A default-mode failure there is a finding
about compatibility of this complete stack, not a proof that native single-key
BGV requires flooding. A wrong decrypted self-test value does not by itself
isolate ciphertext rebuilding, fusion, parameters, or the library as the cause.
Do not disable this test to obtain a smaller report. Diagnose and qualify an
appropriate single-key path separately.
