# Native single-key implementation and seven-approach study

This is implemented encrypted computation, not a plaintext substitute. It is
not a production security certification, an exhaustive parameter optimization,
or a replacement for independent cryptographic review. The existing default
threshold path and all historical results remain available.

## Architecture and security contract

The explicitly selected native path uses OpenFHE 1.3.1 ordinary KeyGen,
EvalMultKeyGen, EvalAtIndexKeyGen and ordinary Decrypt with a complete collector
key. It does not perform partial decryption or fusion. No ring dimension is
forced, HEStd_128_classic remains enabled, and studies reject a generated ring
above 65536. The scaling method and secret distribution remain FLEXIBLEAUTOEXT
and uniform ternary. The different multiparty-mode setting is not an assertion
of equal threshold security: this path has one complete key and releases no
partial decryptions.

Native startup qualification generates throwaway ordinary keys and checks
metadata and coefficient identity, fresh byte-identical reconstruction,
ordinary decryption of original and rebuilt ciphertexts, subtraction to zero,
products, plaintext multiplication, additions, and squarings/rotations through
every requested level, across both rows. Success and failure are cached by
parameters/mode/depth. It is separate from threshold qualification: success in
one never supplies success in the other. A shared startup-test lock protects
OpenFHE's process-global evaluation-key tables. Context initialization, setup
and key installation must still be serialized by the application. This is
not a general thread-safe service framework.

For an invalid fixed plaintext encoding, randomized validation has ideal
per-attempt bound p^-t. The profile requires Q>=1 and a global target B>=128.
Selection uses integer arithmetic:

    k = floor(log2 p)
    q = ceil(log2 Q)
    t = ceil((B + q)/k)

Since p>=2^k and Q<=2^q, this conservatively guarantees Q*p^-t<=2^-B.
The study declares Q=1,000,000 and B=128; p=786433 selects eight repetitions.
This is stronger than simply reusing the historical seven-repetition setting
without accounting for attempts. The Q bound must be enforced by deployment
admission/key-lifetime accounting, which this library does not implement.
Computational challenge generation and FHE correctness errors are additional
assumptions; nominal 128-bit encryption is not a proof of this whole contract.

The evaluator/collector remain honest-but-curious and noncolluding. No proof of
arbitrary malicious-ciphertext robustness, collector output-only privacy,
malicious-evaluator integrity, replay admission, release policies or key custody
is supplied by passing these tests. Do not label the result Prio3-equivalent
malicious-client security or deploy it on that basis.

## Seven approaches and actual changes

1. Native setup/decryption is a separate opt-in API, not deletion of threshold
   checks. `PaperTask::new` retains the old path; `new_native` selects the new
   profile. Context mode/field/layout/capacity are checked before evaluation.
2. Task-specific profiles derive complete depth from the actual selected
   predicate and output transformation. The ring is library-selected; its
   realized row determines explicit native layouts. Threshold fixed-row
   validation remains strict. Profiles still cap depth at 28 and require one
   ciphertext per client report.
3. Deterministic prime checks, split-field compatibility, N<p and NM<p are
   checked. The probe examines 65537 and 786433 at five key-switching settings
   across five tasks and both modes. A 'selected' context is not a qualified
   encrypted circuit. Rejections and library security-estimation errors remain
   in the CSV; no failed estimate is bypassed with a forced ring.
4. Native binary SumVec uses A_T=identity and skips its redundant all-one
   weighting multiplication. Mandatory group-isolation and final output masks
   remain. The existing Fermat chain is already depth-optimal for a binary
   multiplication circuit: for e=p-1, depth is at least ceil(log2 e), attained
   by the chain at p=786433 (20) and p=65537 (16). This is a bound on the
   exponentiation circuit, not on every conceivable validity algorithm.
5. Randomized profiles expose packing groups explicitly and qualify first/last
   groups, duplicate-group flushes, outside-group and second-row injections.
   The study compares 32 and 16 groups for binary SumVec(100), and N=4 vs N=32.
   Each batch releases one aggregate; there is no hidden sub-batch disclosure.
   Neither server packing nor larger batches shrink a client's ciphertext.
6. Native key switching uses explicit digit settings. Evaluation keys are
   generated only for the layout's declared rotation indices and multiplication.
   Count digits 3 and 5 form a separate ablation. Smaller keys are not assumed
   to be faster, and '0' in historical threshold metadata means library default
   (three), not zero key-switch digits.
7. FPC1 already bit-packs residues. Its canonical parser, exact reconstruction,
   wrong-version/context/reserved/length refusals and out-of-group inputs are
   exercised; the wire format is unchanged. Measurements report header size,
   fixed-width coefficient bits and approximate generic-radix coding headroom.
   The last figure estimates coding overhead for arbitrary residue tuples,
   not ciphertext entropy, an achieved compression, or security. No novel
   compressed parser is introduced merely to claim a size win.

## Reproduce

Activate the pinned Linux OpenFHE 1.3.1 / Rust environment, including
OPENFHE_DIR, LD_LIBRARY_PATH, CARGO_TARGET_DIR and OMP_NUM_THREADS. Then:

```sh
cargo build --release --locked --manifest-path prio3/fhe-paper-core/Cargo.toml --bins
$CARGO_TARGET_DIR/release/native_profile_probe > parameter-selection.csv
python3 prio3/fhe-paper-core/study/native_matrix.py --out /absolute/new/directory
```

The output directory must be new. The runner compiles and fingerprints the
actual binaries and linked libraries, archives source, and qualifies each
profile using actual encrypted valid/invalid inputs. Qualification can use two
isolated processes; measurement is sequential, after qualification finishes.
Rejected profiles never receive successful timing rows. Any timed output
mismatch aborts rather than turning into an apparent optimization.

The matched Count controls use six batches in each of two fresh key processes.
Other rows use three batches in one fresh key process by default. These are
screening observations, not precise population performance estimates. There is
no controlled warm-up or affinity. Raw batch values and observed ranges are
reported; no CI over correlated within-key samples is claimed. Process peak
RSS includes all simulated roles. Key serialization, client encryption,
evaluator core, setup, collector and process wall time have separate metrics.

The Count comparison keeps p, exact predicate, layout and nominal encryption
security fixed. Randomized native rows use a declared global attempt budget;
historical seven-repetition timings cannot be presented as matched guarantees.
Any cross-host comparison to the professor's M2 Boolean measurements remains
uncontrolled. Native timing improvements do not establish production readiness,
minimal safe parameters, or an optimal point for every workload.

Timing boundary detail: `setup_ms` is the collector setup API invocation. Native
profile construction realizes a context before that invocation; the historical
constructor does not. Consequently that stage alone must not establish a total
setup speedup. Whole-process wall time includes profile planning for both.
Evaluator core excludes key installation/constructor costs in both paths; those
costs remain in wall time. Report and key byte comparisons are independent of
these timing boundaries.

Capacity limit: `max_batch()` is the arithmetic no-wrap bound, not a measured
noise-capacity certificate. This study exercises N=4 and N=32, not batches of
p-1 reports. Larger supported field sums still need complete noise-budget and
failure-probability analysis plus workload qualification. Arbitrary noisy
client ciphertexts remain outside the proven functional model. Repeated client
slot choices can also force extra verification flushes; deployment admission
and slot assignment must address this performance-abuse surface.
