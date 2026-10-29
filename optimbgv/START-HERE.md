# Start here: what this package does and how to reproduce it

This document assumes you have not read the conversation that produced this
repository. The goal is to compute statistics without giving the evaluator
individual plaintext measurements. It is a research implementation, not a
ready-to-deploy collection service.

## 1. The actors and the complete computation

The collector holds a secret decryption key. Clients use the matching public
key to encrypt reports. An evaluator checks and aggregates encrypted reports
without that secret key. Only the final intended aggregate is a protocol output.
The test harness also decrypts intermediate values to check correctness; those
diagnostics must not become messages released in a deployment.

The model assumes the evaluator follows the protocol and does not collude with
the collector. A collector with the full key can decrypt individual reports if
it obtains them. This package does not remove that trust assumption.

Every task follows this sequence:

1. Encode a measurement into designated plaintext slots and encrypt it.
2. Serialize and decode the report through the packed ciphertext codec.
3. Isolate authorized slots with evaluator-chosen masks.
4. Compute the task's valid contribution under encryption; invalid inputs must
   contribute zero to the entire task output.
5. Add contributions and serialize the final aggregate.
6. Decrypt and compare every expected output against a plaintext reference.

## 2. Terms used throughout the package

* **p=65,537** is the plaintext prime: all arithmetic is modulo p. It is not a
  security level. Integer aggregates need explicit no-wrap limits.
* **Ring dimension 32,768** determines the polynomial size. This profile has
  32,768 plaintext SIMD slots, arranged in two rows by the implementation.
* **SIMD** applies one encrypted operation to many slots. Slots can hold table
  entries or intermediate values, not just useful measurement coordinates.
* **Fermat equality** is delta_a(x)=1-(x-a)^65536. It is one if x=a and zero
  otherwise in this prime field. The power uses sixteen successive squarings.
* **Depth** is the longest chain of dependent multiplications, not their total
  number. Masks and output conversion can add depth beyond the Fermat exponent.
* **Rotation keys** enable encrypted slot movement; many rotations can create
  very large evaluator key sets. They are not client report bytes.

SIMD and Fermat are used together. Batching is compatible because
2*32,768=65,536 divides p-1. Every independent client still uploads its own
ciphertext report, even when that report has many unused slots.

## 3. Each task: encoding, logic, example and reason

### Count

The input is a binary event indicator. The contribution is delta_1(x): x=1
contributes one, x=0 contributes zero, and every other field value contributes
zero. For reports [0,1,2,1], the expected count is 2.

Why: Count needs only the number of ones. This projection computes that output
directly; it does not provide a separately exposed valid/invalid flag. Removing
unnecessary validity intermediates is therefore legitimate only under this
output contract, not automatically for other tasks.

Code: `count-openfhe142/fhe-prio3/src/verify.rs` implements the projection;
`count-openfhe142/fhe-paper-core/src/lib.rs` integrates it; the measured adapter is `full-cost142/src/bin/bgv_cost.rs`,
function `count`. The retained profile uses depth 18, seven HYBRID digits,
four groups and a qualified cap of 32 reports; the cost run has four reports.

### Bounded Sum with maximum 100

Upload x as a scalar. Compute F(x)=sum_{a=1}^{100} a*delta_a(x).
For [0,100,37,63], the sum is 200. An input 101 contributes zero.
The input zero also contributes zero, so no separate flag is needed for the
output. A SIMD table evaluates candidate values in parallel and reductions
combine their weighted equality indicators.

Why: this avoids validating seven separate encrypted bits and combining their
flags. The price is a lookup table, rotations and large evaluation keys.
Require 100N<65,537, where N is the accepted batch-size bound.

Code: `redesign-small-prime142/src/main.rs`; matched measurement adapter:
`full-cost142/src/bin/bgv_cost.rs`.

### Histogram with 3 or 8 buckets

Upload a bucket index b. Bucket a receives delta_a(b), for a=0,...,K-1.
With K=3, reports [0,2,2,1] produce [1,1,2]. Index 3 is invalid and
contributes [0,0,0]. Equality decoding creates a one-hot contribution for a
valid index, so a malicious field value cannot select two buckets through this
encoding. Require N<65,537.

Why: an index replaces the paper's uploaded one-hot vector and its extra
sum-to-one constraint. This changes the input representation; it is not the
same encrypted one-hot validation circuit. Table padding and output masks are
essential: unused slots must not create extra counts or disclosures.

Code: `redesign-small-prime142/src/bin/histogram_lookup.rs`; cost adapter:
`full-cost142/src/bin/bgv_cost.rs`.

### Binary SumVec of length 10, 25, 50 or 100

The output counts ones separately at every vector coordinate. Divide a report
into chunks of at most 13 bits. For example, bits [1,0,1] encode chunk value
1+0*2+1*4=5. A 13-bit chunk must lie in [0,8191]; a shorter final chunk has
its own smaller range.

For chunk h, V_h tests membership in its allowed range. D_(h,k) looks up its
k-th bit, returning zero if the chunk is invalid. Output coordinate (h,k) is

    D_(h,k)(z_h) * product_{j != h} V_j(z_j).

Why the product matters: if a later chunk is invalid, earlier valid chunks
must ALSO contribute zero. Merely decoding each chunk independently would
partially admit an invalid report and change the promised semantics.

Why use chunks: one lookup handles several bits while keeping the lookup range
within the SIMD table layout. Thirteen bits is the selected implementation
choice, not a proof of universal optimality. Longer vectors need more chunk
checks, deeper products and larger keys. This implementation emits one output
ciphertext per coordinate. Require N<65,537 for each coordinate's integer sum.

Code: `redesign-small-prime142/src/bin/vector_lookup.rs`; cost adapter:
`full-cost142/src/bin/bgv_cost.rs`. Detailed identities, slot handling and depth
derivations are in `redesign-small-prime142/FORMAL.md`.

## 4. What differs from the paper and the Boolean implementation?

Count retains its binary measurement. Sum, Histogram and SumVec use the new
scalar/index/chunk representations above, rather than the paper's original
weighted-bit/one-hot uploads. Their functionality is specified explicitly and
must be justified as alternative constructions in a paper.

The professor's measured Boolean circuit uses BinFHE STD128/GINX gates to check
its discrete Z4 messages, normalize bits, mask a report and run binary counters.
It does not run this Fermat equality circuit. Prio3 uses shared reports and
distributed proof verification, not encrypted Fermat evaluation. The compared
tasks share measurement/output semantics but have different representations
and trust assumptions.

## 5. Reproduce from a GitHub checkout

```sh
git clone --branch janak/fhe-prio3 https://github.com/JANAKDHOKRAT/FHE.git
cd FHE/optimbgv
python3 verify_package.py
```

That command verifies packaged hashes and recorded arithmetic/evidence. It
does NOT run encrypted circuits, rebuild the SDK or establish security.

For fresh encrypted execution, install Linux build tools, Python 3,
util-linux/taskset, Rust supporting edition 2024, and the shared OpenFHE 1.4.2
SDK. SDK headers, libraries and its CMake metadata must all be installed.
The SDK installation is an external prerequisite, not provided by this folder.
The pinned source revision and original host details are in
`full-cost142/evidence/environment.json`. Keep your own build settings.

```sh
export OPENFHE_DIR=/absolute/path/to/your/openfhe-install
bash build.sh
taskset -pc $$
# Select a CPU actually allowed by the preceding command.
export OPTIMBGV_CPU=0
bash run.sh /absolute/path/to/a-new-results-directory all
```

Replace the example paths and CPU with real values. Run from this folder. The
output directory must not exist. Run sequentially with ample RAM and disk;
reference peak process memory was about 7.78 GiB, and keys can exceed 7 GB.
Compilation and long-vector cases take time. Do not run concurrent cases.

The complete run covers 21 configurations. Boolean Sum/Histogram cells are
absent because supplied complete implementations are unavailable, not because
Boolean FHE cannot compute them. The runner stops on failure; keep that record.

## 6. How to judge a reproduction

Check each process exit code, final PASS, expected/actual outputs, reported
p/ring/depth/digits and loaded OpenFHE version. Read `.stderr` on failures.
Use `full-cost142/summarize.py NEW_RESULTS --complete` to validate a completed
matrix. Raw `.jsonl` and `.process.json` records retain measurements; compare
with `full-cost142/evidence/` and `full-cost142/RESULTS.md`.

Fresh randomness changes ciphertext contents. Timing and memory vary by machine;
the published figures are single observations, not guaranteed repeat values.
Do not suppress a failure or silently retune a profile to match the table.
The all-task cost run uses valid inputs; previous invalid-input tests are
separate evidence, retained with source and logs in the task folders.

## 7. What passing does not establish

Passing confirms finite correctness evidence and recorded accounting. It does
not certify arbitrary malicious ciphertexts, collector circuit privacy,
independent 128-bit security, truthful measurements, replay resistance or a
production deployment. Nominal library security checks remain enabled, but
independent screening findings remain relevant. No overall BGV performance
advantage over Prio3 or the Boolean vector implementation is established.

For the full cost boundaries, read `full-cost142/PROTOCOL.md`. For deeper proofs,
read `redesign-small-prime142/FORMAL.md`. Use the top-level scripts for this
package; historical scripts and REFERENCE-GUIDE.md retain old workspace paths.
