# Small-prime encoding redesign — isolated research implementation

Use RESULTS.md for the actual encrypted outcomes and FORMAL.md for the ideal
field identities and the complete depth derivations. These are new encodings,
not silent changes to the retained paper-core task encodings.

The Rust executables implement exact bounded Sum(100), Histogram(3,8), and
binary SumVec(10,25,50,100). They use the unchanged OpenFHE 1.4.2 wrapper and
packed report codec in the preserved count-openfhe142 directory. No original
file, guard or library security setting is modified. They are circuit/evidence
executables, not a deployable DAP endpoint or a production-security certification.

The test harness owns known inputs and the secret key so that it can check
EVERY output slot for each evaluated report and for the final aggregate. Those
individual-report decryptions are test diagnostics, not protocol messages.
In the intended paper architecture only the final task aggregate goes to the
collector. Intermediate membership flags are not decrypted or released.

## Reproduce

The existing SDK and dependency environment are required. The evidence machine
has a 32 GiB memory limit. Rotation keys are large, and these tests can take
many minutes. Run the script sequentially to bound concurrent memory demand.

```sh
bash /workspace/FHE/optimization/redesign-small-prime142/build.sh
bash /workspace/FHE/optimization/redesign-small-prime142/run.sh /workspace/fhe-validation/redesign-reproduction
```

Each task checks serialized encrypted uploads, masks unauthorized slots,
executes its validity/output circuit, serializes evaluated outputs, decrypts
them, and compares all slots against an integer oracle. Outputs repeat only the
intended scalar or coordinate across the first row and zero the second row.
Sum and Histogram retain one output ciphertext; SumVec currently emits one
ciphertext per coordinate. Server computation, rotation keys and collector
traffic are therefore essential costs; smaller uploads alone are not a win.

The current experiments use local in-process roles and fixed test task IDs.
They do not implement network admission, authentication, replay prevention,
an interoperable task-negotiation format, key lifecycle or an aggregate-release
policy. The inherited arbitrary-malicious-ciphertext and circuit-privacy
questions remain open. The named HEStd_128_classic criterion is retained;
independent parameter screening is not replaced by that label.

## Earlier candidates retained for review

probe.cpp and probe-boundary.cpp inspect alternative key switching/scaling
families and retain refusals. complete.cpp is an earlier binary-coordinate
redesign with BV switching. It passed its SumVec(10) subtask, then the test
process failed at Histogram for a missing rotation key. It is not the qualified
Histogram implementation; histogram_lookup is. The first BV digit-size-4
attempt ended with exit 137 near the resource limit and has no circuit pass.
Neither C++ candidate is used by the primary build/run scripts. Their native
serialization sizes must not be mixed with the packed Rust report sizes.

An initial Sum run correctly refused unqualified ciphertext rebuilding. The
primary Rust code calls native startup qualification, retaining that guard.
An early vector run was stopped during startup to fix its rotation-key plan;
the corrected program composes arbitrary small shifts from generated binary
rotation indices. All abandoned and failed attempts are retained as such.
