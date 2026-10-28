# Full cost protocol, declared before measurements

Primary requested case: binary SumVec length 100. Harness also supports lengths
10,25,50, Count, bounded Sum(100), Histogram(3,8). The supplied professor Boolean
implementation covers binary vectors/Count; do not invent professor Sum/Histogram
results where no complete validator is provided.

One fresh process, one fresh key setup and one batch of four valid reports per
configuration, serial execution, same host, CPU0, one thread. This is a full-cost
diagnostic run, NOT a throughput distribution, confidence interval or production
reliability proof. No parameter/security/encoding/circuit changes to make a result
look better. BGV remains p=65,537, ring 32,768 and its already qualified task-specific
depth/decomposition. Professor remains STD128/GINX with original gates/counter.
Prio3 is the same pinned 0.18.1-alpha.3 reference, two aggregators executed serially.

Binary value at client i, coordinate j is
(17*i + 31*j + floor(j/3) + floor(i*j/7)) mod 2.
Count uses j=0; Sum values are [0,100,37,63]; histogram bucket is i mod K.
All backends use these same measurement/output semantics. Encoding differs and
is recorded. No artificial invalid reports or diagnostic decryptions in core time;
the original variants already have separate invalid-input qualification evidence.

Setup includes parameters, mandatory native startup qualification for BGV,
key generation, sizing/serialization of ALL setup material, installing keys,
plaintext constants and codec construction. Report setup components separately
where possible. Retain qualification; it is not free. Evaluation starts with
keys loaded in every backend; do not reload keys per batch in only one backend.
Large BGV rotation-key sizing uses one-index messages to bound temporary buffers.

Client time includes encoding, encryption/proof generation and actual object
serialization. Server core includes input deserialization, validation/masking,
aggregation and final output serialization. Prio3 includes both aggregation
roles and serialized verifier-share/message round trips through their actual
decoders (but no network delay). Collector time includes output deserialization,
decryption/unsharding and task decoding. Check expected output after timing.
Full-slot/flag test diagnostics are separate; whole-process measurements include
them and setup. Progress logging is outside core substage timers and recorded.

Record both raw serialized cryptographic objects and the actual prototype output
bundle consumed by the collector. Count every BGV vector output ciphertext and
its exact bytes; never infer bytes by multiplying an unrelated Count profile.
Prio3's two output shares are distinct collector messages; report their sum.
Report nonce/duplicated public-share metadata separately for Prio3. These are
prototype/core formats, not full DAP/HPKE/TLS/release-wrapper costs.

Measure process wall, CPU time and OS peak RSS with a single-child Python wrapper.
Whole-process RSS includes all simulated roles; do not label it isolated server
memory. Timed stage sums exclude cleanup/diagnostics and are not network
end-to-end latency. No other owned benchmark/build runs during timed cases.

Keep all refusals/failures and source hashes. A process is successful only if its
final verified result record exists AND exit code is zero. Smaller parameters
with failed output are not a result. Claims remain within the paper's trust model;
these tests do not prove independent 128-bit security, malformed-ciphertext
security, collector circuit privacy, administrative savings or a deployment win.
