# Encrypted-verdict aggregation: experimental, not production-qualified

The new `single::oblivious` module implements the uploaded plan's masking identity
using real OpenFHE BGV operations. Client encoding, FLP proofs, fields, and report
wire bytes are unchanged. The previous `single::Evaluator` and `SingleCollector`
remain a **verdict-revealing measurement baseline**, not a safe fast mode.
The new protocol has NOT replaced them as a production default: an honest-input phase range guard is now implemented, but the requested
noise-hiding and full circuit-privacy guarantees remain unproved.

## Implemented protocol

Let n be submitted reports, R the ring dimension, and L the output dimension.
All products and sums below are in F_p, with Prio's existing no-wrap batch bound.

1. Evaluator fixes a batch and its report ciphertext digests. For Select tasks,
   it keeps the pads already used on the selected support-check coefficients.
   For weighted Sum/SumVec, it makes one additional reduced output ciphertext
   per report, with independent pads on every coefficient. No two reports share
   an output ciphertext. Binary SumVec(max=1) is detected as a Select map by
   the existing output-map code, so it also reuses support pads and adds no
   output ciphertext. The plan's blanket classification of SumVec as Convolution
   was too broad.
2. Collector runs the existing FLP/support checks privately, obtaining v_i.
   It opens y_i = o_i + r_i and computes T = sum_i v_i y_i locally. It replies
   only with fresh encryptions of the verdict polynomial. The submitted count
   is public; the accepted count is not in the reply.
3. Evaluator multiplies each encrypted verdict polynomial by a plaintext mask
   polynomial, adds the products, independently masks all non-output coefficients,
   floods, and reduces. It sends E(U), where U = sum_i v_i r_i.
4. Collector returns decode(T-U) locally. There is no evaluator result API.
   This is not enforcement against an operator voluntarily sharing its result.

### Why the block packing works

Use B=floor(R/L) verdicts per ciphertext and ceil(n/B) ciphertexts. Require
1 <= L <= R and n>0. In a block put v_i at coefficient iL. For c in [0,L), put
r_i[c] at exponent c-iL in P. If the exponent is negative, store -r_i[c] at
R+c-iL, since X^R=-1. The intervals for different i have no overlapping residues
because the total occupied interval has length BL<=R. Thus coefficient c of VP
is exactly sum_i v_i r_i[c]. Add block results at the SAME c positions.
This explains why ceil(nL/R) was incorrect for this layout: R=8192,L=100,n=163
requires three whole-block ciphertexts, not two.

The masking identity is exact: T-U = sum_i v_i(o_i+r_i)-sum_i v_i r_i = sum_i v_i o_i.
It does not authenticate the evaluator's computations.

### What the privacy argument does and does not establish

With independent ideal uniform masks, y_i is an output-domain one-time pad.
Given all y_i, the verdicts and S, U is determined by U=sum_i v_i y_i-S.
The implementation expands fresh OsRng seeds with XofTurboShake128; its masking
claim is computational, not perfect information-theoretic uniformity.
The evaluator receives RLWE ciphertexts of verdicts, not plaintext verdicts.
Fixed reply length is tested across differing accepted counts.

This plaintext argument does NOT establish ciphertext circuit privacy, a
worst-case flooding bound, negligible decryption failure, constant-time behavior,
or resistance to adaptive malformed ciphertexts. Existing `finish` flooding is
reused; observed successful decryption does not qualify it. No library security
setting substitutes for these proofs. Timing and deployment error channels are
not covered. A malicious evaluator can still substitute E(U), forge query
computations, omit reports or introduce Sybils. Those were outside the retained
honest-evaluator model and remain outside the guarantee here.

## Durable state and its operational contract

Requests contain protocol version, a task/key binding, a fresh batch ID,
submitted count, and ordered ciphertext digests. The task binding includes
public-key evaluation-form CRT residues, moduli, dimensions, output map,
proof count, task ID and the pinned prio 0.18.1 task Debug representation.
This is a VERSION-SPECIFIC wire contract; portable canonical task serialization
is still needed before supporting upgrades/multiple implementations. Clients and
evaluators must use the same immutable task configuration. The request metadata
is not a signature and does not prove correspondence to the ciphertexts against
a malicious evaluator.

The collector requires an existing trusted local ledger directory. It reserves
batch and report IDs using exclusive file creation, fsyncs each file and the
directory, and does so before opening request ciphertexts. Release is separately
reserved before final decryption. Reopening with `with_keys` and the same key and
ledger refuses the same batch and freshly randomized checks of the same canonical
report ciphertext. Replay under a different task/key, re-encryption, Sybils and
attacker-relabelled digests are not prevented. No authenticated client identity
is implied.

Crashes burn pending batches; they cannot resume, and partially reserved report
sets may be unavailable. This sacrifices availability to prevent reopening.
The local filesystem must honor atomic create-new and fsync. The operator must
protect key storage, all ledger path ancestors, retention and rollback protection;
network-filesystem semantics are not qualified. No automatic eviction exists.
This is not a distributed transactional service or an externally audited keystore.
Do not delete the ledger while the corresponding key can be used.

## Qualification and measurements

The tests cover both fields and all eight requested configurations, invalid
plaintexts, a fully poisoned report, three-block packing, all-rejected batches,
fixed reply sizes, exact replay, rerandomized request replay after key restoration,
a separate OS-process exit/recovery test with saved keys and pending batch,
wrong task/batch, truncated messages, overflow counts, a crafted-query batch of
100 reports, and one reflected encrypted-verdict example. They use actual keys,
FLP proofs, ciphertexts and decryption. The old attack demonstrations remain.

A constant-guess statistic on 100 samples is diagnostic only. Uniformity tests
cannot prove mask privacy; repeated random mask values are allowed. No assertion
claims that every doubled ciphertext must trip a gate: centered phases can wrap.
A universal T5 detection claim remains unsupported. An honest-input range
bound and persistent failure guard are implemented; privacy and reaction-leak
analysis remain incomplete. Unit tests are not security proofs.

Matched measurement commands and raw results are under `results/oblivious/`.
The benchmark reuses the same release binaries, library, machine and thread
configuration for both protocols. It measures one run, not a throughput SLA.
Collector check time includes verdict encryption; these stages are not separately
instrumented. Failures and resource refusals are retained. The saved measurement matrix predates the phase guard and does not measure
its overhead. Current source does implement the guard.

Expected wire changes before measurement: unchanged client reports; 32 digest
bytes per submitted report plus 68 additional check-header bytes; Select adds no
output ciphertext, Convolution adds one reduced ciphertext per report; reply
is 72 bytes plus ceil(n/floor(R/L)) fresh ciphertexts; final is 72 bytes plus one
reduced ciphertext (64 more header bytes than the baseline).

## Release decision

Production gate NOT GREEN. The user authorized publication of this separate
research folder with limitations recorded. Correctness tests do not certify
noise hiding, circuit privacy, arbitrary-ciphertext security or deployment safety.
See the package README and validation logs for current test evidence.

The historical pre-guard matrix contains 96 runs: 94 successes and two unsupported
Sum100/p65537/N1024 runs. Guard-inclusive full measurements remain outstanding.
