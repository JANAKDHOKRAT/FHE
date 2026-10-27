# Experimental Count optimization: contract and proof

Later update: [HARDENING.md](HARDENING.md) records the separate authenticated Count path and independent parameter screening. This document describes the retained raw-core experiment; its historical results have not been rewritten.

This folder is a separate research copy. `prio3/` remains the baseline. Native
Count projection is opt-in; its default is false. It is refused for every other
task and for randomized validation. No 50% saving is assumed.

## Observable functionality

For admitted plaintext values x_i in F_p, output sum_i [x_i=1], with N<p.
Valid zero contributes zero, valid one contributes one, and every other field
value contributes zero. The admission count is not the valid-report count.
No validity flag is exposed. Authentication, participation quotas, replay
protection and minimum-size release are absent, as in the paper-core baseline.

## Exact equivalence

Let P(x)=x(1-(x(x-1))^(p-1)) and R(x)=1-(x-1)^(p-1).
For x=0, P=R=0. For x=1, P=R=1. For x outside {0,1},
x(x-1) and x-1 are nonzero. Fermat's theorem in the prime field gives
both powers equal to one, hence P=R=0. These three disjoint cases exhaust F_p.
This is an equality of aggregate contributions, not of validity predicates.

## Isolation and depth

Each report is masked to its authorized scalar slot before addition. Reusing a
group flushes pending contributions before the new value is admitted, preventing
cross-report cancellation before projection. R(0)=0, so unused slots stay zero.
Group folding is unchanged, as is the final mask retaining only output slot 0.
For e=p-1 the implemented left-to-right exponent has depth
floor(log2(e))+popcount(e)-1. Total projection depth is this plus two:
one admission-mask multiplication and one final output-mask multiplication.
Subtraction, addition and rotation consume no multiplicative levels. The old
circuit additionally needs bitness multiplication and contribution gating.
No claim about noise correctness follows solely from this depth count.

## Security and limits

Collector holds one full secret key. Evaluator is honest-but-curious and must
not collude with collector. Ordinary OpenFHE BGV single-key setup uses the
library's HEStd_128_classic selection, with no forced ring or security bypass.
Record Q and auxiliary QP, actual key-switch parts and secret distribution.
Library selection is not an independent lattice-security proof. Encryption
correctness is required for the field proof to apply. Whole-domain equivalence
does not prove security for arbitrary ciphertexts lacking an honest plaintext
interpretation, nor circuit privacy. No malicious-evaluator integrity, output
provenance or authorized-release proof is provided. A malicious collector already
has a key capable of decrypting individual reports if it obtains them.

Operational qualification is bounded to 32 admitted reports, with 33rd refused;
this is not a certificate for every arithmetically possible N<p. Measurements
must declare their exact batch sizes, packing, keys, and fresh-key repetitions.
Concurrency/DoS and network authentication require a deployment layer; do not
invent a service-security pass from this local measurement harness.

## Why the measured saving exceeds half

At matched G=4/N=4, the old packed wire uses n=65536 and 1113 stored
residue bits per coefficient across its Q chain. The small-ring projection uses
n=32768 and 754 bits. The unchanged wire format has a 56-byte header and two
ciphertext components. The measured message envelope adds 71 bytes in these
runs. Thus full serialized sizes are exactly:

- Baseline: 127 + 2*65536*1113/8 = 18,235,519 bytes.
- Small ring: 127 + 2*32768*754/8 = 6,176,895 bytes.

This is a measured parameter/circuit saving, not new compression or fewer
uploaded reports. It does not establish a globally minimal secure profile.
The same-ring projection is an alternative Pareto point with lower evaluation
key bytes; the small-ring option requires seven key-switch digits and increases
total evaluation-key bytes at G=4. All claims are Count-only, N<=32, and under
the stated encryption-correctness and trust assumptions.
