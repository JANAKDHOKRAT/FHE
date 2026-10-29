# Original encodings and exact contribution circuits

The plaintext field is F_65537 and ring dimension is32768. Fully split batching
is compatible because2n=p-1. Measurement coordinates remain the paper's bits
(Sum uses weights1,2,4,8,16,32,37), one-hot histogram vectors, or binary vectors.
No scalar, bucket-index or13-bit chunk upload is substituted in these candidates.

Define Z(x)=1-x^65536, D(x)=1-(x-1)^65536, A(x)=Z(x)+D(x).
Fermat proves Z is the indicator of0, D of1, and A of membership in{0,1}, for
EVERY field element. It is not an assumption that clients submit honest bits.
For a binary-coordinate task, contribution k is

    Y_k = D(x_k) product_(j != k) A(x_j).

All bits valid: A_j=1 and D_k=x_k. Some coordinate j nonbinary: D_j=A_j=0,
so its own output vanishes and every other output includes A_j=0. Thus the
whole report contributes zero. Sum applies the original weights to Y and sums;
Count uses D alone. This preserves the aggregate contribution, not a separately
exposed validity flag.

For a one-hot histogram use Y_k=D(x_k) product_(j != k) Z(x_j).
It is one exactly when coordinate k is1 and every other coordinate is0. Every
other field-valued input produces the zero vector. This enforces the one-hot
condition without substituting an index encoding.

Equivalence to the paper's bitness-plus-sum-equals-one field predicate also
uses K<p. Once bitness holds, the integer sum lies in[0,K]; with K<p its
residue is1 exactly when that integer sum is1. Both supported histograms,
K=3 and K=8, satisfy this constraint. Without it, p+1 ones could pass a
modular sum-equals-one test while failing actual one-hot membership. No
equivalence for arbitrary unbounded histogram dimensions is claimed here.

## Selected coordinates and depth

A normal supported plaintext mask selects D's own coordinate (and Sum's weight).
D starts at level16, selected D at17, other Z/A factors at16. A balanced product
of the actual factors, without rounding the report length up, requires
16+ceil(log2(K+1)). This gives17,18,19,20,20,21,22,23 for Count,Histogram3,
Sum7bits,Histogram8,Vec10,Vec25,Vec50,Vec100 respectively.

The mask is applied BEFORE combining other-coordinate factors. Outside its
selected coordinate it is identically zero. At that coordinate every aligned
factor reads an authorized coordinate j. The complete output consequently
ignores all other slots, including arbitrary values in padding and row two.
These are field-function statements, conditional on correct FHE evaluation.
All finite encrypted tests poison unused slots deliberately.

No modular wrap: Count/Histogram/binary-vector batches require N<p; Sum100
requires100N<p. These experiments use N5, and the custom100 test uses N4.
This does not qualify maximum batch sizes or a streaming admission service.

## Rotation plans on the stock SDK

BV20/Vec25 uses [1,8,-8]. Every required shift in[-24,24] has a checked path
of at most10 rotations. Budget11 includes the preceding relinearization.
BV20/Vec50 uses[-16,-4,-1,1,4,16], with at most6 rotations; budget7.
These plans trade extra operations for fewer stored keys. They do not assert a
runtime win. Other small tasks use HYBRID, one digit per Q tower, and unit
rotations; Count requires no rotation key.

## Length100: timing rotations and sharing windows

The custom experiment uses three rotation keys[1,8,-11], BVdigit8 and budget7.
Five centers [0,66,-67,-63,70] cover every required offset[-99,99] within six
post-indicator rotations. This is a finite checked integer graph, not a guess.
The code asserts coverage before encrypting test reports.

To obtain A(x shifted by c), distribute that center's rotation path through
the16 squaring stages. At level0 at most7 rotations precede the first square;
at later levels at most6 follow the preceding relinearization. Therefore each
path has at most7 key switches per level. Automorphisms commute with squaring,
addition and the uniform constant1, so interleaving rotations computes exactly
the same shifted Z and D, without changing client encoding or exponent.

At center c define canonical windows

    P_(0,c)=A(x shifted by c)
    P_(r,c)=P_(r-1,c) * rotate(P_(r-1,c),2^(r-1)).

It is the product of2^r consecutive membership indicators. The required
canonical shifts1,2,4,8,16,32 each use at most6 rotations in the checked key
graph. The code builds these windows ONLY from unshifted canonical operands.
It never stacks a canonical shift on an already post-rotated operand. A finished
canonical window can then be shifted through the six-edge cover tree. Including
its preceding relinearization, the same7-switch budget holds. Shifted windows
are cached and reused, rather than rebuilt from all their leaves.

For coordinate k, decompose [-k,-1] and [1,K-1-k] into dyadic windows, align
them to k, and multiply with selected D_k. The intervals contain exactly the
other K-1 application coordinates, once each. They never include unauthorized
slots in a selected output. check_math.py checks this for every supported K,k.

## What the prime-selector patch does

OpenFHE1.4.2 normally rounds a computed modulus lower bound to a bit size, then
starts at a power of two when searching for an NTT prime. The isolated research
fork selects a prime just above the same numerical bound, aligned to1 mod2n.
The Gaussian/noise formulas, secret distribution, assurance parameter and every
HE-standard ring check are unchanged. The patch applies only to BV/FLEXIBLEAUTOEXT.
All old source/installations are preserved.

Floating-point selection uses an upward margin. An INDEPENDENT rational checker
encloses sqrt(n) with128-bit rational endpoints and verifies every ACTUAL q_i
above the corresponding upstream bound. It checks distinct primes, q_i!=p,
2n|(q_i-1), sigma,alpha36, thresholdParties1, and actual product bit length.
The context also passes the unchanged standard check and a direct second table
lookup. No ciphertext scale metadata is manually relabelled.

These checks preserve the library's stated NUMERICAL planning bounds. They do
not prove those estimates are a complete negligible-failure theorem for the
whole circuit or its terminal additions. That remains a separate requirement.
The fork must be labelled as modified parameter-generation code, not an unchanged
upstream build. OpenMP and concurrent diagnostics also preclude treating these
elapsed times as matched performance benchmarks.

## Scope of the proofs and tests

The reduced polynomial for a binary-vector contribution has nonzero top
coefficient -(-2)^(K-1), with total degree K(p-1). Ordinary fan-in-two exact
arithmetic circuits therefore need multiplication depth at least
16+ceil(log2 K). This does not cover bootstrapping or changed protocols and is
not a global impossibility theorem for FHE. The non-power-of-two vector schedules
above attain that arithmetic lower bound while including the selection mask.
It does not prove optimal modulus, keys, runtime or memory.

FHE security and honest encryption are separate from these field identities.
The experiments use genuine public-key encryptions of valid and invalid field
values. They do not prove safety for arbitrary malformed ciphertexts, collector
circuit privacy or128-bit security under every independent attack model.
Nominal library acceptance is retained, not promoted to a security proof.

## Final shared-power schedule

The selected100 implementation shares powers through stage14. Its recorded
maximum center path has12 steps, fitting two groups of at most6 rotations. Each group follows the
previous relinearization and precedes one squaring, so7 is still the maximum
key-switch count at that level. The total exponent remains2^16. The root0
indicator follows the same shared powers without rotations. No plaintext
subtraction is moved across squaring: (x-1) is formed BEFORE the shared powers.
The common-power CTs are not mutated by branches. This avoids recomputing all
16 stages per center; the earlier independent-power version is incomplete evidence.
