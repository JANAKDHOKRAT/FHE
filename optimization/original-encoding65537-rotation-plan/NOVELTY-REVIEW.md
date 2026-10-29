# Technical novelty assessment — 30 October 2026

## Verdict and scope

The evidence supports a task-specific arithmetic-circuit implementation and
parameter-engineering contribution. It does not currently establish a new
cryptographic primitive, a new security theorem, a universally optimal method,
or a first-in-the-literature algorithm. The most plausible research contribution
is the combination of output-equivalent circuit specialization, slot isolation,
and rotation scheduling under explicit modulus/key-memory constraints.

This is an internal technical review, not independent peer review. New online
search and a paper download were attempted against OpenAlex and IACR ePrint
2014/106; both failed with proxy tunnel403, including escalated retries.
Consequently the review cannot exclude recent or otherwise inaccessible prior
work. No claim of an exhaustive literature search is made.

## Claim-by-claim assessment

| Ingredient | Assessment | Defensible claim |
|---|---|---|
| Z(x)=1-x^(p-1), D(x)=1-(x-1)^(p-1) | Standard finite-field point indicators, equivalent to Lagrange interpolation | Applied to these tasks, not newly invented |
| Count contribution D(x) | Elementary specialization of the indicator of1 | Output-equivalent Count circuit reduction; not a separately preserved validity flag |
| A(x)=Z(x)+D(x) | Standard sum of disjoint point indicators | Shallower membership-test realization with an operation-count trade-off |
| Y_k=D(x_k) product other A(x_j) | Indicator factoring and absorption | Task-specific contribution circuit; standalone cryptographic novelty unestablished |
| One-hot Y_k=D(x_k) product other Z(x_j) | Standard indicator of a pattern | Direct one-hot contribution circuit, equivalent to the paper's predicate for supported K<p |
| p65537, n32768,16 squarings | Already present in professor's BFV investigation; elementary consequence of p-1=2^16 | Not a new parameter idea |
| Balanced multiplication/reused interval products | Standard circuit-depth and common-subexpression techniques | Application-specific scheduling and implementation |
| Composed rotations from a small key set | Established FHE practice; HElib has explicit partial-matrix/BSGS machinery | Particular constrained rotation plan, not invention of sparse rotation keys |
| Moving rotations through squaring | Ring-automorphism identity | Noise-budget-aware scheduling of an established identity; exact combination needs further prior-art comparison |
| Selecting NTT primes above numerical bounds | Standard parameter-selection principle; custom change to upstream rounding | Independently checked engineering refinement, not a new encryption scheme or security proof |
| Returning one packed vector ciphertext | Established SIMD/output-packing mechanism | Improvement over this selected older implementation, not universal cryptographic compression |

## Algebra checked

All statements here concern functions on F_p, not equality of unreduced formal
polynomials. Fermat gives Z(x)=[x=0], D(x)=[x=1], and A(x)=[x in{0,1}]. Thus
D(x)A(x)=D(x). For the original binary contribution,

    x_k product_j A(x_j) = D(x_k) product_(j != k) A(x_j).

If all coordinates are bits, both sides equal x_k. If some coordinate is not a
bit, both sides vanish. This is a direct application of standard indicator
algebra. It is not a new assumption and does not establish FHE security.

Likewise the paper's Count contribution

    x (1-[x(x-1)]^(p-1))

and D(x) agree at every field element. The contribution alone cannot preserve
the original validity flag: valid0 and invalid2 both produce contribution0,
but their original validity flags differ.

One-hot Y_k is1 exactly when x_k=1 and every other coordinate is0. Equivalence
with bitness plus the paper's modular sum-equals-one condition uses K<p.
The original weighted Sum encoding is inherited, not a new contribution.

Computing A using Z and D needs two16-squaring chains, versus a bitness residual
followed by one16-squaring chain. Lower depth therefore does not mean fewer
encrypted multiplications or faster execution. This trade-off must accompany
any proposed optimization claim.

## A precise, limited optimality statement

For arbitrary field-valued binary-vector reports, the reduced polynomial for
Y_k has total degree K(p-1), with nonzero top coefficient -(-2)^(K-1). Unique
multivariate reduced representation modulo x_j^p-x_j implies that no lower-
total-degree polynomial can represent the same full-domain function.

For a fan-in-two arithmetic circuit with ciphertext additions, multiplications,
and linear slot operations, degree is at most2^d after d multiplicative layers.
At p=65537 this gives d >=16+ceil(log2 K). This is a standard degree argument
applied to this function, not a new general lower-bound technique.

The selected binary lengths10,25,50,100 reach depths20,21,22,23 in the recorded
schedules, including their supported selection-mask operations. For these
non-power-of-two lengths the depths meet that restricted arithmetic lower bound.
This does not prove optimal modulus size, keys, operation count, runtime, RAM,
or security, and does not cover bootstrapping, trusted-bit promises, different
protocols, or additional nonlinear primitives treated as free operations.

## Prior-work evidence actually inspected

1. HElib source at commit3e337a66a91a92d49de6a9505340826b0eb71081,
   src/keySwitching.cpp: active addSome1DMatrices/addBSGS1DMatrices routines,
   around lines570–600, explicitly select partial key-switch matrices and
   support baby-step/giant-step composition. This refutes novelty of the broad
   idea 'store fewer rotation keys and compose rotations'; it does not establish
   that HElib implements this exact per-level schedule.
   https://github.com/HomEnc/HElib/tree/3e337a66a91a92d49de6a9505340826b0eb71081
2. OpenFHE1.4.2 commit aa391988d354d4360f390f223a90e0d1b98839d7,
   src/pke/lib/scheme/bgvrns/bgvrns-parametergeneration.cpp: existing numerical
   noise lower bounds, NTT-prime searches and ring/security checks. The patch
   changes rounding/selection, not those underlying formulas.
3. Professor's archived fhe/report.cpp and scripts/optimize_reports.py already
   use p65537 and the smaller ring for arithmetic report sizing. They do not
   execute full vector predicates. This is a direct earlier parameter baseline.
4. The local VDAF draft22 and professor paper define the task encodings and
   validity conditions. Those are inherited functionality, not new cryptography.

Relevant literature to obtain and compare in full before a priority claim:
Halevi and Shoup, Algorithms in HElib, CRYPTO2014 (ePrint2014/106);
Smart and Vercauteren, Fully Homomorphic SIMD Operations (2014);
Blelloch, Prefix Sums and Their Applications (1990), for scan/product-tree
techniques; finite-field interpolation treatments such as Lidl and Niederreiter,
Finite Fields. These are orientation references, not papers claimed to have
been freshly downloaded and fully reviewed in this session.

## Review findings limiting the contribution

- The final100 log reports maximum_pre_rotation_steps12. The code consequently
  shares14 of16 squaring stages, followed by two rotation-bearing stages.
  The stale MATHEMATICS.md claim of13 shared stages/three stages was corrected
  during this review. The dynamic checker/code already used14; no code changed.
- Full-domain field correctness is not arbitrary-ciphertext robustness, circuit
  privacy or negligible decryption-failure security. The100 profile retains the
  library target but its recorded primal-uSVP estimates are about92.86 ADPS16
  bits and126.10 MATZOV bits. Do not claim independently certified128-bit security.
- Keys were reduced relative to selected lookup implementations, whose encodings
  differ. Count also changes packing from four groups to per-report evaluation.
  These comparisons are not isolated demonstrations of a new algorithm's benefit.
- Several uploads grow. Runtime of the100 qualification is about6904 seconds,
  including setup and diagnostic decryptions; it is not a matched throughput
  benchmark. A smaller ring does not establish practical superiority.
- The supported cases are Sum100, Histogram3/8 and binary vectors10/25/50/100,
  plus Count. Bounded SumVec16 with maximum100 and Histogram16 are not thereby
  qualified. No universal implementation for every task parameter is established.

## What would make a stronger research claim

Specify an optimization problem: minimize measured ciphertext/key bytes subject
to field/ring, output disclosure, ignored padding, complete correctness/noise
constraints and a declared encryption-security assessment. State the admissible
rotation generators and per-level key-switch budget. Prove the field equivalence,
slot noninterference and restricted depth result as separate propositions.

Compare against original-encoding baselines with matched functionality and the
same security criterion. Ablate contribution rewriting, interval sharing,
rotation composition/scheduling and prime selection separately. Include standard
power-of-two and BSGS rotation choices. Retain stock-SDK refusals and failed runs;
do not convert parameter acceptance into an encrypted test pass.

Run repeated end-to-end measurements with key epochs, complete wire accounting
and memory. Identify parameters fully. Obtain full text on recent rotation-key
minimization, compiler scheduling, equality/membership circuits and RNS parameter
optimization; build a closest-prior-work comparison with theorem/algorithm
locations. Independent cryptographic review remains necessary.

## Recommended wording now

“We implement and qualify task-specialized BGV contribution circuits that preserve
the original measurement encodings and ignore unused slots. We combine indicator
factoring with shared product windows and constrained rotation scheduling, and
evaluate their task-dependent resource trade-offs at a fixed small plaintext
prime and ring dimension.”

Avoid 'new cryptographic primitive', 'first', 'universally optimal', 'no security
loss', 'production secure' and 'better than Prio3' without additional evidence.
