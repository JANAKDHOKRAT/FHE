# Client-ciphertext admission: a concrete proof obligation

Baseline: 8ff50de. This note is not a completed client proof implementation,
not a production security theorem, and not an accepted-invalid-PINE attack.

## Why structural validity is insufficient

Let p be the plaintext prime, Q the product of ciphertext towers, and c=(c0,c1).
A secret-key phase is c0+c1*s in R_Q. Decoding a centered phase modulo p
need not commute with a public plaintext product if that phase wraps Q.

The adjacent wrapper regression `chosen_phase_linearity` constructs public,
canonical RNS residues for c0=floor(Q/2), c1=0. It does not know the secret key.
For these parameters every tower q_j is 1 modulo 2p, hence Q is 1 modulo 2p.
Therefore floor(Q/2) mod p=0. Multiplication by 2 produces Q-1, whose centered
representative is -1, so decoding gives p-1 instead of 2*0=0.

This is a counterexample to applying decoded field-linearity to every
structurally accepted ciphertext. It does not show that an attacker can forge
PINE's full FLP proof under secret query points. It also does not demonstrate
key recovery or invalidate honest-ciphertext correctness.

## Candidate bounded-witness admission relation

Under the inspected BGV public-key convention pk0=p*e_pk-a*s, pk1=a,
a proposed relation for each report ciphertext must constrain witnesses:

    c0 = pk0*u + p*e0 + m  (in R_Q)
    c1 = pk1*u + p*e1      (in R_Q)

with explicit admitted supports for m, u, e0 and e1, and exact coefficient,
RNS and evaluation-domain encodings. Ternary u and bounded e0/e1 are possible
supports, not a claim that a malicious prover sampled from honest distributions.
The key-generation assumption must bound e_pk and s as well. Confirm the
formula, scaling and samplers against the exact wrapper/library source before
using the relation in a proof system.

Bind the public statement to the descriptor, key, part identifier, ciphertext
bytes and nonce. Prove knowledge and hide the witnesses. Only proving an
unbounded modular encryption equation does not solve the problem.

For R=Z[X]/(X^n+1), ||ab||_infinity <= n||a||_infinity||b||_infinity.
Given ||u||,||s||<=1, ||e_pk||,||e0||,||e1||<=E and ||m||<=M,
the integer fresh phase has norm at most H=M+p*(2n+1)*E.
For a query sum of t ciphertext/plaintext products with polynomial bounds A_j,
a sufficient pre-mask bound is H*sum_j n*A_j. Add separately the bounds for
constants, masks and flooding, then prove safety through every reduction step.
Use the actual admitted row coefficients; dimensions and maximum batch sizes
must be bounded before allocations. This sufficient bound can be pessimistic.
Failure of this bound is not evidence of a concrete cryptanalytic attack.

## Decisions before implementation

1. Inspect and pin exact encryption/key generation and reduction semantics.
2. Derive a supported parameter envelope from admitted witness supports and
   all honest evaluator paths, including multi-ciphertext query accumulation.
3. Choose a concrete zero-knowledge proof system capable of this bounded ring
   relation. Specify setup, soundness/knowledge, privacy and quantum assumptions.
4. Specify challenge stages. G must be fixed before wraparound randomness; W
   before verification randomness; proof bodies before private FLP query points.
   If auxiliary proof bytes enter a hash transcript, account for their additional
   grinding choices. Do not introduce a circular statement/challenge dependency.
5. Verify admission proofs before query evaluation and before any decryption.
6. Implement hostile witness/noise tests and cross-key/task/part substitutions.
7. Prove the resulting fixed-input and adaptive-query soundness reduction.

Even successful bounded-witness admission does not fix a malicious evaluator:
it can still submit unauthorized check or aggregate ciphertexts. Check and final
computation authorization remain distinct obligations. Nor does admission alone
establish collector-side ciphertext privacy or negligible whole-execution failure.
