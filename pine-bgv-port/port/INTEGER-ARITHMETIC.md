# Established arithmetic claims and explicit premises

These lemmas do not establish cryptographic protocol security.

## Quantization

For scale S=2^f and exact coordinatewise nearest rounding q_j=round(S x_j),
|q_j/S-x_j|<=1/(2S). Hence ||q/S-x||_2<=sqrt(d)/(2S) by summing squares.
Triangle inequality gives ||q/S||_2<=||x||_2+sqrt(d)/(2S).
Consequently real clipping to B/S does not ensure ||q||_2<=B.
The exact post-rounding integer check sum(q_j^2)<=B^2 avoids this ambiguity.
It may reject an honest real vector; retry/reclipping policy is separate.

integer_updates.quantize accepts explicit rational inputs. It is NOT asserted
bit-for-bit equivalent to PINE's binary64 multiplication/rounding. encoding.py
implements and tests the pinned reference's floating-point semantics. Both
require checking the actual resulting integer vector before submission.

## Aggregate uniqueness and update magnitude

Premises: N is the submitted cohort size; each accepted integer vector q_i
has Euclidean norm <=B; rejected reports contribute zero. Let a_i be acceptance.
For s=sum_i a_i*q_i, triangle inequality gives ||s||_2<=NB and |s_j|<=NB.
If p>2NB, every s_j lies strictly in (-p/2,p/2), so its field residue has the
unique centered lift s_j. Dividing by N*S gives the specified equal-client
update and ||s/(NS)||_2<=B/S. This denominator is N, not accepted count.
This is not weighted FedAvg; sample weighting requires a separate bound.

Checking ||s||<=NB is only a necessary check. It cannot prove the clients'
individual bounds, honest training, correct evaluation, or cohort integrity.

## Probability accounting

For adaptive bad events E_i, if Pr(E_i | every possible prior history h)<=eps_i,
then Pr(union E_i)<=sum eps_i. Proof: total probability bounds each Pr(E_i),
then apply the union bound. Independence is unnecessary. A single fixed-input
error bound does not establish the required bound for adaptive chosen inputs.
No concrete PINE-BGV whole-execution eps_i has been established here.

## Parameter limitation, not impossibility

The rejection of p=65537 with encoded norm bound 16 and reference alpha=8.7
comes from its rounded wrap bound 256 and requirement p>=2600*256.
It does not prove that all bound/field/profile combinations or alternate
protocols are impossible. Choosing another bound changes quantization capacity.

## Unresolved cryptographic work

No implementation currently proves encryption well-formedness or evaluator
execution. No secure replacement of PINE's distributed challenge derivation,
collector-view simulator, or circuit-privacy composition theorem is provided.
None of these arithmetic lemmas closes those gaps. Production status remains red.
