# Exact alternative encodings and circuits

These are circuit constructions over F_p, p=65,537, with the paper's honest,
noncolluding evaluator/collector model. They replace the paper's bit/slack or
one-hot upload encodings; they are not a claim to implement its original Eq. 5
unchanged. Their ideal plaintext aggregate functions are specified below.
Encryption correctness and security are separate from these algebraic identities.

## Equality and finite-domain lookup

Define delta_a(z)=1-(z-a)^(p-1). Fermat's theorem gives delta_a(z)=1 iff z=a,
and zero otherwise, for every field element. There is no division. Since
p-1=2^16, an equality lookup takes sixteen successive ciphertext squarings.
For a set A of distinct canonical field elements, sum_{a in A} delta_a(z)
is exactly the indicator of membership in A. It is zero or one, so there is
no cancellation or integer-count wrap in this membership indicator.

An authorized scalar slot is first isolated by an evaluator-chosen plaintext
mask. Rotation/addition then broadcasts it through the first SIMD row. All
unauthorized slots and the second row were zeroed before this broadcast.
A lookup table enumerates its constants periodically through that row. A
power-of-two cyclic rotation/addition reduction sums one table period at
every row position. Identical repeated values are representations of the
same task output, not extra per-client outputs.

## Bounded Sum(100)

Upload encoding E_S(x)=x is a single scalar, not bit/slack coordinates.
F(x)=sum_{a=1}^{100} a delta_a(x) equals x when 0<=x<=100 and zero otherwise
for all x in F_p. In particular F(0)=0 and every invalid scalar contributes
zero. Table period 128 fits the SIMD row; padding entries have zero weight.
Weighted equality lookup, row reduction, and aggregation evaluate F exactly
in the ideal field computation. Require 100N<p; for the tested N=32,
100N=3,200<p. This does not separately expose a validity flag.

Depth: input isolation 1 + equality 16 + plaintext weights 1 = 18.
Broadcast, table reduction and sum across reports use additions/rotations.

## Histogram(L)

Upload the bucket index b as E_H(b)=b. The output coordinate a is delta_a(b)
for 0<=a<L. This is exactly the intended one-hot measurement if b is an
admissible index and the zero vector for every other field element. A table
of period next_power_of_two(L), followed by a plaintext output mask, excludes
padding indices and the second row. The first row repeats the histogram
output, with zeros in padded coordinates. Require N<p for integer counts.

Depth: isolation 1 + equality 16 + output mask 1 = 18.

## Binary SumVec(L), 13-bit chunks

Partition the L bits into m=ceil(L/13) chunks with widths b_h<=13. Upload
z_h=sum_{k=0}^{b_h-1} 2^k v_{h,k} in designated scalar slots of one ciphertext.
Every canonical chunk is <2^13<p; there is no field wrap in the encoding.
For arbitrary uploaded field elements, define

V_h(z)=sum_{a=0}^{2^{b_h}-1} delta_a(z),
D_{h,k}(z)=sum_{0<=a<2^{b_h}, bit_k(a)=1} delta_a(z).

V_h is exactly the admissible-range indicator. D_{h,k} equals the k-th bit
for admissible chunks and is zero for every inadmissible chunk. D_{h,k}(0)=0.
Use subset lookup tables directly for D: this avoids an extra plaintext
bit-selection multiplication after equality evaluation.

The contribution for coordinate (h,k) is

Y_{h,k}=D_{h,k}(z_h) * product_{j!=h} V_j(z_j).

If every chunk is admissible, Y equals the original binary vector. If any
chunk q is inadmissible, coordinates belonging to q vanish because D_q=0;
all other coordinates vanish because their product contains V_q=0. Therefore
the ENTIRE invalid report contributes zero, including when otherwise valid
chunks contain ones. This is an identity for arbitrary field elements, not
an assumption that the client encrypted bits honestly.

The evaluator isolates each scalar before lookup. After broadcast, the second
row is zero. Every subset used for D excludes zero, so its decoded bit is
zero in the second row. V may equal one there; multiplying it cannot change
the zero output. Thus only repeated intended aggregate coordinates are present
in the plaintext output. Intermediate V values are never protocol outputs.

Each factor has depth 1+16=17. There are m factors per output (one D and m-1
V), multiplied in a balanced tree. Required depth is 17+ceil(log2 m):

| L | m | Required depth | Requested tested context |
|---:|---:|---:|---|
| 10 | 1 | 17 | depth 18, HYBRID digits 7 |
| 25 | 2 | 18 | depth 18, HYBRID digits 7 |
| 50 | 4 | 19 | depth 19, HYBRID digits 21 |
| 100 | 8 | 20 | depth 20, HYBRID digits 22 |

Parameter selection and actual encrypted test outcomes are recorded separately;
this table is not itself evidence of successful decryption. Require N<p for
each integer coordinate aggregate. The prototype emits one ciphertext per
output coordinate, with the coordinate repeated in its first row and zero
second row. This is a substantial output-size and computation cost.

## Security limits of these claims

These proofs establish ideal field functionality for arbitrary plaintext
elements and declared encodings. They do not prove that arbitrary malicious
ciphertexts securely realize such plaintext elements, that residual ciphertext
noise hides intermediate information from a full-key collector (circuit
privacy), or that the full encryption parameter sets have independently
established 128-bit attack costs. Named library security checks remain enabled;
the earlier Count profile's independent-screening caveat is not removed.
No threshold guarantees, authentication, replay prevention or deployment
release policy are added by these circuit prototypes.
