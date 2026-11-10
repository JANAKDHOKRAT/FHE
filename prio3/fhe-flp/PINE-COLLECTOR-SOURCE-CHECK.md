# Source check of plaintext lifting and reduced decryption

Inspected OpenFHE source: commit
`32362085fcfa8133f86a4e81d4440734c984b16d` (1.3.1), matching the source tree
used for the installed library in this environment. This closes a **source
inspection** gap in `PINE-SECURITY-ARGUMENT.md`; it is not an independent review
or a new joint-privacy/security theorem. Other OpenFHE versions must be checked
again. Runtime/build provenance accompanies the training evidence.

## F4: coefficient plaintext lift

The Rust wrapper's `Context::coef_plaintext` first calls `center` on each field
residue and rejects too many coefficients. Its C++ shim
`tbgv_plaintext_new_coef` calls `MakeCoefPackedPlaintext` with those signed values.

In OpenFHE `src/pke/lib/encoding/coefpackedencoding.cpp`:

- `encodeVec` (lines 41–68) zeros all coefficients first and checks each supplied
  value's bounds. For BGV, a negative value v becomes Q - |v| in the polynomial;
  nonnegative values become v. The BFV branch has different behavior and is not
  the branch used here.
- `CoefPackedEncoding::Encode` (lines 70–96) copies the polynomial into DCRT,
  applies the integer scaling factor, and converts to evaluation format.

For this FIXEDMANUAL path, scale 1 is required. The source inspection establishes
centered integer lifting for the coefficients; it does not justify treating an
arbitrary scale or arbitrary imported ciphertext as having that meaning. The
wrapper's metadata restrictions and PINE task self-checks remain necessary.

## F7: decryption of the reduced collector ciphertext

The collector opens a two-component, **one-tower** ciphertext reconstructed
with the task's fixed reduced metadata. C++ `tbgv_decrypt_coeffs` invokes the
library's BGV decryption and obtains `GetCoefPackedValue`; Rust maps the signed
values back to field residues.

In OpenFHE:

1. `src/pke/lib/scheme/bgvrns/bgvrns-pke.cpp`, `PKEBGVRNS::Decrypt`
   (lines 44–98), computes the decryption phase. For the one-tower case its
   modulus-reduction loop performs zero iterations. It calls
   `DecryptionCRTInterpolate(p)` on that single tower.
2. `src/core/include/lattice/hal/default/poly-impl.h`,
   `DecryptionCRTInterpolate` (lines 574–583), calls polynomial `Mod(p)`, which
   delegates to the vector modulus operation.
3. `src/core/lib/math/hal/intnat/mubintvecnat.cpp`, `NativeVectorT::Mod`
   (lines 145–160), uses half of the original modulus q. For residue v > q/2,
   it subtracts q-p before reduction modulo p, giving (v-q) mod p; otherwise
   it gives v mod p. That is exactly reduction of the CENTERED phase modulo p.
4. `CoefPackedEncoding::Decode` (lines 119–138) applies the inverse scaling
   factor modulo p and `fillVec` returns centered plaintext values. For scale
   1 this is the intended centered representative. The library clears its
   decoded temporary noise buffer, but this is not circuit privacy: the key
   holder still possesses the ciphertext.

Crucial restriction: this does NOT say that a full-level, arbitrary-phase
ciphertext can be decrypted by reducing its original centered phase modulo p
without further conditions. With several towers the BGV decryption code performs
modulus reductions first. The chosen-phase counterexample in
`tests/chosen_phase_linearity.rs` demonstrates why a no-wrap argument is needed.
For honestly evaluated admitted reports, the admission argument must ensure the
pre-reduction arithmetic and every reduction stay in their safe bounds. For a
malicious evaluator, the collector still cannot establish that its submitted
reduced ciphertext came from that computation.

## What remains unproved

Reading these paths strengthens the engineering evidence for the existing safe
arithmetic argument under its stated assumptions. It does not bind admission
copies to query ciphertexts against a malicious evaluator, authenticate the
aggregate, provide a simulator for the collector's entire view, or eliminate
observable reactions. The production gate remains closed.
