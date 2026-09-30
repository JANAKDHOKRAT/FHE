# Zero-knowledge proofs of key well-formedness: assessment and decision

**Status: assessed, not built. Decision: do not build now; revisit under the
conditions in §8.** Written 30 September 2026 from a reading of LaZer commit
`3330e48` and of this crate at branch head `7d834ae`, plus one proof measured
on a 4-vCPU machine (`measurements.txt`).

This note answers three questions the project asked: would proving key
contributions well formed change the Prio3 structure we follow; would it
make the system too expensive to be usable by many people; and is it worth
doing. The short answers are no, no, and not now.

## 1. What the proof would be

`SECURITY.md` §6.2 states assumption A3: every aggregator's key contribution
in the ceremony has a small secret and noise from the specified
distribution. Today A3 is *bounded by measurement*: the deep key check
refuses contributions whose noise would bring any decryption point within
about 64 bits of the flooding, and the runtime flooding check refuses
fusions outside the flooding support. It is not proven.

A zero-knowledge proof would let each aggregator prove, for each key
contribution it reveals in the ceremony, that it knows a secret `s` and
noise `e` of bounded norm such that the revealed residues equal
`-a·s + e` (public key), the hybrid key-switching relation (relinearization
key, two rounds) or the automorphism key relation (rotation keys). The
receiver verifies the proof before it rebuilds the key, and the proof bytes
enter the signed transcript so an auditor can re-verify offline.

The proof replaces the sentence "bounded by measurement" with "proven". It
changes nothing else: not the validity check, not the client, not the
aggregation, not the collector.

## 2. What it does not do

* **It does not change the Prio3 structure.** Client encodes, aggregators
  check validity with a verify-key challenge, aggregators sum, collector
  decrypts. All of that stays. The proof lives inside the ceremony, which
  runs once per task, before any client exists.
* **It does not touch clients.** Clients neither produce nor verify these
  proofs. A per-report proof of ciphertext well-formedness is a different
  thing, is not what A3 needs, and would cost the client what Prio3's FLP
  costs or more. It is out of scope here and argued against in §7.
* **It does not add per-report cost.** Every cost below is per key
  contribution per aggregator per ceremony.

## 3. What LaZer is, as read

LaZer (IBM Research Zurich, MIT licence, `https://github.com/lazer-crypto/lazer`)
implements the Lyubashevsky–Nguyen–Plançon proof toolbox (`lnp-tbox`) for
linear relations with exact and approximate norm bounds, plus LaBRADOR for
succinct proofs. Facts that matter for us, with their source in the tree:

| Fact | Source |
| --- | --- |
| Version 0.1.0, "updated on release. XXX"; no tagged release; latest commit 28 Sep 2026 | `src/version.c`, `git log` |
| Requires Linux amd64, AVX-512 and AES-NI, gcc ≥ 13.2, gmp, mpfr; SageMath ≥ 10.2 for parameter generation; succinct functions absent without AVX-512 | `README.md`, `docs/source/getting_started.rst` |
| Build clones `cpu_features` from GitHub; LaBRADOR is a git submodule; Intel HEXL and Falcon are vendored zips | `README.md`, `.gitmodules`, `third_party/` |
| Proof ring degree 64 or 128; proof modulus a product of 50-bit primes, at most 2^256; at most 1024 additions in the CRT domain | `scripts/codegen.sage`, `scripts/moduli.sage` |
| Proof modulus sized as `log2 q = ⌈log2(2(1+ψ)(P + n·P·deg·S + E) + 1)⌉`, ψ = 3358, P = (p−1)/2 | `scripts/lin-codegen.sage` |
| Parameter generator targets 128 bits (`DELTA128` for MLWE and MSIS); generated headers print knowledge error ≤ 2^-127, completeness ≥ 1 − 2^-3 | `scripts/lnp-tbox-codegen.sage`, `demos/kyber1024/params.h` |
| Relations: linear over `R_p`, per-partition exact ℓ2 bounds, binary coefficients, approximate ℓ∞ with slack ψ; quadratic relations and the automorphism `X → X^-1` at the C level only | `scripts/lnp-params.sage`, `src/lazer-in2.h` |
| Largest shipped statement: Swoosh, `p = 2^214 − 255`, 256 committed polynomials, 240-bit proof modulus | `python/swoosh/` |
| No constant-time claim anywhere in sources or docs; rejection sampling uses mpfr; demos use zero seeds | `grep` over `src/`, `docs/`; `demos/kyber1024/kyber1024-demo.c` |
| Own test suite: 25 C tests | `tests/run-tests` |

Measured here (details in `measurements.txt`): the Kyber1024 key proof, 32
committed degree-64 polynomials, gives a 20,279-byte proof in about 105 ms
on one core, verifies in 53 ms, 40 of 40 accepted; LaZer's own suite passes
24 of 25 with one skip for SageMath.

## 4. The obstacle: our key moduli do not fit LaZer's proof ring

The relation `b = −a·s + e (mod Q)` cannot be handed to LaZer as one linear
relation over `R_Q`. LaZer needs a proof modulus about 30 bits above the
statement modulus and caps it at 2^256, so a statement modulus above about
2^225 is refused. Ours:

| Mode | N | towers | log2 Q |
| --- | --- | --- | --- |
| verdict | 32768 | 7 (48, 60, 60, 55, 55, 55, 17 bits) | ≈ 350 |
| silent | 65536 | 29 (36, 60, 60, 25 × 44, 21 bits) | ≈ 1277 |

The key-switching keys use the extended modulus `Q·P` of hybrid key
switching and are larger still.

**The design that would work.** Lift each RNS tower's relation to the
integers with an explicit quotient witness:

    b_t + a_t·s − e − q_t·v_t = 0        for every tower t

with witness `(s, e, v_1, …, v_T)`, `s` ternary (exact ℓ2 ≤ √N), `e`
Gaussian (ℓ2 ≤ 1.2·σ·√N), each `v_t` approximately bounded in ℓ∞ by about
`N/2`. All towers share one commitment of `(s, e)`, and one proof modulus of
about 90 to 100 bits (two 50-bit primes) covers all rows. This is the bridge
nobody has built.

**The shortcut that is an attack.** Proving tower groups separately (say
verdict towers 1–4 with one witness and towers 5–7 with another) lets an
adversary choose the noise on the second group freely. The true noise is
then `e + Q₁₋₄·w` for a `w` of its choice, which reaches 2^293 to 2^310:
exactly the window `SECURITY.md` §6.2 measured as "decrypts correctly but
leaks the encryption randomness". The proof must bind one witness across
every tower or it proves nothing.

**Rotation keys.** LaZer's relations support only the automorphism
`X → X^-1`. Our rotation keys use Galois automorphisms `X → X^{5^j}`. The
rotation-key witness `σ_j(s)` would be committed as a separate small vector,
and whether it must be bound to `s` (as opposed to only bounded in norm) is
a security argument to be written, not an implementation detail. The
current view is that A3 needs only the norm bound, because a rotation key
built from a different secret is caught by the joint key check.

## 5. Cost, measured and extrapolated

Witness sizes for the public key alone, from the tower counts above:

| Mode | coefficients (2 + T)·N | degree-64 polynomials | × Kyber reference |
| --- | --- | --- | --- |
| verdict | (2 + 7)·32768 = 294,912 | 4,608 | 144 |
| silent | (2 + 29)·65536 = 2,031,616 | 31,744 | 992 |

Scaling the measured 20,279-byte, 105 ms proof linearly gives about 2.9 MB
and 15 s per verdict-mode key contribution, and about 20 MB and 100 s per
silent-mode one. LNP proof size grows roughly linearly in the committed
witness and prover time faster than that, so these are lower bounds. A party
contributes one public key, two relinearization rounds and one key per
rotation index (18 in silent mode), so a silent-mode party would spend on
the order of an hour proving, once per ceremony, on top of the 300 s and
6.3 GiB the ceremony costs today. Nothing at that size has been measured
with LaZer; parameter generation for it needs SageMath and has not been run.

Where the cost lands: on two or three aggregator machines, once per task
key. It does not land on clients, and it does not scale with the number of
reports or of clients.

## 6. Compatibility with the model

Compatible. The proof is a new blob in the ceremony's existing
commit-then-reveal rounds (`KeyCommit`/`KeyReveal`,
`Relin2Commit`/`Relin2Reveal`), hashed in the commit, verified before the
receiver calls the shim's `with_b`, and digested into the round-9 transcript.
The proof parameters' hash would join the round-1 `params` fingerprint so
parties on different parameters stop early. The per-report protocol, the
wire format of reports, the collector and every measurement type are
unaffected.

The worry that this would make the system unusable for a large population
is therefore misplaced in direction: it raises a one-time institutional
cost, not a per-user cost. The real objections are elsewhere, in §7.

## 7. Is it worth it

Not now. The gain and the price, stated plainly:

**Gain.** A3 becomes proven instead of measured. That is the one place
where our guarantee against a single malicious aggregator is weaker than
Prio3's, and closing it is what a top-venue reviewer would demand before
anything else. For a deployment with accountable aggregators (institutions
that sign a ceremony transcript and can be held to it), the measured bound
is the same class of trust Prio3 already places in aggregators not
colluding, and it is written down as such.

**Price.**
1. A research bridge (tower lifting, §4) that does not exist and whose
   soundness argument has to be written and reviewed.
2. Silent-mode sizes that are extrapolations; the honest outcome of
   measuring them may be "not with this library".
3. A 0.1.0 research library, with no constant-time claim and no release
   discipline, added to the trusted base of a key ceremony. In the short
   term that makes the system less reviewed, not more.
4. Weeks to months of work that produce no change to the validity check,
   which is where the thesis lives.

**A per-report proof of ciphertext well-formedness** is a separate idea
that sometimes travels with this one, and it is a worse trade: it puts a
lattice proof on every client, which is the cost Prio3's FLP already
carries and the cost this design exists to avoid. The client-side threat it
would address (a garbage ciphertext poisoning a silent-mode batch) is
handled today by rejection in verdict mode and by required authentication
with per-client quotas in silent mode, at no client cost.

## 8. When to revisit

Build it when at least one of these holds:

* A paper submission to a venue that will not accept a measured bound. Then
  the bridge itself is a contribution: a public OpenFHE-to-lattice-proof
  bridge for multi-tower keys does not exist and would serve any threshold
  FHE deployment on OpenFHE, verifiable outsourced FHE, and lattice-based
  proofs of plaintext knowledge.
* Aggregators that are mutually distrusting and unaccountable, so there is
  no transcript-and-signature fallback.
* LaZer or LaBRADOR reaches a tagged release with a security review, or a
  library appears that takes RNS keys natively.

The build-and-test checklist, the production disqualifiers and the phased
plan for that day are kept alongside this note in the project's records
(62 parameters, 33 disqualifiers, seven phases); the first phase is a
bit-exact transcription of OpenFHE 1.3.1's `MultipartyKeyGen`,
`MultiKeySwitchGen`, `MultiMultEvalKey` and `MultiEvalAutomorphismKeyGen`
relations through this crate's shim, before any proof code.

## 9. Reproducing the numbers

    git clone https://github.com/lazer-crypto/lazer && cd lazer
    git checkout 3330e487228f633eceb322807b13a596b516770f
    apt-get install libgmp-dev libmpfr-dev        # gcc 13, cmake, make present
    make lib                                       # 2 m 14 s here; needs network for cpu_features
    # the Makefile expects hexl under build/hexl/lib64; on Ubuntu 24.04 it lands in build/hexl/lib
    cd demos/kyber1024
    cp <this folder>/kyber1024-bench.c .
    cc -O3 -I../.. -o kyber1024-bench kyber1024-bench.c ../../liblazer.a -lmpfr -lgmp -lm \
       ../../third_party/hexl-development/build/hexl/lib/libhexl.a -lstdc++
    ./kyber1024-bench
    cd ../.. && ln -s lib third_party/hexl-development/build/hexl/lib64 && make check && (cd tests && python3 run-tests)

`kyber1024-bench.c` is LaZer's `demos/kyber1024/kyber1024-demo.c` (MIT,
IBM) with two additions: the proof length is read back from
`lin_prover_prove`, and prover and verifier are timed separately over 20
runs. `lazer-test-suite.log` is the unedited output of `run-tests`.

## 10. References

* Lyubashevsky, Nguyen, Plançon. Lattice-based zero-knowledge proofs and
  applications: shorter, simpler, and more general. CRYPTO 2022.
* Beullens, Seiler. LaBRADOR: compact proofs for R1CS from module-SIS.
  CRYPTO 2023.
* Nguyen, Seiler. Greyhound: fast polynomial commitments from lattices.
  CRYPTO 2024.
* Lyubashevsky, Nguyen, Seiler et al. The LaZer library: lattice-based zero
  knowledge and succinct proofs for quantum-safe privacy. CCS 2024.
* Bai, Lepoint, Roux-Langlois, Sakzad, Stehlé, Steinfeld. Improved security
  proofs in lattice-based cryptography: using the Rényi divergence rather
  than the statistical distance. Journal of Cryptology 2018.
* Boudgoust, Scholl. Simple threshold (fully homomorphic) encryption from
  LWE with polynomial modulus. ASIACRYPT 2023.
* Chowdhury, Sinha, Singh, Mishra, Chandran, Patranabis, Chatterjee.
  Efficient threshold FHE with application to real-time systems. ePrint
  2022/1625.
