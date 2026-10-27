# Count hardening result — production gate remains open

The user explicitly chose to retain the paper's honest-evaluator assumption.
No malicious-evaluator proof is claimed or silently replaced by a signature.
Original `prio3/` files remain frozen and unchanged. The new authenticated
entry points are in `count-auth/`; old raw-core behavior remains reproducible.

| Requirement | Actual outcome |
|---|---|
| Authenticated, durable replay control | Implemented; competing-process, restart, quota and abrupt-exit tests passed |
| Network aggregate substitution/count relabeling | Refused before decryption by the new signed, policy-bound collector entry point |
| Malicious evaluator correctness | Outside the model, by explicit user choice; signatures are not a computation proof |
| Independent parameter assessment | Executed for four attack families under two named cost models, including actual auxiliary QP; scoped heuristic screening, not a proof |
| Input ciphertext bounded-noise security | **Not established**; client authentication and structural parsing do not prove this |
| Collector learns only aggregate | **Not established**; full-key collector can inspect ciphertext/noise beyond its API's plaintext result |
| Production push | **Not allowed; not performed** while the last two cryptographic gates remain open |

## Why the cryptographic gaps were not relabeled as fixes

The existing `fhe-prio3/src/wfe.rs` delegates repetitions to
`vdec::CHECK_SECURITY_BITS=80`. At n=65536 this gives five repetitions and an
ideal per-proof exponent 85; it is not a 128-bit proof policy. More importantly,
its documented extracted opening for effective ciphertext2C permits bounds
2*n*B_U and 2*n*(B_E+1). With B_U=2^24 and B_E=2^29 at n=65536,
these are 2^41 and about 2^46. Increasing repetition count alone does not make
those accepted noise bounds fit the native Count circuit. It also does not
supply a complete Fiat–Shamir security argument or lifetime/query accounting.
The native ordinary encryptor uses different error sampling from that proof
prover. We did not attach this protocol and pretend all of those issues vanish.

A correct integration needs a reviewed proof of knowledge of a permitted
opening, bound to the actual task/key/client/batch/ciphertext, whose proven
noise bounds support the *entire* native circuit. Its soundness, rejection
sampling, Fiat–Shamir model and total wire/key/runtime costs must be accounted
for. No new home-made proof was presented as production-reviewed cryptography.

For collector privacy, rerandomizing with an ordinary small-noise encryption of
zero is not itself a simulation argument. The actual screened profile retains
only two ciphertext moduli at its final level: the product is 79 bits. A
standard per-coefficient uniform-flooding proof with error boundB requires
widthW large enough for 2*n*B/(2W+1)<=2^-128 and decryption margin
p(B+W)+(p-1)/2<Q_final/2. Even using B=1, that sufficient certificate requires
about 165 modulus bits here. The current 79-bit final modulus cannot meet it.
This rules out claiming that this particular flooding certificate works by
just adding a knob; it is not an impossibility claim about every future
privacy construction. A simulator/rerandomization argument and parameters
with adequate retained modulus must be derived and then requalified. Adding
noise after full-key decryption does not hide the original ciphertext from
its key holder.

These two requirements interact: a flooding bound justified only for honest
ciphertexts does not cover arbitrary registered malicious-client ciphertexts.
Finite decryption tests do not supply the missing accepted-input noise proof.

## What was actually run

- Durable authentication tests: seven parent tests; process workers invoked in
  eight real child processes, plus an abrupt-exit worker. Updated SQLite is
  pinned through rusqlite0.41 and Cargo.lock.
- Actual BGV authenticated end-to-end test: two distinct signed client reports,
  correct aggregate1, replay refusal across restart, count relabel refusal,
  wrong epoch refusal, exact release retry.
- Screened d4 native complete-circuit qualification: 32 admitted mixed
  valid/invalid/cancellation/slot-injection reports, then33rd refused.
- QP guard test: actual screened context accepted; old small-ring profile refused.
- Formatting and Clippy with warnings denied.
- Independent estimator: pinned malb/lattice-estimator commit and Sage image
  digest, network-disabled execution, raw results and inputs in
  `hardening-evidence/`. Redundant candidate sweeps were intentionally stopped
  after d4 screening while on d5. Incomplete rows are not counted as passes.
- A new QP guard initially failed its unit test because a native usize was
  encoded with platform width instead of canonical u32. It was corrected;
  failure log is retained alongside final passing tests.

The stronger profile's real authenticated upload is16,793,800 bytes. The older
6,176,895-byte serialized report remains historical evidence, not this hardened
path's upload. Neither profile is declared a complete production-secure system.
