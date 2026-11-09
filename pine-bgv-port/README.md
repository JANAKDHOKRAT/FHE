# PINE–BGV port: incomplete research implementation

**Not production-ready. No complete PINE protocol or privacy proof is claimed.**
Published at the owner's request to preserve and review the work.

Implemented: two FieldPrio2 arithmetic circuits using chunked ParallelSum
square/multiplication gadgets, fixed-point encoding checks, parameter preflight,
exact integer-update arithmetic, and a real OpenFHE BGV affine-query test.
The encrypted test compares decrypted query rows with prio on honest and
arbitrary input/proof values with nonzero unused coefficients. Challenges are
fixed test values. The test process holds both keys; this does not establish
role isolation, secure challenges, ciphertext privacy or production security.

Missing: full upstream differential qualification, secure challenge/consistency
binding, authenticated evaluation, collector privacy, distributed training,
realistic model benchmarks and comprehensive adversarial qualification.

## Reproduce

Requires Python 3, Rust supporting edition 2024, C++17/OpenMP and shared
OpenFHE 1.3.1 with MATHBACKEND=4. Set OPENFHE_DIR to its install prefix,
LD_LIBRARY_PATH to include its lib directory, and OMP_NUM_THREADS=2.

From this folder:

    (cd port && python3 -m unittest -v)
    cargo fmt --manifest-path port/pine-circuit/Cargo.toml -- --check
    cargo clippy --release --locked --manifest-path port/pine-circuit/Cargo.toml --all-targets -- -D warnings
    cargo test --release --locked --manifest-path port/pine-circuit/Cargo.toml -- --test-threads=1

Fresh results for this packaged source are in evidence/. Only the wrapper
functions used by the circuit tests are exercised here; this is not a rerun of
all wrapper or repository tests. No secret keys or build products are included.

## Provenance and reading

- PINE reference: junyechen1996/draft-chen-cfrg-vdaf-pine,
  commit 4d11ac826606cf8b08e4b34f815ad14ba7397593; source and license in upstream/.
- BGV wrapper: JANAKDHOKRAT/FHE main,
  commit 19db638858d7fc88ad46708803dbcd44d017f76a, copied unchanged.
- prio: 0.18.1, with committed Cargo.lock.
- port/INTEGER-ARITHMETIC.md: proved elementary statements and their premises.
- port/pine-circuit/STATUS.md: encrypted test scope and unresolved work.

The rational quantizer is separate from PINE's binary64 encoding. The parameter
matrix is a preflight calculation, not an encrypted performance measurement.
