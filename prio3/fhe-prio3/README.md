# fhe-prio3

Prio3's five measurement types (Count, Sum, SumVec, Histogram,
MultihotCountVec), encoded as in draft-irtf-cfrg-vdaf-22, with the validity
check evaluated homomorphically under an n-of-n threshold BGV key.
The check's randomness is keyed with a verify key only the aggregators hold,
as in Prio3. The protocol, its security argument and measured
costs are in [FHE_PRIO3_SPEC.md](FHE_PRIO3_SPEC.md).

Crates:

* `../openfhe-tbgv-rs` — C shim plus safe Rust bindings for OpenFHE's
  multiparty BGV (key ceremony, evaluation, partial decryption, fusion).
* `fhe-prio3` (this crate) — types, challenge derivation, verification
  circuit, aggregator and collector state machines, `simulate` binary.

## Build

Requires OpenFHE 1.3.x installed (default prefix `/usr/local`; override with
`OPENFHE_DIR`, `OPENFHE_INCLUDE_DIR`, `OPENFHE_LIB_DIR`), a C++17 compiler
and Rust 1.85+.

```sh
git clone --depth 1 --branch v1.3.1 https://github.com/openfheorg/openfhe-development.git
cmake -S openfhe-development -B openfhe-build -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_EXAMPLES=OFF -DBUILD_UNITTESTS=OFF -DBUILD_BENCHMARKS=OFF
cmake --build openfhe-build -j && sudo cmake --install openfhe-build && sudo ldconfig

cd prio3/fhe-prio3
cargo test --release            # about 2.25 hours on 4 vCPUs; tests serialise themselves
cargo +nightly fuzz run parse    # fuzz the wire-format parser (needs cargo-fuzz)
cargo +nightly fuzz run roundtrip
cargo run --release --bin simulate -- --type sum --max 100 --reports 4
cargo run --release --bin simulate -- --type histogram --length 64 --aggregators 3
cargo run --release --bin simulate -- --type sumvec --length 1200 --bits 4
```

Both crates are standalone Cargo workspaces (the parent `prio3` workspace
references a vendored `libprio-rs` that is not in git).

CI (`.github/workflows/prio3.yml`) builds OpenFHE 1.3.1 from the same
commit and options, runs every test suite of the shim, this crate and the
node, and fuzzes the wire-format parser: 5 minutes per target on each
change, one hour per target nightly.

## Modes and authentication

```rust
// Verdict mode (default): four message rounds per report (mask and partial,
// each committed before it is revealed); aggregators learn accept/reject.
let cfg = TaskConfig::new(task_id, MeasurementType::Sum { max_measurement: 100 }, 2);
// Silent mode: no per-report messages or decryption; invalid reports add zero.
let cfg = TaskConfig::new_silent(task_id, MeasurementType::Sum { max_measurement: 100 }, 2);
// Require signed reports, one per registered client per batch.
let mut cfg = cfg; cfg.auth = AuthPolicy::Required { max_reports_per_client_per_batch: 1 };
let registry = StaticRegistry::new(enrolled_client_public_keys);
let agg = Aggregator::new(cfg.clone(), &material, 0, &shares[0], Some(registry))?;
let client = Client::new(cfg, &material.context, &material.public_key)?.with_identity(identity);
```

```sh
cargo run --release --bin simulate -- --type sum --max 100 --mode silent --reports 2   # ~2 min, ~10 GiB RAM
cargo run --release --bin simulate -- --type count --auth --reports 4
```

Measured on 4 vCPUs (see the spec for the full tables): verdict mode
0.45–0.65 s per report per aggregator with 2.7 MiB reports; silent mode
0.71–0.74 s per report per aggregator with 64-report batches and about
0.43 s with 256-report batches (the validity circuit runs once per batch;
per report the aggregator parses the report, masks it to its group's
slots and adds it to the batch), 21.3 MiB reports and 3.5 GiB of keys
per aggregator. Report
sizes are those of the packed wire format (spec §6b), which also keeps
every received byte away from OpenFHE's deserializer. The
regression pilot adds about 0.4 s per report in verdict mode.
`cargo test --release` takes about 2.25 hours on 4 vCPUs (measured
2026-10-01, one suite at a time; CI runs each suite as its own job), almost
all of it in the silent-mode tests; evaluation keys are released when the last aggregator for a task
drops, so the peak is that of one three-aggregator silent test. Network deployment lives in
`../fhe-prio3-node`, including sharding across independent aggregator
sets (`src/sharding.rs` here, router and `keygen-shards` there).

## Library use

```rust
use fhe_prio3::*;

let cfg = TaskConfig::new(task_id, MeasurementType::Sum { max_measurement: 100 }, 2);
// Key ceremony: in production each aggregator runs `ceremony::run` on its
// own machine over a `ceremony::Transport` (the node crate's `ceremony`
// command does it over HTTPS) and keeps only its own share;
// `run_local_ceremony` generates every share in one process, for tests.
let (material, shares) = keys::run_local_ceremony(&cfg)?;

let client = Client::new(cfg.clone(), &material.context, &material.public_key)?;
let report = client.shard(&Measurement::Sum(51))?;          // same bytes to every aggregator

let mut a0 = Aggregator::new(cfg.clone(), &material, 0, &shares[0], None)?;
let mut a1 = Aggregator::new(cfg.clone(), &material, 1, &shares[1], None)?;
let id = report.report_id;
let (k0, k1) = (a0.prepare_init(&report)?, a1.prepare_init(&report)?);      // mask commitments
let (m0, m1) = (a0.prepare_mask_reveal(&id, &[k1])?, a1.prepare_mask_reveal(&id, &[k0])?); // masks
let (c0, c1) = (a0.prepare_masks(&id, &[m1])?, a1.prepare_masks(&id, &[m0])?); // partial commitments
let (v0, v1) = (a0.prepare_reveal(&id, &[c1])?, a1.prepare_reveal(&id, &[c0])?); // partials
assert_eq!(a0.prepare_finish(&id, &[v1])?, Verdict::Accepted);
assert_eq!(a1.prepare_finish(&id, &[v0])?, Verdict::Accepted);
// (`fhe_prio3::local::verdict(&mut aggs, &report)` runs the same rounds.)

// Verified release: the collector checks every partial decryption with
// blinded known-answer checks before it decodes anything (spec §4.4).
let collector = Collector::new(cfg, &material)?;
let shares = vec![a0.aggregate_share()?, a1.aggregate_share()?];
let mut pending = collector.release_challenge(0, shares)?;
let commits = vec![a0.release_commit(&pending.challenge)?, a1.release_commit(&pending.challenge)?];
let opening = collector.release_open(&mut pending, commits)?;
let reveals = vec![a0.release_reveal(&opening)?, a1.release_reveal(&opening)?];
let result = collector.release_finish(&pending, &reveals)?;
```

Security: the claims, assumptions and proof sketches are in
[SECURITY.md](SECURITY.md). The internal adversarial review, its findings,
and the package for an external audit are in [AUDIT.md](AUDIT.md). Neither
is an external audit.
