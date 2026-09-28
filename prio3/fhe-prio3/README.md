# fhe-prio3

Prio3's five measurement types (Count, Sum, SumVec, Histogram,
MultihotCountVec) with the validity check evaluated homomorphically under an
n-of-n threshold BGV key. The protocol, its security argument and measured
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
cargo test --release            # ~2 minutes; tests serialise themselves
cargo run --release --bin simulate -- --type sum --max 100 --reports 4
cargo run --release --bin simulate -- --type histogram --length 64 --aggregators 3
cargo run --release --bin simulate -- --type sumvec --length 1200 --bits 4
```

Both crates are standalone Cargo workspaces (the parent `prio3` workspace
references a vendored `libprio-rs` that is not in git).

## Modes and authentication

```rust
// Verdict mode (default): two rounds per report, aggregators learn accept/reject.
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
cargo run --release --bin simulate -- --type sum --max 100 --mode silent --reports 2
cargo run --release --bin simulate -- --type count --auth --reports 4
```

## Library use

```rust
use fhe_prio3::*;

let cfg = TaskConfig::new(task_id, MeasurementType::Sum { max_measurement: 100 }, 2);
// Key ceremony: in production each party runs the steps in `keys` over the
// network; `run_local_ceremony` executes them in one process.
let (material, shares) = keys::run_local_ceremony(&cfg)?;

let client = Client::new(cfg.clone(), &material.context, &material.public_key)?;
let report = client.shard(&Measurement::Sum(51))?;          // same bytes to every aggregator

let mut a0 = Aggregator::new(cfg.clone(), &material, 0, &shares[0], None)?;
let mut a1 = Aggregator::new(cfg.clone(), &material, 1, &shares[1], None)?;
let m0 = a0.prepare_init(&report)?;  let m1 = a1.prepare_init(&report)?;   // broadcast masks
let v0 = a0.prepare_masks(&report.report_id, &[m1])?;
let v1 = a1.prepare_masks(&report.report_id, &[m0])?;                       // broadcast partials
assert_eq!(a0.prepare_finish(&report.report_id, &[v1])?, Verdict::Accepted);
assert_eq!(a1.prepare_finish(&report.report_id, &[v0])?, Verdict::Accepted);

let collector = Collector::new(cfg, &material)?;
let (aggregate, count) = collector.unshard(&[a0.aggregate_share()?, a1.aggregate_share()?])?;
```
