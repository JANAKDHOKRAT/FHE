> Historical pre-phase-guard measurements. Current source contains the guard. See the package README for current status. Archive this dataset before rerunning: run.py appends results and overwrites metadata.

# Reproduce the experimental comparison

These results are for the local encrypted-verdict candidate, **without W1**.
No production-security certification or completed full-size qualification is claimed.

1. Build OpenFHE 1.3.1 and use the same OPENFHE_DIR/LD_LIBRARY_PATH for both binaries.
2. Set CARGO_TARGET_DIR to a writable shared build directory, and OMP_NUM_THREADS=2.
3. In fhe-flp, run:

   ```sh
   cargo test --release --locked -- --test-threads=1
   cargo fmt --check
   cargo clippy --release --all-targets --locked -- -D warnings
   cargo build --release --locked --bins
   BATCHES=16 python3 results/oblivious/run.py
   python3 results/oblivious/summarize.py
   ```

4. Run the wrapper's full tests and Clippy checks from ../openfhe-tbgv-rs too.
5. The runner appends to measurements.jsonl. Preserve old evidence before a new
   session; machine.json describes the most recently launched session. The
   committed baseline files outside this directory are never overwritten.
6. The saved pre-guard matrix includes BATCHES=16,256,1024. Repeating it with
   the current guard requires a separate evidence dataset. Record unsupported
   workloads and failures; do not describe it as W1 privacy qualification.

The Python scripts only launch the Rust benchmarks, collect Linux wait4 resource
usage, and check/summarize measured bytes. Encryption, FLP, masking, validation,
aggregation and plaintext-reference correctness assertions execute in Rust/OpenFHE.

The ledger roots created by measure_oblivious are in the OS temporary directory.
They contain consumed-ID marker files, no secret keys. Production code requires
an operator-protected durable directory and externally managed key persistence.
A fresh measurement key is generated for every process; startup/keygen are
recorded separately from core per-batch times.

See OBLIVIOUS-STATUS.md for the exact trust assumptions, proof gaps and protocol.
