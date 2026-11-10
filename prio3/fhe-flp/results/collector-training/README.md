# Collector/training qualification evidence

Source code: commit `d5682a63121fb2b689d5034c87b2302ba342c4f1`.
`provenance.json` identifies source files, binary, libraries, dataset and build environment.

- Full suite: 84 tests passed. The eight new tests were rerun after the final
  descriptor-parameter validation guard; that rerun also passed.
- `cargo fmt --check` and `cargo clippy --release --all-targets -- -D warnings` passed.
- Real data: UCI handwritten digits (scikit-learn copy, pinned/hash-checked by
  `scripts/fetch_training_digits.py`). 1,437 training / 360 held-out examples.
- Four clients, 650-parameter softmax model, five complete rounds, proof counts
  7 main / 4 norm-equality. Every encrypted sum exactly equals its integer
  plaintext reference; each model update and checkpoint also matches exactly.
- Initial held-out accuracy: 13.06%; final: 88.61%. This is one deterministic
  data split and training configuration, not a generalization or convergence guarantee.
- Per round: 6,963,648 client-report bytes, 53,166,836 check-request bytes,
  122,952 aggregate-request bytes. Key/setup traffic and peak memory are not measured.
- `model-final.bin` is the resulting model/state checkpoint (`TrainingState::load`).
  It contains public-dataset model weights and round=5; no client or collector keys.

The round times are single observations on a shared cloud machine, not a
controlled performance comparison. The single-process runner deliberately holds
the plaintext reference. It does not demonstrate deployment isolation.

**Security gate remains CLOSED:** the full collector-view privacy proof and
malicious-evaluator computation authentication are absent. A passing test named
`known_limit_an_evaluator_that_deviates_can_substitute_the_sum` demonstrates an
attack that STILL succeeds. The bounded session does not repair it.

See `../../PINE-COLLECTOR-TRAINING.md` for the implementation, recovery semantics,
source-inspected decryption facts, and remaining obligations.
