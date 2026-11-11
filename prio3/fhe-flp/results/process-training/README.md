# Separate-process PINE training evidence

Source: `bcbdac1` (full hash in `provenance.json`).

- Three complete rounds; four client processes, one evaluator process and one
  collector process per round. Actual PIDs are in `rounds.jsonl` / `processes.json`.
- Real UCI/scikit-learn digit data, 650 parameters, 1,437 training images and 360
  held-out images. Same deterministic split/configuration as the earlier run.
- Every encrypted sum exactly matched the independent integer reference; each
  model update also matched. Final held-out accuracy: 88.06% after three rounds.
- 50 Rust tests passed (22 library, 17 PINE, 8 training, 3 process-boundary).
  Five Python transport tests passed. Formatting and Clippy with warnings denied
  passed. This is a targeted regression run, not a rerun of unrelated modules.
- `model-final.bin` is the public-dataset model checkpoint, next round=3.

The collector executable generates and retains its own secret key; the driver
never receives it. Raw reports travel only from client to evaluator through the
qualification driver. Reference integer updates are kept out of server inputs.
No keys, client-local CSV files, report ciphertexts, or private ledgers are
committed in this evidence directory.

**Not established:** protection from malicious same-user processes, remote
channel security, malicious-evaluator computation authentication, or the complete
collector-view privacy theorem. The runner explicitly uses
`--allow-unverified-evaluator`; without that flag collector startup is refused.
This guard is not a proof and is not a repair of the substitution attack.

See `../../PINE-PROCESS-DEPLOYMENT.md` for operation and scope, and
`../../PINE-EVALUATION-PROOF-OBLIGATIONS.md` for the outstanding cryptographic work.
