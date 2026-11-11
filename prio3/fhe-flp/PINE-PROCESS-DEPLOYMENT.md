# Separate PINE/BGV role processes

**Functional process separation is implemented and exercised. Cryptographic
collector privacy and malicious-evaluator computation authentication remain
open. This is not a production-security release.**

## Implemented roles

`pine_role` is a real executable using the existing OpenFHE/PINE implementation.

| Process command | Inputs | Outputs |
|---|---|---|
| `keygen PRIVATE_KEY_FILE` | OS randomness | Private Ed25519 key file (0600), public identity frame |
| `init-model FEATURES CLASSES MODEL_FILE` | Model dimensions | Initial immutable model checkpoint |
| `task MODEL JOB_JSON IDENTITIES TASK_FILE` | Public model/config/cohort | Canonical signed-report task descriptor |
| `client TASK MODEL JOB_JSON LOCAL_CSV CLIENT_KEY PUBLIC_KEY` | That client's data/signing key and public round state | One signed PINE/BGV report frame |
| `evaluator TASK LEDGER PUBLIC_KEY REPORT_COUNT` | Public key and report frames; then collector verdict | Check-request frame; then aggregate frame |
| `collector TASK LEDGER REPORT_COUNT --allow-unverified-evaluator` | Public task; check and aggregate frames | Public key, verdict, then released sum |
| `update TASK MODEL JOB_JSON RELEASE_FILE NEW_MODEL TEST_CSV` | Authorized local release path, current model/config | New immutable model and evaluation metric |
| `reference TASK MODEL JOB_JSON LOCAL_CSV` | Qualification-only local data | Quantized integer reference; never forwarded to either server |

The collector generates its full BGV secret key internally. The executable has
no secret-key export command, and the driver never receives that key. No client
training data or raw client report is sent to the collector by the driver.
The evaluator receives no collector key. Local training and model update code
are the same tested library code as the earlier single-process qualification.

The explicit `--allow-unverified-evaluator` switch is required because the
collector still cannot authenticate the evaluator's ciphertext computation.
Without it, startup refuses before reading task files or generating a key.
This is a fail-closed deployment guard, **not a fix for the substitution attack**.
The library's lower-level APIs retain their documented research behavior.

## Transport and failure behavior

`process_wire` frames use magic `PNEIPC01`, a one-byte role/message kind, a
little-endian u64 payload length, then the payload. Each receiving role enforces
its expected kind and task-specific length limit before allocating/reading the
body. Input files have explicit size caps. JSON configuration rejects unknown
fields; task/model/config consistency is checked before local training.

The Python driver uses directly connected local pipes, nonblocking descriptors,
and deadlines for both reads and writes. A peer that stops reading cannot defeat
the write deadline by filling a pipe. Children have a minimal environment and
are reaped, with unfinished children killed on failure. Worker errors are a
single refusal string. Task reservations survive process exit; an aborted
collector task cannot simply restart and decrypt more inputs.

The released-sum frame includes the task descriptor's SHA-256 digest, accepted
count, and exact dyadic sums. The updater checks the digest, model, round,
configuration and integer-domain bounds. **That digest is not authentication**:
this local driver trusts its private pipe to the child it launched. A remote
transport needs authenticated peer provisioning and channels; framing alone is
not TLS, a signature, or an execution proof.

## What the run establishes

Run after building and fetching the public digit dataset:

    cargo build --release --bin pine_role
    python3 scripts/train_pine_processes.py \
        /ABSOLUTE/PATH/TO/pine_role /PATH/TO/digits.csv /NEW/OUTPUT/DIRECTORY \
        --rounds 3 --clients 4 --allow-unverified-evaluator

The runner launches distinct processes for the four clients, evaluator,
collector, task preparation and model updates. A separate reference path checks
exact integer sums and model updates; its values do not enter either server's
input. Every round records the actual process IDs and exact-match outcomes.
The local datasets, signing keys and collector/evaluator ledgers remain in the
private run directory and are NOT included in committed evidence.

The processes in this qualification run share a machine and OS user. Different
PIDs and working directories do not establish protection from a malicious
same-user process, ptrace, a privileged host, shared filesystem access, or
colluding operators. Production roles need separate administrative boundaries
and protected storage/channel provisioning. This run establishes separate
address spaces and protocol data flow, not that deployment threat model.

## Remaining cryptographic work

See `PINE-EVALUATION-PROOF-OBLIGATIONS.md`. A proof must cover the check request
BEFORE any admission measurement or verifier opening, and the aggregate BEFORE
release. It must bind both to the exact client-signed reports without revealing
those reports to the full-key collector. Process isolation does not supply this
proof. No zkVM guest, proving key, execution receipt or collector-view simulator
is added by this change.
