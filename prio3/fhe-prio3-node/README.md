# fhe-prio3-node

Network deployment of [fhe-prio3](../fhe-prio3): aggregator and collector
servers over HTTPS, a client, SQLite persistence with crash-resume, and key
shares sealed at rest.

## Roles and topology

* **Aggregator `i`** (`fhe-prio3-node aggregator --index i`): one process
  per key share. Aggregator 0 is the *leader*: clients submit to it, and it
  drives the per-report rounds (verdict mode) or forwards reports (silent
  mode) to the helpers, then drives the batch close. Helpers only answer
  authenticated calls from the leader.
* **Collector** (`fhe-prio3-node collector`): receives one aggregate share
  per aggregator, unshards when all are present, serves the result. Holds no
  key.
* **Client** (`fhe-prio3-node submit`): fetches a group ticket when the task
  batches, encrypts, signs if the task requires it, submits to the leader.

All node-to-node calls carry a bearer token in `x-fhe-prio3-token` over TLS
and are refused otherwise. Bodies are bincode, capped at the size of a fresh
report plus 64 KiB; the collector caps at 256 MiB.

## Endpoints

| Path | Who calls | Auth | Body → reply |
| --- | --- | --- | --- |
| `GET /v1/status` | anyone | none | → `StatusReply` |
| `GET /v1/group` | client → leader | none | → `GroupTicket` (silent batched tasks) |
| `POST /v1/submit` | client → leader | none | `Report` → `SubmitOutcome` |
| `POST /v1/close` | operator → leader | token | `()` → `BatchResult` |
| `POST /v1/report` | leader → helper | token | `Report` → `Result<MaskMessage,String>` (verdict) / `SubmitOutcome` (silent) |
| `POST /v1/masks` | leader → helper | token | `MasksRequest` → `VerifierMessage` |
| `POST /v1/verifiers` | leader → helper | token | `VerifiersRequest` → `SubmitOutcome` |
| `POST /v1/count-share` | leader → helper | token | `()` → `CountShare` |
| `POST /v1/count-finish` | leader → helper | token | `CountFinishRequest` → `u64` |
| `POST /v1/aggregate-share` | leader → helper | token | `()` → `AggregateShare` |
| `POST /v1/aggregate-share` | leader → collector | token | `ShareEnvelope` → `Option<BatchResult>` |
| `GET /v1/result` | operator → collector | token | → `Option<BatchResult>` |

## Persistence and restart

Every state-changing step (an accepted verdict-mode report, an admitted
silent-mode report, the count round, the aggregate share) commits the
aggregator's `AggregatorState` snapshot plus the report bytes it may still
need in one SQLite transaction (`journal_mode=WAL`, `synchronous=FULL`). A
restarted node with the same database, task file and share resumes from the
last committed step; a report whose processing was interrupted before its
commit is simply not in `seen` and is reprocessed when resubmitted. The
end-to-end test restarts the leader mid-batch and finishes the batch.

The key share file is AES-256-GCM sealed with the 32-byte key in
`FHE_PRIO3_SEAL_KEY` (hex), authenticated with the aggregator index and task
id as associated data, so a share cannot be moved to another aggregator or
task. Production supplies that environment key from a KMS or HSM.

## Concurrency model

OpenFHE work is CPU-bound and shares process-global key tables, so each node
holds one `Aggregator` behind a mutex and runs every homomorphic step on the
blocking pool under that lock. Throughput per node is therefore one report
at a time (0.5–0.7 s in verdict mode); scale by running more aggregator
*sets* under different tasks or keys, not by threads inside one node.

## Setup

```sh
export FHE_PRIO3_SEAL_KEY=$(openssl rand -hex 32)
fhe-prio3-node task-config --out task.bin --type sum:100 --aggregators 2 --mode verdict --auth-quota 1
fhe-prio3-node keygen --task task.bin --out-dir keys/        # material.bin, share-0.sealed, share-1.sealed
fhe-prio3-node client-identity --out client.key              # prints the public key to enrol

fhe-prio3-node collector  --task task.bin --material keys/material.bin --db col.db --listen 0.0.0.0:8443 \
    --token "$TOKEN" --tls-cert col.pem --tls-key col.key
fhe-prio3-node aggregator --index 1 --task task.bin --material keys/material.bin --share keys/share-1.sealed \
    --db agg1.db --listen 0.0.0.0:8444 --aggregators https://agg0:8443,https://agg1:8444 \
    --collector https://collector:8443 --token "$TOKEN" --tls-cert agg1.pem --tls-key agg1.key --ca ca.pem --clients clients.txt
fhe-prio3-node aggregator --index 0 ... (same, --share keys/share-0.sealed)

fhe-prio3-node submit --task task.bin --material keys/material.bin --leader https://agg0:8443 --ca ca.pem \
    --value sum:51 --identity client.key
fhe-prio3-node close --leader https://agg0:8443 --ca ca.pem --token "$TOKEN"
```

`keygen` runs the whole ceremony in one process. The ceremony is a sequence
of serialized messages (`fhe_prio3::keys`); running it across machines
means moving those files between parties in the documented order, which is
an operational procedure rather than new code.

## Tests

`cargo test --release --test e2e` starts two aggregators and a collector on
random localhost ports with certificates generated on the fly, then runs:
verdict-mode Count with an invalid report, a replay, a wrong internal token,
a leader restart from its database mid-batch, batch close, and post-close
rejection; and a silent batched Sum with an out-of-range report. It needs
`FHE_PRIO3_SEAL_KEY` set only for the CLI, not for the tests.
