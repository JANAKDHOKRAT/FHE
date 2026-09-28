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
* **Router** (`fhe-prio3-node router`, optional): front of a *sharded*
  deployment, see below. Holds no key, sees no ciphertext.

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
| `GET /v1/assign` | client → router | none | → `Assignment { shard, leader }` |
| `GET /v1/shard/{i}/task` | client → router | none | → `TaskConfig` of shard `i` |
| `GET /v1/shard/{i}/material` | client → router | none | → `PublicMaterial` of shard `i`, evaluation keys stripped |
| `GET /v1/shards` | anyone | none | → `Vec<Assignment>` |
| `POST /v1/close-all` | operator → router | token | `()` → combined `BatchResult` |

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
*sets* under different tasks or keys, not by threads inside one node. That
is what sharding below does.

## Sharding: many aggregator sets in parallel

A base task is split into `S` *shard tasks* (`keygen-shards --shards S`),
each an independent `TaskConfig` with its own task id
(`SHA-256("fhe-prio3/1 shard" || base id || i)`), its own key ceremony and
therefore its own joint key, and its own aggregator set and collector. The
shards never talk to each other. A report encrypted for shard `i` is
accepted only by shard `i`: its task id is bound into the report id, the
Fiat–Shamir challenge and the signature, and its ciphertexts are under a
key no other shard holds. Every shard runs exactly the single-set protocol,
so the security argument of the spec applies to each shard unchanged; a
malicious client that could beat one shard could beat one set, and cannot
do more damage by being sharded.

The **router** is the only public address. `GET /v1/assign` hands a client
a shard (round robin) and that shard's leader URL; the client fetches the
shard's task and client material once per shard, encrypts under that
shard's key and submits to that shard's leader. `POST /v1/close-all` closes
every shard through its leader and returns the combined result
(`fhe_prio3::sharding::combine_results`): aggregates and counts are added,
regression moments are added and the fit is recomputed. The router never
holds a key share, a ciphertext or a partial decryption; compromising it
lets an attacker steer clients between shards and nothing else. At startup
the router checks every leader's `/v1/status` and refuses to run if leader
`i` does not serve shard `i`'s task as aggregator 0. A shard below its
minimum batch fails the whole close; nothing partial is returned, the
shards already closed stay closed, and the operator retries `close-all`
once the short shard has reached its minimum (the closed shards return
their released result again).

Closing is idempotent. Each aggregator releases its partial decryptions
**once** per batch and stores them in its persisted state; a repeated
`close` (retry after a network failure, a leader restart, a second
`close-all`) returns the same bytes. Without this a repeated close would
have handed out a fresh noise-flooded partial decryption of the same
ciphertext each time, giving an observer more samples of the same
secret-dependent value to average; this was found by the sharded test and
fixed in the protocol crate.

```sh
fhe-prio3-node keygen-shards --task task.bin --shards 2 --out-dir shards/
# per shard i: start its collector and aggregators from shards/shard-i/ as above
fhe-prio3-node router --shards-dir shards/ --leaders https://l0:8443,https://l1:8443 \
    --listen 0.0.0.0:9443 --token "$TOKEN" --tls-cert r.pem --tls-key r.key --ca ca.pem
fhe-prio3-node submit-sharded --router https://router:9443 --ca ca.pem --value sum:42
fhe-prio3-node close-all --router https://router:9443 --ca ca.pem --token "$TOKEN"
```

Measured on this machine (4 vCPUs, verdict-mode Sum, 16 reports submitted
concurrently, each shard = 2 aggregator processes + 1 collector process,
`OMP_NUM_THREADS` pinned per process, `tests/sharded.rs`):

| shards × threads per aggregator process | wall time for 16 reports, run 1 | run 2 |
| --- | --- | --- |
| 1 × 1 | 24.2 s | 19.1 s |
| 2 × 1 | 13.3 s | 11.8 s |
| 1 × 4 | 19.1 s | 15.6 s |
| 2 × 2 | 17.0 s | 14.0 s |

With one thread per process the two shards run on four cores instead of
two and finish in 1.6–1.8× less time (1.82× and 1.62× in the two runs):
the shards are independent and parallelise. With the thread budget fixed
at four, sharding gains only 1.1×, because a single shard's OpenMP threads
already occupy every core.
Sharding therefore buys throughput in proportion to the *machines* added,
not from splitting one saturated machine; on one 4-core box the
single-set numbers in the spec are what it delivers.

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

`cargo test --release --test sharded -- --nocapture` launches the built
binary as separate processes (`keygen-shards`, per shard two aggregators
and a collector, one router) for each of the four configurations in the
table above, submits 16 reports concurrently through the router, checks
the combined result against the plaintext sum, checks that a second
`close-all` returns byte-identical output, a wrong token gets 401, an
unknown shard gets 404, and clients receive no evaluation keys. Timings
are printed and written to `$TMPDIR/fhe_prio3_sharding_timing.txt`; they
are not asserted, since they depend on the machine.
