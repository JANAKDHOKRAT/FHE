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
* **Collector** (`fhe-prio3-node collector --id c`): receives one aggregate
  share per aggregator; when all are present, it verifies every partial
  decryption with blinded checks, then decodes and serves the result.
  Holds no key share. With release policies (below) it holds its own X25519
  sealing key and receives only what the task's policy `c` names.
* **Client** (`fhe-prio3-node submit`): fetches a group ticket when the task
  batches, encrypts, signs if the task requires it, submits to the leader.
* **Router** (`fhe-prio3-node router`, optional): front of a *sharded*
  deployment, see below. Holds no key, sees no ciphertext.

All node-to-node calls carry a bearer token in `x-fhe-prio3-token` over TLS
and are refused otherwise. Bodies are postcard (serde; one value has one encoding, and a trailing byte is refused). Every ciphertext inside a body
is in the packed wire format (spec §6b). It is parsed in safe Rust, and none
reaches OpenFHE's deserializer. Body limits are set per route:

* The public routes `/v1/submit` and `/v1/close` are capped at the packed
  size of one report plus 64 KiB.
* The internal routes are capped at the largest internal message plus
  64 KiB. That message is either a report or the `n − 1` masks the leader
  sends each helper in one `/v1/masks` request, whichever is larger.
* The verification routes (`/v1/count-*` after the share,
  `/v1/release-*`) carry checks and partials of every aggregator and are
  capped at 256 MiB.
* The collector caps at 512 MiB.

A single cap of one report used to refuse the `/v1/masks` request of a
three-aggregator verdict deployment, which carries two masks.
`tests/e2e.rs::three_aggregators_verdict_over_tls` reproduces that failure
and passes with the split. The same test also uploads hostile chunks: one
in OpenFHE's own format, one with a wrong fingerprint, one with a residue
above its modulus and one a byte short. The test checks that each is
refused and that the leader keeps serving.

Startup checks. Every node refuses to start unless the OpenFHE libraries
it loaded are the tested version. Aggregators and the collector then run a
self-test that rebuilds every kind of exchanged object at every level the
task reaches with throwaway keys, and refuse to start if any rebuild is not
exact (spec §6b). The self-test takes about 2 s in verdict mode and about
30 s in silent mode, once per process.

Upgrading across the change of message codec (bincode 1, unmaintained
per RUSTSEC-2025-0141, to postcard): finish collecting every batch before
upgrading. Task files, public material, sealed shares and persisted node
state written by an earlier build are in the old encoding and are refused
with a serialization error; re-run `task-config` and the ceremony for new
tasks. The packed ciphertext wire format is unchanged.

Upgrading across the change to the packed format: finish collecting every
batch before upgrading. The database layout is unchanged, but an earlier
build stored other parties' ciphertexts in OpenFHE's format. On such a
database:

* an aggregator node starts only if its batch is an open verdict-mode
  batch, which it resumes;
* an aggregator with pending silent-mode reports, or with a count share or
  aggregate shares already released, refuses to start and names the reason;
* a collector with shares waiting for the rest refuses to start and names
  the reason;
* a collector whose result is already stored starts and serves it.

Released shares cannot be issued again, because each ciphertext's partial
decryption is released once, so a batch released but not collected before
the upgrade can only be collected by the build that released it. Clients
and aggregators of one task must run the same format; an old-format report
is refused with `BadMagic`.

## Endpoints

| Path | Who calls | Auth | Body → reply |
| --- | --- | --- | --- |
| `GET /v1/status` | anyone | none | → `StatusReply` |
| `GET /v1/group` | client → leader | none | → `GroupTicket` (silent batched tasks) |
| `POST /v1/submit` | client → leader | none | `Report` → `SubmitOutcome` |
| `POST /v1/close` | operator → leader | token | `()` → `CloseReply{result (no policies), released_to}` |
| `POST /v1/report` | leader → helper | token | `Report` → `Result<MaskCommit,String>` (verdict) / `SubmitOutcome` (silent) |
| `POST /v1/mask-commits` | leader → helper | token | `MaskCommitsRequest` → `MaskMessage` (revealed once every mask commitment is in) |
| `POST /v1/masks` | leader → helper | token | `MasksRequest` → `VerifierCommit` (commitment to its partial) |
| `POST /v1/commits` | leader → helper | token | `CommitsRequest` → `VerifierMessage` (revealed once every commitment is in) |
| `POST /v1/verifiers` | leader → helper | token | `VerifiersRequest` → `SubmitOutcome` |
| `POST /v1/count-share` | leader → helper | token | `()` → `CountShare` (partial and checks) |
| `POST /v1/count-commit` | leader → helper | token | `CountSharesRequest` → `CountCommit` |
| `POST /v1/count-open` | leader → helper | token | `CountCommitsRequest` → `CountOpening` |
| `POST /v1/count-reveal` | leader → helper | token | `CountOpeningsRequest` → `CountReveal` |
| `POST /v1/count-finish` | leader → helper | token | `CountRevealsRequest` → `u64` (verified count) |
| `POST /v1/aggregate-share` | leader → helper | token | `ShareRequest{collector}` → `ShareReply::Plain` (no policies) / `::Sealed` |
| `POST /v1/release-commit` | leader → helper | token | `ReleaseChallenge` → `ReleaseCommit` |
| `POST /v1/release-reveal` | leader → helper | token | `ReleaseOpening` → `RevealEnvelope::Plain` (no policies) / `::Sealed` |
| `POST /v1/aggregate-share` | leader → collector | token | `ShareEnvelope` (no policies) / `SealedEnvelope` → `ShareReceipt{complete, challenge}` |
| `POST /v1/release-commits` | leader → collector | token | `ReleaseCommitsRequest` → `ReleaseOpening` |
| `POST /v1/release-reveals` | leader → collector | token | `ReleaseRevealsRequest` → `FinishReceipt{result (no policies)}` |
| `GET /v1/result` | operator → collector | token | → `Option<BatchResult>` |

Verification flows (spec §3.4–§3.6, §4.4). *Verdict:* `/v1/report` (mask
commitments), `/v1/mask-commits` (masks), `/v1/masks` (partial
commitments), `/v1/commits` (partials), `/v1/verifiers`.
*Silent close:* `/v1/count-share`, `-commit`, `-open`, `-reveal`,
`-finish`; each helper verifies the count with its own checks before
anything is released. *Release to a collector:* the helpers'
`/v1/aggregate-share`; the collector answers the last share with a
challenge; the helpers' `/v1/release-commit`; the collector's
`/v1/release-commits` returns the opening; the helpers'
`/v1/release-reveal`; the collector's `/v1/release-reveals` verifies and
stores the result. The leader relays every message. With policies, shares
and reveals are sealed to the collector, so the leader reads none of them.
A malicious leader can still stop a release by answering the challenge
itself first (`AUDIT.md` F-8).
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

The only client reports a restart needs are those of the silent-mode
verification ciphertext still open (at most `silent_batch_groups` of them):
`restore` rebuilds that ciphertext from them. A report is stored when it is
admitted and deleted in the same transaction as the snapshot that no longer
lists it (its ciphertext was verified and folded into the sums); verdict
mode adds a report to the sums when it is accepted and stores none. The
database therefore stays bounded by one verification ciphertext's reports
and the snapshot, whatever the batch size. Earlier builds kept every report
(22 MiB each in silent mode: 1.4 TB for a batch of 65,536); a node started
on such a database deletes the rows no restore needs.
`tests/e2e.rs` checks the stored reports after every submission.

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

## Monitoring: metrics, health, alerts

Every node (`aggregator`, `collector`, `router`) takes
`--metrics-listen <addr>` and serves there, over plain HTTP (bind it to a
private interface):

* `GET /metrics`: Prometheus text format, one registry per node;
* `GET /healthz`: 200 while the process answers (liveness);
* `GET /readyz`: 200 when the node can serve, 503 after a panic poisoned
  its state (it refuses every step until restarted; restart it and it
  resumes from its last committed step).

`/healthz` and `/readyz` are also on the public TLS listener, for load
balancers. A metrics address that cannot be bound stops the node from
starting, so a node never runs unmonitored by accident. Nodes stop
gracefully on SIGTERM and SIGINT (30 s for requests in flight).

What the series tell an operator (`src/metrics.rs` documents each):

| Question | Series |
| --- | --- |
| Is a node stuck? | `fhe_prio3_step_active_since_timestamp_seconds` (start of the step holding the state lock, 0 when idle), `fhe_prio3_lock_waiters`, `fhe_prio3_last_progress_timestamp_seconds` |
| Is it slow? | `fhe_prio3_step_duration_seconds{step}`, `fhe_prio3_lock_wait_seconds`, `fhe_prio3_phase_duration_seconds{phase}` (close, count, gate, release), `fhe_prio3_http_request_duration_seconds{route}`, `fhe_prio3_peer_request_duration_seconds{peer,route}`, `fhe_prio3_db_commit_duration_seconds` |
| Is it failing? | `fhe_prio3_http_requests_total{route,status}`, `fhe_prio3_step_failures_total{step}`, `fhe_prio3_phase_failures_total{phase}`, `fhe_prio3_peer_requests_total{peer,route,outcome}`, `fhe_prio3_reports_total{outcome,reason}`, `fhe_prio3_ready` |
| Capacity | `fhe_prio3_batch{field}` (aggregator: accepted, pending, closed; collector: shares_received, result_ready), `fhe_prio3_db_size_bytes`, `fhe_prio3_db_written_bytes_total`, `process_resident_memory_bytes`, `process_cpu_seconds_total`, `process_open_fds` |

Label values come from fixed sets (route templates, step and phase names
in the code, configured peer URLs, `RejectReason` variant names); nothing
a client sends becomes a label.

`deploy/prometheus/alerts.yml` holds the alerting rules (node down or not
ready, a step stuck, a queue with no progress, a backlog, a stalled release,
slow admissions or commits, failed phases, steps, peer calls and
submissions, a high rejection rate, a growing database, high memory) and
`deploy/prometheus/alerts.test.yml` tests every rule with `promtool test
rules`, a firing and a non-firing case each; CI runs both
(`promtool check rules`, `promtool test rules`). A unit test
(`metrics::tests::every_series_the_alert_rules_name_is_exported`) fails if a
rule names a series no node exports. `deploy/prometheus/prometheus.yml` is
an example scrape configuration.

`tests/e2e.rs` scrapes the nodes' `/metrics` after real traffic and checks
the exact values: reports by outcome and reason, requests by route and
status, steps, phases, peer calls, batch gauges, no failures, idle locks.

## Load test

`fhe-prio3-node loadtest` drives real clients against a running
deployment: `--workers` threads, each with its own client and OpenFHE
context, take a group ticket, encrypt a measurement and submit it over TLS.
The measurements are a deterministic function of `--seed` (histograms are
skewed, bucket `b` with probability `2^-(b+1)`, so every run has large cells
and cells below a suppression threshold), and `--invalid-every n` makes
every n-th report invalid (a non-bit slot). After the last report the batch
is closed and the released result compared with the expected one:

* the exact aggregate of the valid reports, the valid count, the admitted
  count;
* with small-cell suppression: the cells below `min_cell_count` zeroed and
  listed, the others exact, the counts withheld;
* below `min_batch_size`: a refusal, either the leader's (fewer reports
  admitted than the minimum) or, with enough reports admitted but too few
  valid, the encrypted gate's, which only the gate can know.

Throughout, every node's `/metrics` is scraped into a timeline (resident
memory, database size, lock waiters, batch gauges), and the last scrape of
each node goes into the JSON report with the client-side timings (ticket,
encryption, submission round trip, percentiles), the outcomes, the close's
duration and the verdict. The command exits non-zero unless the released
result is exactly the expected one and every report was delivered.

`loadtest/run.sh` brings up a split-key deployment as separate processes
over TLS (certificates, task, keys, the collector and the aggregator with
metrics listeners), runs the load test and stops the nodes:

```sh
cargo build --release
loadtest/run.sh --out /tmp/lt --reports 1024 --type histogram:16 \
    --min-batch 1000 --min-cell 100 --invalid-every 2 --workers 2 --keys keygen
```

`--keys ceremony` runs the distributed ceremony (one process per key
party); at the production parameters its two processes do not fit on one
15 GiB machine (AUDIT.md F-25), so single-machine runs use `--keys keygen`
(the same keys from one dealer process). The collector runs on the
material without evaluation keys (`client-material`), which is all it uses.

Measured on one 4-vCPU, 15 GiB machine running the client threads, the
aggregator and the collector together, at the production silent-mode
parameters (ring 65536, depth 28, 64 groups, 7 repetitions; reports of
23,085,183 bytes), `histogram:16`:

| Run | Result | Submission | Close | Peaks |
| --- | --- | --- | --- | --- |
| 128 reports, 12 invalid, `min_batch 3`, `min_cell 3`, 2 workers | exact; cells below 3 suppressed and listed, counts withheld | 121.9 s, 1.05 reports/s; encryption mean 0.58 s; submit p50 0.63 s, p99 21.1 s | 225.8 s (gate 131.7 s, release 69.1 s) | aggregator 9.20 GiB resident, 2.2 GiB database; collector 4.25 GiB, 1.3 GiB |
| 1024 reports, 512 invalid, `min_batch 1000`, `min_cell 100`, 2 workers | refused by the encrypted gate (512 valid < 1000, with 1024 admitted) | 911.6 s, 1.12 reports/s | 1158.2 s (gate 1060 s, of which the gates' products 957 s) | aggregator 9.15 GiB, 2.2 GiB; collector 4.40 GiB, 1.3 GiB |

What the numbers say, from the nodes' own metrics:

* A report costs the aggregator a mean of 0.80 s of state-lock time
  (`fhe_prio3_step_duration_seconds{step="silent_admit"}`), of which about
  0.33 s is its share of the batch verification (about 21 s per 64
  reports, which is also the p99 of a submission: the report that
  completes a verification ciphertext waits for it) and about 0.18 s the
  database commit of the report (kept until its ciphertext is verified,
  for restore).
* The release gates cost about 0.9 s per factor on this machine (957 s for
  the products over 1001 batch-size factors and 101 cell factors): they
  dominate the close at large thresholds and grow linearly with them; their
  memory stays bounded (AUDIT.md F-22).
* The aggregator's resident peak is at start-up, while the evaluation keys
  are loaded (4.4 GB of material); it then runs at about 5-6 GiB. The
  database stays bounded by one verification ciphertext's reports
  (AUDIT.md F-21).
* Submissions here are bounded by the client threads sharing the machine
  with the servers; the server-side capacity is the inverse of the mean
  admission time.

## Release policies: several collectors, each seeing only its elements

A task may declare `collectors`, each with the elements of the aggregate
it receives, whether it receives the second moments of those elements, and
an X25519 sealing key (`fhe-prio3-node collector-identity`). The policy is
part of the task, hence of its digest and of the attested material: it
cannot change after the batch opens, and every aggregator enforces it on
its own.

*How it is enforced.* The report's slots are cut into chunks (one
ciphertext each) at every point where the set of collectors allowed to see
a slot changes, so a chunk lies entirely inside one visibility class.
Releasing to collector `c` is then partially decrypting the chunks whose
class includes `c`, and the second-moment accumulators of pairs inside
`c`'s elements. Nothing that no policy names is ever partially decrypted,
and no extra multiplication level is used in either mode (the alternative,
a plaintext selector before decryption, would not fit silent mode's
25-level budget). A helper answers a release request for collector `c`
with what *its* copy of the task allows for `c`; a leader asking for an
unknown collector gets 400 and cannot widen a release.

*Sealing.* Each aggregator seals its share for collector `c` to `c`'s key
(ephemeral X25519, HKDF-SHA256, AES-256-GCM, associated data = task,
collector id, aggregator index; `fhe_prio3::seal`). The leader relays
opaque envelopes and `close` returns no result on such tasks; each
collector serves its own result to its own operator. Without policies the
leader relays plain shares and returns the result, as before, and could
read every released aggregate; with policies it reads none. Slots serving
a constraint over every element (the weight bits of `MultihotCountVec`)
go only to collectors that see every element; a restricted collector runs
the consistency check on the constraints its slots cover.

*Bounded releases.* Each aggregator releases once per (batch, collector),
persisted, so the number of noisy partial decryptions per batch is the
number of declared collectors plus the valid count, fixed in the task.
What a deployment reveals is the union of its policies; overlapping
policies reveal nothing beyond that union.

```sh
fhe-prio3-node collector-identity --out col0.sealed    # prints hex public key K0
fhe-prio3-node collector-identity --out col1.sealed    # K1
fhe-prio3-node task-config --out task.bin --type bounded:100,5,15,15 --moments \
    --collector "$K0:0,1" --collector "$K1:2,3:moments"
fhe-prio3-node collector --id 0 --seal-secret col0.sealed ... ; fhe-prio3-node collector --id 1 --seal-secret col1.sealed ...
fhe-prio3-node aggregator ... --collectors https://col0:8444,https://col1:8445
```

`tests/e2e.rs::two_collectors_with_policies_over_tls` runs two collector
nodes with disjoint policies (the second with moments) over TLS: each
serves exactly its elements, the regression is fitted on collector 1's
columns only, a helper refuses an unknown collector id, an envelope sealed
for collector 1 is refused by collector 0 and cannot be opened with its
key, a repeated close is idempotent, and a collector started with a key
the task does not declare, or with none, refuses to start.

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
holds a key share, a ciphertext or a partial decryption.

**What the router is trusted with: nothing that touches privacy.** The
material a client encrypts under is *attested*: `keygen`/`keygen-shards`
give each aggregator a long-term Ed25519 identity (sealed at rest under
the deployment key, reused across shards) and every aggregator signs each
shard's task digest, context, joint public key, joint tag and rotation
indices (`fhe_prio3::attest`). Clients pin the aggregators' public keys
(`aggregator-keys.txt`, distributed out of band like a CA bundle) and a
sharded client refuses material that lacks a valid attestation from every
aggregator. A compromised router can therefore steer clients between
shards, refuse service, or close shards early with the operator token; it
cannot make a client encrypt under a key of its own or under a different
task, because that would need every aggregator's signature, which is the
collusion the scheme does not defend against anyway. The file-based
`submit` accepts `--aggregator-keys` for the same check. At startup
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
fhe-prio3-node keygen-shards --task task.bin --shards 2 --out-dir shards/   # also shards/aggregator-keys.txt, shards/identities/
# per shard i: start its collector and aggregators from shards/shard-i/ as above
fhe-prio3-node router --shards-dir shards/ --leaders https://l0:8443,https://l1:8443 \
    --listen 0.0.0.0:9443 --token "$TOKEN" --tls-cert r.pem --tls-key r.key --ca ca.pem
fhe-prio3-node submit-sharded --router https://router:9443 --ca ca.pem --aggregator-keys aggregator-keys.txt --value sum:42
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

## Key setup across machines (`ceremony`)

Each aggregator generates its own key share on its own machine; no
machine, file or process ever holds another aggregator's share. The
aggregators run `fhe-prio3-node ceremony` at the same time, each serving
its signed messages over HTTPS and reading the others'
(`fhe_prio3::ceremony`, spec §6b "Distributed key ceremony"):

```sh
# once per aggregator machine i, with that machine's own FHE_PRIO3_SEAL_KEY
fhe-prio3-node init-identity --index $i --out-dir /srv/agg    # prints its public key
# collect the n printed keys, line i = aggregator i, into aggregator-keys.txt,
# distribute it (and task.bin) to every aggregator and to clients; agree on a session:
SESSION=$(openssl rand -hex 32)
# on every machine, at the same time:
fhe-prio3-node ceremony --task task.bin --index $i \
    --identity /srv/agg/aggregator-$i.identity.sealed --aggregator-keys aggregator-keys.txt \
    --session $SESSION --listen 0.0.0.0:9000 \
    --aggregators https://agg0:9000,https://agg1:9000,https://agg2:9000 \
    --token "$TOKEN" --tls-cert agg.pem --tls-key agg.key --ca ca.pem --out-dir /srv/agg
# -> /srv/agg/material.bin (identical on every machine, attested by all),
#    /srv/agg/share-$i.sealed (this machine's share only), /srv/agg/transcript.txt
```

What it defends against, in order: a party choosing the common `a` with a
trapdoor (it is expanded from a hash of seeds committed before any was
revealed); a rogue public-key share chosen after seeing the others'
(every contribution is committed, signed, before any is revealed); a
malformed contribution (only `b` residues travel, checked for length and
against every tower modulus in the shim before OpenFHE builds anything,
never through OpenFHE's deserializer); a well-formed but wrong contribution
or partial decryption (a joint key check encrypts a jointly random vector
under the joint key, squares it, rotates it by every index and decrypts
with every party's committed partial decryption; a single wrong slot
aborts); equivocation (every party signs the hash of the whole transcript
and of the joint material, and attests the material). Any party can stop
the ceremony (n-of-n); a stopping party's server answers 410 with its
reason and the others stop instead of waiting. The transcript digest is
printed and written so operators can compare it out of band.

For a sharded deployment, `shard-tasks --task task.bin --shards S --out-dir
shards/` writes each shard's task, and the aggregators run `ceremony` once
per shard task (a fresh session each).

`keygen` and `keygen-shards` run every party in one process (a dealer that
sees every share). They remain for tests and trials; a deployment uses
`ceremony`.

## Setup

```sh
export FHE_PRIO3_SEAL_KEY=$(openssl rand -hex 32)
fhe-prio3-node task-config --out task.bin --type sum:100 --aggregators 2 --mode verdict --auth-quota 1
# keys: `ceremony` on each aggregator machine (above), or for a single-machine trial:
fhe-prio3-node keygen --task task.bin --out-dir keys/        # material.bin, share-0.sealed, share-1.sealed
fhe-prio3-node client-identity --out client.key              # prints the public key to enrol

fhe-prio3-node client-material --material keys/material.bin --out keys/client-material.bin  # for clients and collectors
fhe-prio3-node collector  --task task.bin --material keys/client-material.bin --db col.db --listen 0.0.0.0:8443 \
    --token "$TOKEN" --tls-cert col.pem --tls-key col.key
fhe-prio3-node aggregator --index 1 --task task.bin --material keys/material.bin --share keys/share-1.sealed \
    --db agg1.db --listen 0.0.0.0:8444 --aggregators https://agg0:8443,https://agg1:8444 \
    --collector https://collector:8443 --token "$TOKEN" --tls-cert agg1.pem --tls-key agg1.key --ca ca.pem --clients clients.txt
fhe-prio3-node aggregator --index 0 ... (same, --share keys/share-0.sealed)

fhe-prio3-node submit --task task.bin --material keys/material.bin --leader https://agg0:8443 --ca ca.pem \
    --value sum:51 --identity client.key
fhe-prio3-node close --leader https://agg0:8443 --ca ca.pem --token "$TOKEN"
```

## Tests

`cargo test --release --test ceremony_node` runs the distributed ceremony
as three OS processes of the binary, each with its own seal key, identity
and output directory, over TLS: the three write byte-identical attested
material and transcripts, each machine holds only its own share (which
does not open under another machine's seal key), and the shares run the
protocol. A party started on another task configuration makes all three
stop without writing any key material.

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
unknown shard gets 404, clients receive no evaluation keys, the served
material verifies under the pinned aggregator keys, a client pinning a
different key refuses it, one shard's attestations do not validate
another shard's material, and a misordered leader list stops the router. Timings
are printed and written to `$TMPDIR/fhe_prio3_sharding_timing.txt`; they
are not asserted, since they depend on the machine.
