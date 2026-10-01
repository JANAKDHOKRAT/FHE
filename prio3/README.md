# Prio3 And FHE

This folder has:

- Porting of the BGV scheme to rust
- 2 FHE protocol prototypes that try to mimic the Prio3 shape

For a detailed comparison between draft Prio3 VDAF and a possible BGV-FHE reinterpretation, see [PRIO3_VS_BGV.md](./PRIO3_VS_BGV.md). That document focuses on what ports cleanly, what only works after redesign, and what is not portable to the BGV schema as-is.

## Why We Cannot Just "Use FHE On Prio3"

Prio3 is not only "encrypt values and add them".

Prio3 also depends on:

- splitting one client report into shares
- joint validation by the aggregators
- verifier messages between aggregators
- protocol rules that reject bad reports

FHE helps with computing on encrypted data, but it does not automatically give us the same Prio3 protocol.

One important reason is branches.

In normal Prio3, the protocol can do logical decisions like:

- if this share is bad, reject the report
- if verifier messages do not match, stop
- if validation fails, do not count the report

That is natural in a normal protocol, but not in FHE.

With FHE, we can do arithmetic on ciphertexts, but we cannot cleanly do normal protocol branches inside the encrypted computation. Usually we have to replace those decisions with masks, zeroing, or extra protocol rules, and that changes the protocol design.

So if we replace shares with ciphertexts, we still need to redesign:

- how validity is checked
- what each aggregator receives
- how bad reports are handled
- what privacy and security guarantees still remain

That is why we built new FHE-based protocols that only **mimic the Prio3 structure**:

- client
- aggregators
- collector

Both prototypes are now organized as file-based actor pipelines:

- `setup` generates context and only the key material required by each role
- `client` encrypts reports and writes ciphertext artifacts
- `aggregator` loads context plus eval keys only and writes encrypted aggregate shares
- `collector` loads context plus the secret key and decrypts the final result

## Our 2 FHE Protocols

### `fhe-vdaf-1`

The simplest version.

- the client encrypts the whole value
- the whole encrypted value goes to one aggregator
- the aggregator checks the encrypted bits and sums valid inputs
- the collector adds the aggregator outputs

This looks like Prio3 at a high level, but one aggregator gets the full report ciphertext.

### `fhe-vdaf-2`

A closer Prio3-style version.

- the client scales the value and splits it into one shard per aggregator
- each shard is encrypted
- each aggregator checks and sums only its own shard
- the collector combines the aggregator outputs to recover the final sum

This is closer to Prio3 because one aggregator does not receive the whole value directly.

## In One Sentence

We cannot directly turn Prio3 into "Prio3 with FHE" because Prio3 is a full sharing-and-validation protocol, not just encrypted aggregation, so we built `fhe-vdaf-1` and `fhe-vdaf-2` as simple FHE protocols that mimic its shape.

## fhe-prio3 (sound redesign)

`fhe-prio3/` and `openfhe-tbgv-rs/` contain a redesign of the aggregation
protocol with an n-of-n threshold BGV key, all five Prio3 measurement types,
and a randomised validity check whose soundness is proved in
[fhe-prio3/FHE_PRIO3_SPEC.md](./fhe-prio3/FHE_PRIO3_SPEC.md). That document
also explains why the `sum x_i(x_i-1) = 0` check used by `fhe-vdaf-1` and
`fhe-vdaf-2` can be bypassed and what the redesign still does not guarantee.
`fhe-prio3-node/` is the network deployment (HTTPS nodes, SQLite
persistence, sealed key shares, and a router that shards a task across
independent aggregator sets and combines their results) and
[fhe-prio3/COST_REDUCTION_PLAN.md](./fhe-prio3/COST_REDUCTION_PLAN.md)
records which cost reductions were feasible, implemented and measured.
