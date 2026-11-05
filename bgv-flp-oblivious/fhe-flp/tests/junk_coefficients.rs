//! A client controls its whole plaintext polynomial, not only `z`. The
//! evaluator packs many verifier rows into one plaintext product; a value at
//! a coefficient above `z` meets, in such a product, the rows packed below
//! the one being read. This test builds a Count report for the invalid input
//! 2 whose extra coefficients shift exactly the verifier entries that make
//! prio's `decide` accept, and checks that the protocol rejects it.
use fhe_flp::f65537::Field65537 as F;
use fhe_flp::single::{Evaluator, SingleClient, SingleCollector, SingleTask};
use prio::field::{FieldElement, NttFriendlyFieldElement};
use prio::flp::Flp;
use prio::flp::types::Count;

const VK: [u8; 32] = [31u8; 32];

/// prio's Count proof for one gadget (Mul): two wire seeds, then the gadget
/// polynomial. A proof whose seeds are 0 and whose gadget polynomial is the
/// constant `c`, on input 0, has verifier `[c, 0, 0, c]` at every query
/// point: circuit output `p(alpha) - x = c`, wires 0, `p(r) = c`.
fn constant_proof<G: NttFriendlyFieldElement>(typ: &Count<G>, c: G) -> Vec<G> {
    let mut pf = vec![c; typ.proof_len()];
    pf[0] = G::zero();
    pf[1] = G::zero();
    pf
}

/// The attack plaintext for `k` proofs: `z` for the invalid input 2, then
/// one block of `|z|` coefficients per further verifier row.
fn attack_plaintext<G: NttFriendlyFieldElement>(k: usize, z_len: usize) -> Vec<G> {
    let typ = Count::<G>::new();
    let (il, pl, vl) = (typ.input_len(), typ.proof_len(), typ.verifier_len());
    let rows = k * vl;
    // The building block, checked against prio itself at random points.
    for _ in 0..4 {
        let qr = G::random_vector(typ.query_rand_len());
        let c = G::one() + G::one();
        let v = typ.query(&[G::zero()], &constant_proof(&typ, c), &qr, &[], 1).unwrap();
        assert_eq!(v, vec![c, G::zero(), G::zero(), c]);
    }
    // Input 2 with each proof's gadget polynomial lowered by 2: circuit
    // output 2*2 - 2 - 2 = 0, and p(r) is 2 short of x(r)*y(r).
    let two = G::one() + G::one();
    let mut z = vec![two];
    for _ in 0..k {
        let mut pf = typ.prove(&[two], &G::random_vector(typ.prove_rand_len()), &[]).unwrap();
        for v in &mut pf[2..] {
            *v -= two;
        }
        z.extend(pf);
    }
    assert_eq!(z.len(), z_len);
    // Shifts wanted: +2 on every proof's p(r) entry, 0 elsewhere. Block b
    // (coefficients [b|z|, (b+1)|z|)) adds its verifier entry (j - b) to
    // entry j; with constant proofs `c_b` that is `c_b` where j - b is an
    // output or p(r) entry. Solve the triangular system.
    let target = |j: usize| if j % vl == vl - 1 { two } else { G::zero() };
    let hits = |d: usize| d.is_multiple_of(vl) || d % vl == vl - 1;
    let mut c = vec![G::zero(); rows];
    for j in 1..rows {
        let earlier = (1..j).filter(|&b| hits(j - b)).fold(G::zero(), |a, b| a + c[b]);
        c[j] = target(j) - earlier;
    }
    let mut plain = z;
    plain.resize(rows * z_len, G::zero());
    for (b, &cb) in c.iter().enumerate().skip(1) {
        for q in 0..k {
            let at = b * z_len + il + q * pl;
            plain[at..at + pl].copy_from_slice(&constant_proof(&typ, cb));
        }
    }
    plain
}

#[test]
fn threshold_coefficients_above_z_cannot_make_an_invalid_count_pass() {
    use fhe_flp::{Aggregator, Client, Field, Task, TaskParams, key_ceremony};
    let k = 4;
    let task = Task::new(
        Count::<Field>::new(),
        TaskParams {
            task_id: [2u8; 32],
            num_aggregators: 2,
            num_proofs: k,
        },
    )
    .unwrap();
    let vl = task.layout().verifier_len;
    assert!(task.layout().rows_per_group >= k * vl);
    let (pk, shares) = key_ceremony(&task).unwrap();
    let mut aggs: Vec<Aggregator<'_, Count<Field>>> = shares
        .into_iter()
        .enumerate()
        .map(|(i, s)| Aggregator::new(&task, i, s, &pk, VK).unwrap())
        .collect();
    let report = Client::new(&task, &pk)
        .report_from_coefficients(&attack_plaintext::<Field>(k, task.layout().z_len))
        .unwrap();
    let mut states = Vec::new();
    let mut msgs = Vec::new();
    for a in aggs.iter_mut() {
        let (st, m) = a.prepare_init(&report).unwrap();
        states.push(st);
        msgs.push(m);
    }
    let verdicts: Vec<_> = aggs.iter_mut().zip(states).map(|(a, st)| a.prepare_finish(st, &msgs).unwrap()).collect();
    let typ = Count::<Field>::new();
    for p in 0..k {
        assert!(typ.decide(&verdicts[0].verifier[p * vl..(p + 1) * vl]).unwrap(), "proof {p}");
    }
    assert!(verdicts.iter().all(|v| !v.accepted), "Count = 2 must be rejected");
    assert_eq!(verdicts[0].reason.as_deref(), Some("plaintext is not 0 above z"));
}

/// One nonzero coefficient anywhere above `z` of an otherwise valid report
/// is rejected, in both protocols.
#[test]
fn a_single_coefficient_above_z_is_rejected() {
    use fhe_flp::{Aggregator, Client, Field, Task, TaskParams, key_ceremony};
    // one aggregator
    let task = SingleTask::new(Count::<F>::new(), [3u8; 32], 9).unwrap();
    let (n, zl) = (task.layout().ring, task.layout().z_len);
    let (mut collector, pk) = SingleCollector::new(&task).unwrap();
    let client = SingleClient::new(&task, &pk);
    let mut reports = vec![client.shard(&true).unwrap()];
    for at in [zl, zl + 1, n / 2, n - 1] {
        let (_, mut z) = client.shard_with_witness(&[F::one()]).unwrap();
        z.resize(at + 1, F::zero());
        z[at] = F::one();
        reports.push(client.report_from_coefficients(&z).unwrap());
    }
    let mut ev = Evaluator::new(&task, &pk, VK).unwrap();
    for r in &reports {
        ev.ingest(r).unwrap();
    }
    assert_eq!(collector.check(&ev.check_request().unwrap()).unwrap(), vec![0b00001]);

    // threshold
    let task = Task::new(
        Count::<Field>::new(),
        TaskParams {
            task_id: [4u8; 32],
            num_aggregators: 2,
            num_proofs: 4,
        },
    )
    .unwrap();
    let (n, zl) = (task.layout().ring, task.layout().z_len);
    let (pk, shares) = key_ceremony(&task).unwrap();
    let mut aggs: Vec<Aggregator<'_, Count<Field>>> = shares
        .into_iter()
        .enumerate()
        .map(|(i, s)| Aggregator::new(&task, i, s, &pk, VK).unwrap())
        .collect();
    let client = Client::new(&task, &pk);
    for at in [None, Some(zl), Some(zl + 1), Some(n / 2), Some(n - 1)] {
        let (_, mut z) = client.shard_with_witness(&[Field::one()]).unwrap();
        if let Some(at) = at {
            z.resize(at + 1, Field::zero());
            z[at] = Field::one();
        }
        let report = client.report_from_coefficients(&z).unwrap();
        let mut states = Vec::new();
        let mut msgs = Vec::new();
        for a in aggs.iter_mut() {
            let (st, m) = a.prepare_init(&report).unwrap();
            states.push(st);
            msgs.push(m);
        }
        let verdicts: Vec<_> = aggs.iter_mut().zip(states).map(|(a, st)| a.prepare_finish(st, &msgs).unwrap()).collect();
        assert!(verdicts.iter().all(|v| v.accepted == at.is_none()), "{at:?}");
    }
}

#[test]
fn coefficients_above_z_cannot_make_an_invalid_count_pass() {
    let typ = Count::<F>::new();
    let k = 9;
    let task = SingleTask::new(typ.clone(), [1u8; 32], k).unwrap();
    let vl = task.layout().verifier_len;
    assert!(task.layout().rows_per_group >= k * vl, "the attack needs all rows in one product");
    let plain = attack_plaintext::<F>(k, task.layout().z_len);

    let (mut collector, pk) = SingleCollector::new(&task).unwrap();
    let client = SingleClient::new(&task, &pk);
    let reports = vec![client.shard(&true).unwrap(), client.report_from_coefficients(&plain).unwrap()];
    let mut ev = Evaluator::new(&task, &pk, VK).unwrap();
    for r in &reports {
        ev.ingest(r).unwrap();
    }
    let (verdicts, verifiers) = collector.check_with_verifiers(&ev.check_request().unwrap()).unwrap();
    // The shifts work: prio's own decide accepts every proof's verifier...
    for p in 0..k {
        assert!(typ.decide(&verifiers[1][p * vl..(p + 1) * vl]).unwrap(), "proof {p}");
    }
    // ...and the report is rejected because its plaintext is not supported
    // on z (the collector's support check).
    assert_eq!(verdicts[0] & 1, 1, "the honest report is accepted");
    assert_eq!(verdicts[0] >> 1 & 1, 0, "Count = 2 must be rejected");
    let total = collector.unshard(&ev.aggregate_request(&verdicts).unwrap()).unwrap();
    assert_eq!(total, 1);
}
