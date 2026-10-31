//! End-to-end tests of the protocol against prio 0.18.1's plaintext FLP.
use fhe_flp::bitvec::BitVec;
use fhe_flp::{Aggregator, Client, Collector, Field, PLAIN_MOD, Task, TaskParams, Verdict, VerifierMap, key_ceremony};
use prio::field::FieldElement;
use prio::flp::types::Count;
use prio::flp::{Flp, Type};

fn params(n: usize, k: usize) -> TaskParams {
    TaskParams {
        task_id: [7u8; 32],
        num_aggregators: n,
        num_proofs: k,
    }
}

struct World<'a, T: VerifierMap<Field>> {
    task: &'a Task<T>,
    aggs: Vec<Aggregator<'a, T>>,
    verify_key: [u8; 32],
}

fn world<T: VerifierMap<Field>>(task: &Task<T>) -> (openfhe_tbgv_rs::PublicKey, World<'_, T>) {
    let (pk, shares) = key_ceremony(task).unwrap();
    let verify_key = [42u8; 32];
    let aggs = shares
        .into_iter()
        .enumerate()
        .map(|(i, s)| Aggregator::new(task, i, s, &pk, verify_key).unwrap())
        .collect();
    (pk, World { task, aggs, verify_key })
}

impl<T: VerifierMap<Field>> World<'_, T> {
    /// Runs one report through every aggregator; returns every verdict.
    fn submit(&mut self, report: &[u8]) -> Vec<Verdict> {
        let mut states = Vec::new();
        let mut shares = Vec::new();
        for a in self.aggs.iter_mut() {
            let (st, sh) = a.prepare_init(report).unwrap();
            states.push(st);
            shares.push(sh);
        }
        // shares arrive in a different order than they were made
        shares.reverse();
        self.aggs.iter_mut().zip(states).map(|(a, st)| a.prepare_finish(st, &shares).unwrap()).collect()
    }
    fn result(&self) -> T::AggregateResult {
        let shares: Vec<Vec<u8>> = self.aggs.iter().map(|a| a.aggregate_share().unwrap()).collect();
        Collector::new(self.task).unwrap().unshard(&shares).unwrap()
    }
}

fn agreed(v: &[Verdict]) -> bool {
    assert!(v.windows(2).all(|w| w[0] == w[1]), "aggregators disagree: {v:?}");
    v[0].accepted
}

#[test]
fn count_end_to_end_two_and_three_aggregators() {
    for n in [2, 3] {
        let task = Task::new(Count::<Field>::new(), params(n, 4)).unwrap();
        assert_eq!(task.context().ring_dim(), 8192);
        let (pk, mut w) = world(&task);
        let ms = [true, false, true, true, false, true];
        for m in ms {
            let r = Client::new(&task, &pk).shard(&m).unwrap();
            assert_eq!(r.len(), task.report_len());
            assert!(agreed(&w.submit(&r)));
        }
        assert_eq!(w.result(), ms.iter().filter(|&&b| b).count() as u32);
    }
}

#[test]
fn decrypted_verifier_is_exactly_prio_query_and_prio3_combined_verifier() {
    let task = Task::new(Count::<Field>::new(), params(2, 4)).unwrap();
    let (pk, mut w) = world(&task);
    let typ = Count::<Field>::new();
    for m in [false, true] {
        let input = typ.encode_measurement(&m).unwrap();
        let (r, z) = Client::new(&task, &pk).shard_with_witness(&input).unwrap();
        let v = w.submit(&r);
        assert!(agreed(&v));
        let qrs = task.query_rands(&w.verify_key, &r).unwrap();
        let (il, pl, vl) = (typ.input_len(), typ.proof_len(), typ.verifier_len());
        for (p, qr) in qrs.iter().enumerate() {
            let proof = &z[il + p * pl..il + (p + 1) * pl];
            let plain = typ.query(&input, proof, qr, &[], 1).unwrap();
            assert_eq!(&v[0].verifier[p * vl..(p + 1) * vl], &plain[..], "proof {p}");
            // Prio3: each of two aggregators queries its additive share with
            // num_shares = 2; the verifier message is the sum of the two.
            let s0_in: Vec<Field> = input.iter().map(|_| Field::from(123456789u32)).collect();
            let s1_in: Vec<Field> = input.iter().zip(&s0_in).map(|(&x, &s)| x - s).collect();
            let s0_pf: Vec<Field> = proof.iter().enumerate().map(|(i, _)| Field::from(1000 + i as u32)).collect();
            let s1_pf: Vec<Field> = proof.iter().zip(&s0_pf).map(|(&x, &s)| x - s).collect();
            let a = typ.query(&s0_in, &s0_pf, qr, &[], 2).unwrap();
            let b = typ.query(&s1_in, &s1_pf, qr, &[], 2).unwrap();
            let combined: Vec<Field> = a.iter().zip(&b).map(|(&x, &y)| x + y).collect();
            assert_eq!(combined, plain);
        }
    }
}

#[test]
fn linear_map_reproduces_query_on_random_points() {
    let typ = BitVec::<Field>::new(10).unwrap();
    let task = Task::new(typ.clone(), params(2, 3)).unwrap();
    let qrs = task.query_rands(&[1u8; 32], &[9u8; 40]).unwrap();
    let (rows, consts) = task.linear_map(&qrs).unwrap();
    // closed form and the column-by-column reading of Flp::query agree
    assert_eq!(task.linear_map_by_query(&qrs).unwrap(), (rows.clone(), consts.clone()));
    let l = task.layout().clone();
    for trial in 0..5u32 {
        let z: Vec<Field> = (0..l.z_len as u32)
            .map(|i| Field::from(i.wrapping_mul(2_246_822_519).wrapping_add(trial * 77) % 4_000_000_000))
            .collect();
        for (p, qr) in qrs.iter().enumerate() {
            let want = typ
                .query(
                    &z[..l.input_len],
                    &z[l.input_len + p * l.proof_len..l.input_len + (p + 1) * l.proof_len],
                    qr,
                    &[],
                    1,
                )
                .unwrap();
            for r in 0..l.verifier_len {
                let row = &rows[p * l.verifier_len + r];
                let got = row.iter().zip(&z).fold(Field::zero(), |a, (&x, &y)| a + x * y) + consts[p * l.verifier_len + r];
                assert_eq!(got, want[r]);
            }
        }
    }
}

#[test]
fn invalid_inputs_with_honestly_computed_proofs_are_rejected() {
    let task = Task::new(Count::<Field>::new(), params(2, 4)).unwrap();
    let (pk, mut w) = world(&task);
    let client = Client::new(&task, &pk);
    for bad in [2u32, 3, (PLAIN_MOD - 1) as u32, 1 << 31] {
        let (r, _) = client.shard_with_witness(&[Field::from(bad)]).unwrap();
        assert!(!agreed(&w.submit(&r)), "x = {bad} accepted");
    }
    let good = client.shard(&true).unwrap();
    assert!(agreed(&w.submit(&good)));
    // only the valid report is counted
    assert_eq!(w.result(), 1);
}

#[test]
fn bitvec_end_to_end_and_rejects_a_single_non_bit() {
    let typ = BitVec::<Field>::new(100).unwrap();
    let task = Task::new(typ.clone(), params(2, 5)).unwrap();
    let (pk, mut w) = world(&task);
    let client = Client::new(&task, &pk);
    let mut want = vec![0u32; 100];
    for s in 0..4u32 {
        let m: Vec<bool> = (0..100).map(|i| (i * 7 + s * 3) % 5 < 2).collect();
        for (c, &b) in want.iter_mut().zip(&m) {
            *c += b as u32;
        }
        assert!(agreed(&w.submit(&client.shard(&m).unwrap())));
    }
    for (pos, val) in [(0usize, 2u32), (57, (PLAIN_MOD - 1) as u32), (99, 5)] {
        let mut input = vec![Field::zero(); 100];
        input[pos] = Field::from(val);
        let (r, _) = client.shard_with_witness(&input).unwrap();
        assert!(!agreed(&w.submit(&r)), "element {pos} = {val} accepted");
    }
    assert_eq!(w.result(), want);
}

#[test]
fn tampered_proofs_are_rejected() {
    let task = Task::new(Count::<Field>::new(), params(2, 4)).unwrap();
    let (pk, mut w) = world(&task);
    let client = Client::new(&task, &pk);
    let input = Count::<Field>::new().encode_measurement(&true).unwrap();
    let (_, z) = client.shard_with_witness(&input).unwrap();
    for i in 1..z.len() {
        let mut t = z.clone();
        t[i] += Field::one();
        assert!(!agreed(&w.submit(&client.report_from_coefficients(&t).unwrap())), "coefficient {i}");
    }
    // the untampered coefficients pass
    assert!(agreed(&w.submit(&client.report_from_coefficients(&z).unwrap())));
}

#[test]
fn malformed_and_replayed_reports_are_refused() {
    let task = Task::new(Count::<Field>::new(), params(2, 2)).unwrap();
    let (pk, mut w) = world(&task);
    let r = Client::new(&task, &pk).shard(&true).unwrap();
    assert!(w.aggs[0].prepare_init(&r[1..]).is_err());
    let mut longer = r.clone();
    longer.push(0);
    assert!(w.aggs[0].prepare_init(&longer).is_err());
    // all-ones residue bytes are at or above their modulus
    let mut ones = r.clone();
    ones[16..40].fill(0xff);
    assert!(w.aggs[0].prepare_init(&ones).is_err());
    // first use passes, a replay of the nonce does not
    w.submit(&r);
    assert!(w.aggs[0].prepare_init(&r).is_err());
}

#[test]
fn a_flipped_ciphertext_bit_is_not_accepted() {
    let task = Task::new(Count::<Field>::new(), params(2, 4)).unwrap();
    let (pk, mut w) = world(&task);
    let client = Client::new(&task, &pk);
    let mut accepted = 0;
    for pos in [16usize, 1000, 50_000, 200_000, 374_700] {
        let mut r = client.shard(&true).unwrap();
        r[pos] ^= 1;
        let mut states = Vec::new();
        let mut shares = Vec::new();
        let mut parsed = true;
        for a in w.aggs.iter_mut() {
            match a.prepare_init(&r) {
                Ok((st, sh)) => {
                    states.push(st);
                    shares.push(sh);
                }
                Err(_) => parsed = false,
            }
        }
        if parsed {
            for (a, st) in w.aggs.iter_mut().zip(states) {
                accepted += a.prepare_finish(st, &shares).unwrap().accepted as usize;
            }
        }
    }
    assert_eq!(accepted, 0);
}

#[test]
fn shares_from_the_wrong_parties_are_refused() {
    let task = Task::new(Count::<Field>::new(), params(2, 2)).unwrap();
    let (pk, mut w) = world(&task);
    let r = Client::new(&task, &pk).shard(&true).unwrap();
    let (st, sh0) = w.aggs[0].prepare_init(&r).unwrap();
    // aggregator 0's share twice
    assert!(w.aggs[0].prepare_finish(st, &[sh0.clone(), sh0.clone()]).is_err());
}

/// BitVec claiming one element of joint randomness, as Prio3SumVec's
/// circuit uses: the protocol must refuse it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct WithJointRand(BitVec<Field>);
impl Flp for WithJointRand {
    type Field = Field;
    fn gadget(&self) -> Vec<Box<dyn prio::flp::Gadget<Field>>> {
        self.0.gadget()
    }
    fn num_gadgets(&self) -> usize {
        self.0.num_gadgets()
    }
    fn valid(&self, g: &mut Vec<Box<dyn prio::flp::Gadget<Field>>>, x: &[Field], _j: &[Field], n: usize) -> Result<Vec<Field>, prio::flp::FlpError> {
        self.0.valid(g, x, &[], n)
    }
    fn input_len(&self) -> usize {
        self.0.input_len()
    }
    fn proof_len(&self) -> usize {
        self.0.proof_len()
    }
    fn verifier_len(&self) -> usize {
        self.0.verifier_len()
    }
    fn joint_rand_len(&self) -> usize {
        1
    }
    fn eval_output_len(&self) -> usize {
        self.0.eval_output_len()
    }
    fn prove_rand_len(&self) -> usize {
        self.0.prove_rand_len()
    }
}
impl Type for WithJointRand {
    type Measurement = Vec<bool>;
    type AggregateResult = Vec<u32>;
    fn encode_measurement(&self, m: &Vec<bool>) -> Result<Vec<Field>, prio::flp::FlpError> {
        self.0.encode_measurement(m)
    }
    fn truncate(&self, x: Vec<Field>) -> Result<Vec<Field>, prio::flp::FlpError> {
        self.0.truncate(x)
    }
    fn decode_result(&self, d: &[Field], n: usize) -> Result<Vec<u32>, prio::flp::FlpError> {
        self.0.decode_result(d, n)
    }
    fn output_len(&self) -> usize {
        self.0.output_len()
    }
}
impl VerifierMap<Field> for WithJointRand {
    fn max_output_value(&self) -> u64 {
        1
    }
}

#[test]
fn unsupported_tasks_are_refused() {
    assert!(Task::new(WithJointRand(BitVec::new(10).unwrap()), params(2, 2)).is_err());
    assert!(Task::new(Count::<Field>::new(), params(1, 2)).is_err());
    assert!(Task::new(Count::<Field>::new(), params(2, 0)).is_err());
    // input and proofs larger than the ring
    assert!(Task::new(BitVec::<Field>::new(4000).unwrap(), params(2, 2)).is_err());
}
