use prio::{
    codec::{Encode, ParameterizedDecode},
    vdaf::{
        Aggregator, Client, Collector, Vdaf, VerifyTransition,
        prio3::{Prio3Count, Prio3Histogram, Prio3Sum, Prio3SumVec, optimal_chunk_length},
    },
};
use rand::RngCore;
use serde_json::json;
use std::time::Instant;
fn ns(t: Instant) -> u128 {
    t.elapsed().as_nanos()
}
fn run<V>(
    v: V,
    measurements: Vec<V::Measurement>,
    expected: V::AggregateResult,
    task: &str,
    length: usize,
    construct_ns: u128,
) where
    V: Vdaf<AggregationParam = ()> + Client<16> + Aggregator<32, 16> + Collector,
    V::AggregateResult: PartialEq,
{
    let s = Instant::now();
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let setup_ns = construct_ns + ns(s);
    let mut clients = vec![];
    let mut client_ns = 0;
    let mut report_bytes = vec![];
    let mut total_uplink = vec![];
    for m in &measurements {
        let t = Instant::now();
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let (public, shares) = v.shard(b"full-cost142/v1", m, &nonce).unwrap();
        let p = public.get_encoded().unwrap();
        let shares = shares
            .iter()
            .map(|x| x.get_encoded().unwrap())
            .collect::<Vec<_>>();
        client_ns += ns(t);
        report_bytes.push(p.len() + shares.iter().map(Vec::len).sum::<usize>());
        total_uplink.push(shares.iter().map(Vec::len).sum::<usize>() + 2 * (p.len() + 16));
        clients.push((nonce, p, shares));
    }
    let t = Instant::now();
    let mut outputs = vec![vec![], vec![]];
    let mut verifier_bytes = 0;
    for (nonce, p, shares) in clients {
        let mut states = vec![];
        let mut verifiers = vec![];
        for (id, bytes) in shares.iter().enumerate() {
            let public = V::PublicShare::get_decoded_with_param(&v, &p).unwrap();
            let input = V::InputShare::get_decoded_with_param(&(&v, id), bytes).unwrap();
            let (state, share) = v
                .verify_init(&key, b"full-cost142/v1", id, &(), &nonce, &public, &input)
                .unwrap();
            let wire = share.get_encoded().unwrap();
            verifier_bytes += wire.len();
            let share = V::VerifierShare::get_decoded_with_param(&state, &wire).unwrap();
            states.push(state);
            verifiers.push(share);
        }
        let message = v
            .verifier_shares_to_message(b"full-cost142/v1", &(), verifiers)
            .unwrap();
        let wire = message.get_encoded().unwrap();
        verifier_bytes += wire.len();
        for (id, state) in states.into_iter().enumerate() {
            let message = V::VerifierMessage::get_decoded_with_param(&state, &wire).unwrap();
            match v.verify_next(b"full-cost142/v1", state, message).unwrap() {
                VerifyTransition::Finish(out) => outputs[id].push(out),
                VerifyTransition::Continue(..) => panic!("unexpected extra round"),
            }
        }
    }
    let aggregates = outputs
        .into_iter()
        .map(|x| v.aggregate(&(), x).unwrap().get_encoded().unwrap())
        .collect::<Vec<_>>();
    let server_ns = ns(t);
    let sizes = aggregates.iter().map(Vec::len).collect::<Vec<_>>();
    let t = Instant::now();
    let parts = aggregates
        .iter()
        .map(|x| V::AggregateShare::get_decoded_with_param(&(&v, &()), x).unwrap())
        .collect::<Vec<_>>();
    let result = v.unshard(&(), parts, 4).unwrap();
    let collector_ns = ns(t);
    assert_eq!(result, expected);
    key.fill(0);
    println!(
        "{}",
        json!({"status":"PASS","backend":"Prio3","task":task,"length":length,"batch_size":4,"setup_ns":setup_ns,"client_total_ns":client_ns,"server_total_ns":server_ns,"collector_total_ns":collector_ns,"report_bytes":report_bytes,"total_client_uplink_with_duplicate_public_and_nonce_bytes":total_uplink,"aggregate_wire_bytes":sizes.iter().sum::<usize>(),"aggregate_parts_bytes":sizes,"aggregate_ciphertexts":0,"verifier_artifact_bytes":verifier_bytes,"verification_key_bytes":32,"public_key_bytes":0,"evaluation_key_bytes":0,"expected":format!("{expected:?}"),"actual":format!("{result:?}"),"prio_version":"0.18.1-alpha.3","scope":"two aggregator roles serial; output shares serialized and decoded; no network, HPKE or DAP framing"})
    );
}
fn main() {
    let a: Vec<_> = std::env::args().collect();
    let task = a[1].as_str();
    let length: usize = a.get(2).map(|s| s.parse().unwrap()).unwrap_or(1);
    let t = Instant::now();
    match task {
        "count" => {
            let v = Prio3Count::new_count(2).unwrap();
            let setup = ns(t);
            let m = (0..4)
                .map(|i| full_cost142::bit(i, 0) == 1)
                .collect::<Vec<_>>();
            let e = m.iter().filter(|&&x| x).count() as u64;
            run(v, m, e, task, 1, setup)
        }
        "sum" => {
            let v = Prio3Sum::new_sum(2, 100).unwrap();
            run(v, vec![0, 100, 37, 63], 200, task, 1, ns(t))
        }
        "histogram" => {
            let v = Prio3Histogram::new_histogram(2, length, optimal_chunk_length(length)).unwrap();
            let setup = ns(t);
            let mut e = vec![0u128; length];
            let m = (0..4)
                .map(|i| {
                    e[i % length] += 1;
                    i % length
                })
                .collect();
            run(v, m, e, task, length, setup)
        }
        "sumvec" => {
            let v = Prio3SumVec::new_sum_vec(2, 1, length, optimal_chunk_length(length)).unwrap();
            let setup = ns(t);
            let m = (0..4)
                .map(|i| {
                    (0..length)
                        .map(|j| full_cost142::bit(i, j) as u128)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let mut e = vec![0u128; length];
            for x in &m {
                for (e, x) in e.iter_mut().zip(x) {
                    *e += x;
                }
            }
            run(v, m, e, task, length, setup)
        }
        _ => panic!("task"),
    }
}
