//! Direct bucket-index encoding, exact finite-domain SIMD lookup.
use fhe_prio3::{
    messages::{self, Report},
    packed::{Codec, Expect},
};
use openfhe_tbgv_rs::*;
use serde_json::json;
fn main() {
    assert_eq!(OPENFHE_VERSION, "1.4.2");
    let ctx = Context::new_single(
        Params {
            plain_mod: 65537,
            mult_depth: 18,
            security_bits: 128,
        },
        7,
    )
    .unwrap();
    assert_eq!(ctx.ring_dim(), 32768);
    verify_single_rebuild_once(&ctx, 18).unwrap();
    let n = ctx.ring_dim() as usize;
    let row = n / 2;
    let (pk, sk) = keygen_first(&ctx).unwrap();
    let tag = pk.tag().unwrap();
    let m = EvalMultKey::single(&ctx, &sk).unwrap();
    let mb = m.serialize().unwrap().len();
    ctx.install_eval_mult_key(&m, &tag).unwrap();
    drop(m);
    let indices: Vec<i32> = (0..14).map(|j| -(1 << j)).collect();
    let k = RotationKeys::first(&ctx, &sk, &indices).unwrap();
    let kb = k.serialize().unwrap().len();
    ctx.install_rotation_keys(&k, &tag).unwrap();
    drop(k);
    let pkb = pk.serialize().unwrap();
    let codec = Codec::new(&ctx, &pk, &pkb).unwrap();
    println!(
        "{}",
        json!({"status":"PROFILE","p":65537,"ring":n,"depth":18,"digits":7,"key_switch":"HYBRID","rotation_key_bytes":kb,"mult_key_bytes":mb,"public_key_bytes":pkb.len(),"q":ctx.moduli().unwrap(),"qp":ctx.key_basis_moduli(KeyBasis::KeySwitch).unwrap(),"encoding":"scalar bucket index","libraries":loaded_openfhe_libraries().unwrap()})
    );
    let mut mask = vec![0; n];
    mask[0] = 1;
    let mask = ctx.plaintext(&mask).unwrap();
    let ones = ctx.plaintext(&vec![1; n]).unwrap();
    for length in [3usize, 8] {
        let block = length.next_power_of_two();
        let shifts = ctx
            .plaintext(&(0..n).map(|j| (j % block) as u64).collect::<Vec<_>>())
            .unwrap();
        let weights = ctx
            .plaintext(
                &(0..n)
                    .map(|j| u64::from(j < row && j % block < length))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let mut expected = vec![0; length];
        let mut aggregate: Option<Ciphertext> = None;
        for value in [0, length as u64 - 1, length as u64, 65536, 32768] {
            let mut values = vec![65536; n];
            values[0] = value;
            let cipher = ctx.encrypt(&pk, &ctx.plaintext(&values).unwrap()).unwrap();
            let chunk = codec.encode(&cipher).unwrap();
            let mut report = Report {
                task_id: [0xE3; 32],
                report_id: [0; 32],
                group: 0,
                chunks: vec![chunk],
                auth: None,
            };
            report.report_id = Report::compute_id(&report.task_id, report.group, &report.chunks);
            let wire = messages::encode(&report).unwrap();
            assert_eq!(wire.len(), 6176895);
            let report: Report = messages::decode(&wire).unwrap();
            let input = codec
                .decode(&report.chunks[0], Expect::Exactly(codec.fresh_meta()))
                .unwrap();
            let mut x = ctx.mult_plain(&input, &mask).unwrap();
            for j in 0..14 {
                x = ctx.add(&x, &ctx.rotate(&x, -(1 << j)).unwrap()).unwrap();
            }
            let mut z = ctx.sub_plain(&x, &shifts).unwrap();
            for _ in 0..16 {
                z = ctx.square(&z).unwrap();
            }
            let eq = ctx.negate(&ctx.sub_plain(&z, &ones).unwrap()).unwrap();
            let out = ctx.mult_plain(&eq, &weights).unwrap();
            assert!(out.meta().unwrap().level <= 18);
            let outwire = codec.encode(&out).unwrap();
            let back = codec.decode(&outwire, Expect::Any).unwrap();
            let valid = value < (length as u64);
            for (j, v) in sk.decrypt_single(&back, n).unwrap().into_iter().enumerate() {
                assert_eq!(
                    v,
                    u64::from(j < row && valid && j % block == value as usize),
                    "length {length} value {value} slot {j}"
                );
            }
            if valid {
                expected[value as usize] += 1;
            }
            aggregate = Some(match aggregate {
                None => out,
                Some(a) => ctx.add(&a, &out).unwrap(),
            });
            println!(
                "{}",
                json!({"status":"HISTOGRAM_REPORT_PASS","length":length,"value":value,"valid":valid,"report_bytes":wire.len(),"all_slots_checked":n})
            );
        }
        let wire = codec.encode(aggregate.as_ref().unwrap()).unwrap();
        let back = codec.decode(&wire, Expect::Any).unwrap();
        for (j, v) in sk.decrypt_single(&back, n).unwrap().into_iter().enumerate() {
            assert_eq!(
                v,
                if j < row && j % block < length {
                    expected[j % block]
                } else {
                    0
                }
            );
        }
        println!(
            "{}",
            json!({"status":"HISTOGRAM_PASS","length":length,"reports":5,"aggregate":expected,"report_bytes":6176895,"production_security_certified":false})
        );
    }
}
