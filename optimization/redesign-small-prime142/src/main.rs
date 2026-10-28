//! Exact bounded Sum lookup, separate scalar encoding and research harness.
use fhe_prio3::{
    messages::{self, Report},
    packed::{Codec, Expect},
};
use openfhe_tbgv_rs::*;
use serde_json::json;
fn pow(mut x: u64) -> u64 {
    for _ in 0..16 {
        x = x * x % 65537;
    }
    x
}
fn main() {
    assert_eq!(OPENFHE_VERSION, "1.4.2");
    // Exhaustive algebraic equivalence over the entire field, not just honest inputs.
    for x in 0..65537u64 {
        let mut f = 0;
        for a in 1..=100 {
            f = (f + a * (1 + 65537 - pow((x + 65537 - a) % 65537))) % 65537;
        }
        assert_eq!(f, if x <= 100 { x } else { 0 }, "x={x}");
    }
    println!(
        "{}",
        json!({"status":"ALGEBRA_PASS","field_elements":65537,"max":100})
    );
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
    let mult = EvalMultKey::single(&ctx, &sk).unwrap();
    let mult_bytes = mult.serialize().unwrap().len();
    ctx.install_eval_mult_key(&mult, &tag).unwrap();
    drop(mult);
    let mut indices = vec![];
    let mut d = 1;
    while d < row {
        indices.push(-(d as i32));
        d *= 2;
    }
    for d in [1, 2, 4, 8, 16, 32, 64] {
        indices.push(d);
    }
    let k = RotationKeys::first(&ctx, &sk, &indices).unwrap();
    let key_bytes = k.serialize().unwrap().len();
    ctx.install_rotation_keys(&k, &tag).unwrap();
    drop(k);
    let pk_bytes = pk.serialize().unwrap();
    let codec = Codec::new(&ctx, &pk, &pk_bytes).unwrap();
    let libs = loaded_openfhe_libraries().unwrap();
    assert!(libs.iter().all(|s| s.ends_with(".so.1.4.2")));
    println!(
        "{}",
        json!({"status":"PROFILE","p":65537,"ring":n,"depth":18,"key_switch":"HYBRID","digits":7,"q":ctx.moduli().unwrap(),"qp":ctx.key_basis_moduli(KeyBasis::KeySwitch).unwrap(),"libraries":libs,"public_key_bytes":pk_bytes.len(),"mult_key_bytes":mult_bytes,"rotation_key_bytes":key_bytes,"rotations":indices})
    );
    let mut m = vec![0; n];
    m[0] = 1;
    let mask = ctx.plaintext(&m).unwrap();
    let mut shifts = vec![0; n];
    let mut weights = vec![0; n];
    for j in 0..row {
        shifts[j] = (j % 128) as u64;
        if (1..=100).contains(&(j % 128)) {
            weights[j] = (j % 128) as u64;
        }
    }
    let shifts = ctx.plaintext(&shifts).unwrap();
    let weights = ctx.plaintext(&weights).unwrap();
    let ones = ctx.plaintext(&vec![1; n]).unwrap();
    let batches = vec![vec![0, 1, 99, 100, 101, 65536, 32768, 2], vec![100; 32]];
    let mut total_reports = 0;
    for (batch, values) in batches.into_iter().enumerate() {
        assert!(values.len() <= 32 && values.len() * 100 < 65537);
        let mut aggregate: Option<Ciphertext> = None;
        let mut expected = 0u64;
        let mut report_bytes = 0;
        for &value in &values {
            // Modified client contaminates every unauthorized slot and the second row.
            let mut slots = vec![65536; n];
            slots[0] = value;
            let encrypted = ctx.encrypt(&pk, &ctx.plaintext(&slots).unwrap()).unwrap();
            let chunk = codec.encode(&encrypted).unwrap();
            let mut r = Report {
                task_id: [0xE1; 32],
                report_id: [0; 32],
                group: 0,
                chunks: vec![chunk],
                auth: None,
            };
            r.report_id = Report::compute_id(&r.task_id, r.group, &r.chunks);
            let wire = messages::encode(&r).unwrap();
            assert_eq!(wire.len(), 6176895);
            report_bytes = wire.len();
            let report: Report = messages::decode(&wire).unwrap();
            let input = codec
                .decode(
                    &report.chunks[0],
                    Expect::Exactly(encrypted.meta().unwrap()),
                )
                .unwrap();
            let mut x = ctx.mult_plain(&input, &mask).unwrap();
            let mut d = 1;
            while d < row {
                x = ctx.add(&x, &ctx.rotate(&x, -(d as i32)).unwrap()).unwrap();
                d *= 2;
            }
            let mut z = ctx.sub_plain(&x, &shifts).unwrap();
            for _ in 0..16 {
                z = ctx.square(&z).unwrap();
            }
            let equal = ctx.negate(&ctx.sub_plain(&z, &ones).unwrap()).unwrap();
            let mut out = ctx.mult_plain(&equal, &weights).unwrap();
            for d in [1, 2, 4, 8, 16, 32, 64] {
                out = ctx.add(&out, &ctx.rotate(&out, d).unwrap()).unwrap();
            }
            assert!(out.meta().unwrap().level <= 18);
            let encoded = codec.encode(&out).unwrap();
            let restored = codec.decode(&encoded, Expect::Any).unwrap();
            let plain = sk.decrypt_single(&restored, n).unwrap();
            let want = if value <= 100 { value } else { 0 };
            for (j, v) in plain.into_iter().enumerate() {
                assert_eq!(v, if j < row { want } else { 0 }, "input {value}, slot {j}");
            }
            expected += want;
            aggregate = Some(match aggregate {
                None => out,
                Some(a) => ctx.add(&a, &out).unwrap(),
            });
            println!(
                "{}",
                json!({"status":"REPORT_PASS","batch":batch,"value":value,"expected":want,"bytes":wire.len(),"all_slots_checked":n})
            );
        }
        let final_wire = codec.encode(aggregate.as_ref().unwrap()).unwrap();
        let final_ct = codec.decode(&final_wire, Expect::Any).unwrap();
        for (j, v) in sk
            .decrypt_single(&final_ct, n)
            .unwrap()
            .into_iter()
            .enumerate()
        {
            assert_eq!(v, if j < row { expected } else { 0 });
        }
        total_reports += values.len();
        println!(
            "{}",
            json!({"status":"SUM100_PASS","batch":batch,"reports":values.len(),"sum":expected,"report_bytes":report_bytes,"all_output_slots_checked":n,"encoding":"scalar lookup; repeated scalar output, not paper bit/slack encoding","production_security_certified":false})
        );
    }
    println!(
        "{}",
        json!({"status":"ALL_SUM100_PASS","reports":total_reports,"batches":2})
    );
}
