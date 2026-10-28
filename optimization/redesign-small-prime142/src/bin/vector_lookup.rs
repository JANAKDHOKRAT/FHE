//! Exact alternative binary-vector encoding. Isolated complete-circuit experiment.
use fhe_prio3::{
    messages::{self, Report},
    packed::{Codec, Expect},
};
use openfhe_tbgv_rs::*;
use serde_json::json;
fn product(ctx: &Context, mut v: Vec<Ciphertext>) -> Ciphertext {
    while v.len() > 1 {
        let mut next = vec![];
        while let Some(a) = v.pop() {
            next.push(if let Some(b) = v.pop() {
                ctx.mult(&a, &b).unwrap()
            } else {
                a
            });
        }
        v = next;
    }
    v.pop().unwrap()
}
fn main() {
    assert_eq!(OPENFHE_VERSION, "1.4.2");
    let length: usize = std::env::args()
        .nth(1)
        .unwrap_or("100".into())
        .parse()
        .unwrap();
    assert!([10, 25, 50, 100].contains(&length));
    let chunks = length.div_ceil(13);
    let depth = 17 + chunks.next_power_of_two().trailing_zeros();
    let digits = if depth <= 18 { 7 } else { depth + 2 };
    let ctx = Context::new_single(
        Params {
            plain_mod: 65537,
            mult_depth: depth.max(18),
            security_bits: 128,
        },
        digits,
    )
    .unwrap();
    assert_eq!(ctx.ring_dim(), 32768);
    verify_single_rebuild_once(&ctx, depth.max(18)).unwrap();
    let n = ctx.ring_dim() as usize;
    let row = n / 2;
    let (pk, sk) = keygen_first(&ctx).unwrap();
    let tag = pk.tag().unwrap();
    let mult = EvalMultKey::single(&ctx, &sk).unwrap();
    let mult_bytes = mult.serialize().unwrap().len();
    ctx.install_eval_mult_key(&mult, &tag).unwrap();
    drop(mult);
    // All power-of-two broadcasts and reductions needed by the subset lookups.
    let mut indices = vec![];
    let mut d = 1;
    while d < row {
        indices.push(-(d as i32));
        d *= 2;
    }
    for j in 0..13 {
        indices.push(1 << j);
    }
    let stream_keys = std::env::args().any(|s| s == "--stream-keys");
    let key_bytes = if stream_keys {
        // Generate against an empty installed map each time. Install only after
        // every one-index map is generated, preventing cumulative-map duplication.
        let mut maps = vec![];
        let mut bytes = 0;
        for &index in &indices {
            let key = RotationKeys::first(&ctx, &sk, &[index]).unwrap();
            bytes += key.serialize().unwrap().len();
            maps.push(key);
        }
        for key in maps {
            ctx.merge_rotation_keys(&key, &tag).unwrap();
        }
        bytes
    } else {
        let keys = RotationKeys::first(&ctx, &sk, &indices).unwrap();
        // One combined map: this can need several large temporary allocations.
        let bytes = keys.serialize().unwrap().len();
        ctx.install_rotation_keys(&keys, &tag).unwrap();
        bytes
    };
    let pk_bytes = pk.serialize().unwrap();
    let codec = Codec::new(&ctx, &pk, &pk_bytes).unwrap();
    println!(
        "{}",
        json!({"status":"PROFILE","p":65537,"ring":n,"depth":depth.max(18),"digits":digits,"length":length,"chunks":chunks,"rotation_key_bytes":key_bytes,"rotation_wire_format":if stream_keys {"one map per index"}else{"one combined map"},"mult_key_bytes":mult_bytes,"public_key_bytes":pk_bytes.len(),"q":ctx.moduli().unwrap(),"qp":ctx.key_basis_moduli(KeyBasis::KeySwitch).unwrap(),"key_switch":"HYBRID","encoding":"13-bit scalar chunks","libraries":loaded_openfhe_libraries().unwrap()})
    );
    let ones = ctx.plaintext(&vec![1; n]).unwrap();
    let mut total = vec![0u64; length];
    let mut aggregates: Vec<Option<Ciphertext>> = (0..length).map(|_| None).collect();
    // One valid mixed report, then a report whose last chunk is out of range.
    // Other chunks of the invalid report contain ones, testing whole-report gating.
    for report in 0..2 {
        let bits: Vec<u64> = (0..length)
            .map(|j| if report == 0 { (j % 2) as u64 } else { 1 })
            .collect();
        let mut encoded = vec![0; n];
        for (j, &b) in bits.iter().enumerate() {
            encoded[j / 13] |= b << (j % 13);
        }
        if report == 1 {
            encoded[chunks - 1] = 1 << ((length - 1) % 13 + 1);
        }
        for x in &mut encoded[chunks..] {
            *x = 65536;
        }
        let encrypted = ctx.encrypt(&pk, &ctx.plaintext(&encoded).unwrap()).unwrap();
        let chunk = codec.encode(&encrypted).unwrap();
        let mut r = Report {
            task_id: [0xE2; 32],
            report_id: [0; 32],
            group: 0,
            chunks: vec![chunk],
            auth: None,
        };
        r.report_id = Report::compute_id(&r.task_id, r.group, &r.chunks);
        let wire = messages::encode(&r).unwrap();
        let restored: Report = messages::decode(&wire).unwrap();
        let input = codec
            .decode(&restored.chunks[0], Expect::Exactly(codec.fresh_meta()))
            .unwrap();
        let mut flags = vec![];
        let mut decoded = vec![];
        for h in 0..chunks {
            let b = (length - 13 * h).min(13);
            let domain = 1usize << b;
            let mut mask = vec![0; n];
            mask[h] = 1;
            let mut x = ctx
                .mult_plain(&input, &ctx.plaintext(&mask).unwrap())
                .unwrap();
            for j in 0..3 {
                if h & (1 << j) != 0 {
                    x = ctx.rotate(&x, 1 << j).unwrap();
                }
            }
            let mut d = 1;
            while d < row {
                x = ctx.add(&x, &ctx.rotate(&x, -(d as i32)).unwrap()).unwrap();
                d *= 2;
            }
            // Evaluate equality indicators against an entire enumerated domain/subset.
            // The subset for bit k lists exactly those a whose k-th bit is one.
            for k in 0..=b {
                let values: Vec<u64> = (0..domain)
                    .filter(|a| k == b || (a >> k) & 1 == 1)
                    .map(|a| a as u64)
                    .collect();
                let shifts: Vec<u64> = (0..n).map(|j| values[j % values.len()]).collect();
                let mut z = ctx.sub_plain(&x, &ctx.plaintext(&shifts).unwrap()).unwrap();
                for _ in 0..16 {
                    z = ctx.square(&z).unwrap();
                }
                let mut answer = ctx.negate(&ctx.sub_plain(&z, &ones).unwrap()).unwrap();
                let mut d = 1;
                while d < values.len() {
                    answer = ctx
                        .add(&answer, &ctx.rotate(&answer, d as i32).unwrap())
                        .unwrap();
                    d *= 2;
                }
                if k == b {
                    flags.push(answer);
                } else {
                    decoded.push((h, k, answer));
                }
                println!(
                    "{}",
                    json!({"status":"LOOKUP_DONE","report":report,"chunk":h,"bit_or_validity":k,"bits_in_chunk":b})
                );
            }
        }
        for (h, k, digit) in decoded {
            let mut factors = vec![digit];
            for (i, flag) in flags.iter().enumerate() {
                if i != h {
                    factors.push(flag.try_clone().unwrap());
                }
            }
            let output = product(&ctx, factors);
            assert!(output.meta().unwrap().level <= depth.max(18));
            let outwire = codec.encode(&output).unwrap();
            let back = codec.decode(&outwire, Expect::Any).unwrap();
            let bit = 13 * h + k;
            let expected = if report == 0 { bits[bit] } else { 0 };
            let plain = sk.decrypt_single(&back, n).unwrap();
            for (j, v) in plain.into_iter().enumerate() {
                assert_eq!(
                    v,
                    if j < row { expected } else { 0 },
                    "report {report}, bit {bit}, slot {j}"
                );
            }
            total[bit] += expected;
            aggregates[bit] = Some(match aggregates[bit].take() {
                None => output,
                Some(a) => ctx.add(&a, &output).unwrap(),
            });
        }
        println!(
            "{}",
            json!({"status":"VECTOR_REPORT_PASS","length":length,"report":report,"valid":report==0,"report_bytes":wire.len(),"all_output_slots_checked_per_coordinate":n})
        );
    }
    for (i, a) in aggregates.into_iter().enumerate() {
        let a = a.unwrap();
        let wire = codec.encode(&a).unwrap();
        let back = codec.decode(&wire, Expect::Any).unwrap();
        for (j, v) in sk.decrypt_single(&back, n).unwrap().into_iter().enumerate() {
            assert_eq!(v, if j < row { total[i] } else { 0 });
        }
    }
    println!(
        "{}",
        json!({"status":"VECTOR_PASS","length":length,"reports":2,"depth":depth.max(18),"digits":digits,"production_security_certified":false})
    );
}
