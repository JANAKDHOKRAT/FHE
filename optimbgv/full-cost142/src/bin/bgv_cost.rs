use fhe_prio3::{
    messages::{self, Report},
    packed::{Codec, Expect},
};
use openfhe_tbgv_rs::*;
use serde_json::json;
use std::{cell::Cell, time::Instant};
fn ns(t: Instant) -> u128 {
    t.elapsed().as_nanos()
}
struct Ops<'a> {
    c: &'a Context,
    square: Cell<usize>,
    multiply: Cell<usize>,
    rotate: Cell<usize>,
    plain: Cell<usize>,
}
impl<'a> Ops<'a> {
    fn square(&self, a: &Ciphertext) -> Ciphertext {
        self.square.set(self.square.get() + 1);
        self.c.square(a).unwrap()
    }
    fn mult(&self, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        self.multiply.set(self.multiply.get() + 1);
        self.c.mult(a, b).unwrap()
    }
    fn rotate(&self, a: &Ciphertext, i: i32) -> Ciphertext {
        self.rotate.set(self.rotate.get() + 1);
        self.c.rotate(a, i).unwrap()
    }
    fn plain(&self, a: &Ciphertext, b: &Plaintext) -> Ciphertext {
        self.plain.set(self.plain.get() + 1);
        self.c.mult_plain(a, b).unwrap()
    }
}
fn product(o: &Ops, mut v: Vec<Ciphertext>) -> Ciphertext {
    while v.len() > 1 {
        let mut next = vec![];
        while let Some(a) = v.pop() {
            next.push(if let Some(b) = v.pop() {
                o.mult(&a, &b)
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
    let a: Vec<_> = std::env::args().collect();
    let task = a[1].as_str();
    let length: usize = a.get(2).map(|s| s.parse().unwrap()).unwrap_or(1);
    if task == "count" {
        count();
        return;
    }
    assert!(matches!(task, "sumvec" | "sum" | "histogram"));
    if task == "sumvec" {
        assert!([10, 25, 50, 100].contains(&length));
    }
    if task == "histogram" {
        assert!([3, 8].contains(&length));
    }
    let chunks = if task == "sumvec" {
        length.div_ceil(13)
    } else {
        1
    };
    let required = if task == "sumvec" {
        17 + chunks.next_power_of_two().trailing_zeros()
    } else {
        18
    };
    let depth = required.max(18);
    let digits = if required <= 18 { 7 } else { required + 2 };
    let setup = Instant::now();
    let ctx = Context::new_single(
        Params {
            plain_mod: 65537,
            mult_depth: depth,
            security_bits: 128,
        },
        digits,
    )
    .unwrap();
    assert_eq!(ctx.ring_dim(), 32768);
    let n = 32768usize;
    let row = n / 2;
    let t = Instant::now();
    verify_single_rebuild_once(&ctx, depth).unwrap();
    let qualification_ns = ns(t);
    let mut serialize_ns = 0;
    let t = Instant::now();
    let (pk, sk) = keygen_first(&ctx).unwrap();
    let tag = pk.tag().unwrap();
    let mut keygen_ns = ns(t);
    let t = Instant::now();
    let mult = EvalMultKey::single(&ctx, &sk).unwrap();
    keygen_ns += ns(t);
    let t = Instant::now();
    let mult_bytes = mult.serialize().unwrap().len();
    serialize_ns += ns(t);
    ctx.install_eval_mult_key(&mult, &tag).unwrap();
    drop(mult);
    let mut indices = (0..14).map(|j| -(1 << j)).collect::<Vec<i32>>();
    if task == "sumvec" {
        for j in 0..13 {
            indices.push(1 << j);
        }
    } else if task == "sum" {
        indices.extend([1, 2, 4, 8, 16, 32, 64]);
    }
    let mut keys = vec![];
    let mut rotation_bytes = 0;
    for &index in &indices {
        let t = Instant::now();
        let k = RotationKeys::first(&ctx, &sk, &[index]).unwrap();
        keygen_ns += ns(t);
        let t = Instant::now();
        rotation_bytes += k.serialize().unwrap().len();
        serialize_ns += ns(t);
        keys.push(k);
    }
    for k in keys {
        ctx.merge_rotation_keys(&k, &tag).unwrap();
    }
    let t = Instant::now();
    let pk_wire = pk.serialize().unwrap();
    let context_bytes = ctx.serialize().unwrap().len();
    let mut secret = sk.serialize().unwrap();
    let secret_bytes = secret.len();
    secret.fill(0);
    drop(secret);
    serialize_ns += ns(t);
    let codec = Codec::new(&ctx, &pk, &pk_wire).unwrap();
    let ones = ctx.plaintext(&vec![1; n]).unwrap();
    let mut mask = vec![0; n];
    mask[0] = 1;
    let scalar_mask = ctx.plaintext(&mask).unwrap();
    let period = if task == "sum" {
        128
    } else {
        length.next_power_of_two()
    };
    let mut shifts = vec![0; n];
    let mut weights = vec![0; n];
    if task == "sum" {
        for j in 0..row {
            shifts[j] = (j % 128) as u64;
            if (1..=100).contains(&(j % 128)) {
                weights[j] = (j % 128) as u64;
            }
        }
    }
    if task == "histogram" {
        for j in 0..n {
            shifts[j] = (j % period) as u64;
            weights[j] = u64::from(j < row && j % period < length);
        }
    }
    let shifts = ctx.plaintext(&shifts).unwrap();
    let weights = ctx.plaintext(&weights).unwrap();
    let setup_ns = ns(setup);
    println!(
        "{}",
        json!({"status":"SETUP","backend":"BGV","task":task,"length":length,"p":65537,"ring":n,"depth":depth,"digits":digits,"setup_ns":setup_ns,"native_qualification_ns":qualification_ns,"keygen_ns":keygen_ns,"material_sizing_serialization_ns":serialize_ns,"public_key_bytes":pk_wire.len(),"secret_key_bytes":secret_bytes,"context_bytes":context_bytes,"rotation_key_bytes":rotation_bytes,"mult_key_bytes":mult_bytes,"evaluation_key_bytes":rotation_bytes+mult_bytes,"rotation_key_messages":indices.len(),"q":ctx.moduli().unwrap(),"qp":ctx.key_basis_moduli(KeyBasis::KeySwitch).unwrap(),"libraries":loaded_openfhe_libraries().unwrap()})
    );
    let out_len = if task == "sum" { 1 } else { length };
    let mut expected = vec![0u64; out_len];
    let mut reports = vec![];
    let mut client_ns = 0;
    let mut report_bytes = vec![];
    let binary_inputs = (0..4)
        .map(|i| {
            (0..length)
                .map(|j| full_cost142::bit(i, j))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    for i in 0..4 {
        if task == "sumvec" {
            for j in 0..length {
                expected[j] += binary_inputs[i][j];
            }
        } else if task == "sum" {
            expected[0] += [0, 100, 37, 63][i];
        } else {
            expected[i % length] += 1;
        }
    }
    for i in 0..4 {
        let t = Instant::now();
        let mut values = vec![0u64; n];
        if task == "sumvec" {
            for j in 0..length {
                let b = binary_inputs[i][j];
                values[j / 13] |= b << (j % 13);
            }
        } else if task == "sum" {
            values[0] = [0, 100, 37, 63][i];
        } else {
            values[0] = (i % length) as u64;
        }
        let cipher = ctx.encrypt(&pk, &ctx.plaintext(&values).unwrap()).unwrap();
        let chunk = codec.encode(&cipher).unwrap();
        let mut report = Report {
            task_id: [0xF4; 32],
            report_id: [0; 32],
            group: 0,
            chunks: vec![chunk],
            auth: None,
        };
        report.report_id = Report::compute_id(&report.task_id, 0, &report.chunks);
        let wire = messages::encode(&report).unwrap();
        client_ns += ns(t);
        report_bytes.push(wire.len());
        reports.push(wire);
    }
    let ops = Ops {
        c: &ctx,
        square: Cell::new(0),
        multiply: Cell::new(0),
        rotate: Cell::new(0),
        plain: Cell::new(0),
    };
    let mut aggregate: Vec<Option<Ciphertext>> = (0..if task == "sumvec" { length } else { 1 })
        .map(|_| None)
        .collect();
    let mut core_ns = 0;
    let mut excluded_progress_ns = 0;
    for (i, wire) in reports.into_iter().enumerate() {
        let t = Instant::now();
        let mut progress_ns = 0;
        let report: Report = messages::decode(&wire).unwrap();
        assert_eq!(report.task_id, [0xF4; 32]);
        assert_eq!(report.chunks.len(), 1);
        let input = codec
            .decode(&report.chunks[0], Expect::Exactly(codec.fresh_meta()))
            .unwrap();
        if task == "sumvec" {
            let mut flags = vec![];
            let mut decoded = vec![];
            for h in 0..chunks {
                let b = (length - 13 * h).min(13);
                let domain = 1usize << b;
                let mut m = vec![0; n];
                m[h] = 1;
                let mut x = ops.plain(&input, &ctx.plaintext(&m).unwrap());
                for j in 0..3 {
                    if h & (1 << j) != 0 {
                        x = ops.rotate(&x, 1 << j);
                    }
                }
                let mut d = 1;
                while d < row {
                    x = ctx.add(&x, &ops.rotate(&x, -(d as i32))).unwrap();
                    d *= 2;
                }
                for k in 0..=b {
                    let values: Vec<u64> = (0..domain)
                        .filter(|a| k == b || (a >> k) & 1 == 1)
                        .map(|a| a as u64)
                        .collect();
                    let shifts: Vec<u64> = (0..n).map(|j| values[j % values.len()]).collect();
                    let mut z = ctx.sub_plain(&x, &ctx.plaintext(&shifts).unwrap()).unwrap();
                    for _ in 0..16 {
                        z = ops.square(&z);
                    }
                    let mut answer = ctx.negate(&ctx.sub_plain(&z, &ones).unwrap()).unwrap();
                    let mut d = 1;
                    while d < values.len() {
                        answer = ctx.add(&answer, &ops.rotate(&answer, d as i32)).unwrap();
                        d *= 2;
                    }
                    if k == b {
                        flags.push(answer);
                    } else {
                        decoded.push((h, k, answer));
                    }
                    let log = Instant::now();
                    println!(
                        "{}",
                        json!({"status":"LOOKUP_PROGRESS","backend":"BGV","length":length,"report":i,"chunk":h,"bit_or_validity":k})
                    );
                    progress_ns += ns(log);
                }
            }
            for (h, k, digit) in decoded {
                let mut factors = vec![digit];
                for (j, f) in flags.iter().enumerate() {
                    if j != h {
                        factors.push(f.try_clone().unwrap());
                    }
                }
                let output = product(&ops, factors);
                assert!(output.meta().unwrap().level <= depth);
                let coordinate = 13 * h + k;
                aggregate[coordinate] = Some(match aggregate[coordinate].take() {
                    None => output,
                    Some(a) => ctx.add(&a, &output).unwrap(),
                });
            }
        } else {
            let mut x = ops.plain(&input, &scalar_mask);
            for j in 0..14 {
                x = ctx.add(&x, &ops.rotate(&x, -(1 << j))).unwrap();
            }
            let mut z = ctx.sub_plain(&x, &shifts).unwrap();
            for _ in 0..16 {
                z = ops.square(&z);
            }
            let equal = ctx.negate(&ctx.sub_plain(&z, &ones).unwrap()).unwrap();
            let mut output = ops.plain(&equal, &weights);
            if task == "sum" {
                for d in [1, 2, 4, 8, 16, 32, 64] {
                    output = ctx.add(&output, &ops.rotate(&output, d)).unwrap();
                }
            }
            assert!(output.meta().unwrap().level <= depth);
            aggregate[0] = Some(match aggregate[0].take() {
                None => output,
                Some(a) => ctx.add(&a, &output).unwrap(),
            });
        }
        let elapsed = ns(t) - progress_ns;
        core_ns += elapsed;
        excluded_progress_ns += progress_ns;
        println!(
            "{}",
            json!({"status":"REPORT_EVALUATED","backend":"BGV","report":i,"report_core_ns":elapsed,"progress_logging_ns_excluded":progress_ns})
        );
    }
    let aggregate = aggregate
        .into_iter()
        .map(Option::unwrap)
        .collect::<Vec<_>>();
    let t = Instant::now();
    let parts = aggregate
        .iter()
        .map(|c| codec.encode(c).unwrap())
        .collect::<Vec<_>>();
    let sizes = parts.iter().map(Vec::len).collect::<Vec<_>>();
    let wire = messages::encode(&parts).unwrap();
    let finalize_ns = ns(t);
    let t = Instant::now();
    let parts: Vec<Vec<u8>> = messages::decode(&wire).unwrap();
    let mut actual = vec![];
    for part in &parts {
        let c = codec.decode(part, Expect::Any).unwrap();
        if task == "histogram" {
            actual.extend(sk.decrypt_single(&c, length).unwrap());
        } else {
            actual.push(sk.decrypt_single(&c, 1).unwrap()[0]);
        }
    }
    let collector_ns = ns(t);
    assert_eq!(actual, expected);
    let t = Instant::now();
    for (coordinate, part) in parts.iter().enumerate() {
        let c = codec.decode(part, Expect::Any).unwrap();
        let values = sk.decrypt_single(&c, n).unwrap();
        for (j, v) in values.into_iter().enumerate() {
            let want = if j >= row {
                0
            } else if task == "histogram" {
                if j % period < length {
                    expected[j % period]
                } else {
                    0
                }
            } else {
                expected[coordinate]
            };
            assert_eq!(v, want);
        }
    }
    let diagnostic_ns = ns(t);
    if task == "sumvec" {
        assert_eq!(ops.square.get(), 4 * 16 * (length + chunks));
        assert_eq!(ops.multiply.get(), 4 * length * (chunks - 1));
    }
    println!(
        "{}",
        json!({"status":"PASS","backend":"BGV","task":task,"length":length,"batch_size":4,"setup_ns":setup_ns,"client_total_ns":client_ns,"server_total_ns":core_ns+finalize_ns,"server_finalize_ns":finalize_ns,"collector_total_ns":collector_ns,"diagnostic_ns":diagnostic_ns,"progress_logging_ns_excluded":excluded_progress_ns,"report_bytes":report_bytes,"aggregate_wire_bytes":wire.len(),"aggregate_ciphertext_bytes_sum":sizes.iter().sum::<usize>(),"aggregate_parts_bytes":sizes,"aggregate_ciphertexts":parts.len(),"public_key_bytes":pk_wire.len(),"evaluation_key_bytes":rotation_bytes+mult_bytes,"secret_key_bytes":secret_bytes,"context_bytes":context_bytes,"square_calls":ops.square.get(),"ciphertext_multiply_calls":ops.multiply.get(),"rotation_calls":ops.rotate.get(),"plaintext_multiply_calls":ops.plain.get(),"expected":expected,"actual":actual,"p":65537,"ring":n,"depth":depth,"digits":digits,"scope":"alternative encodings; loaded keys; all roles in one process; no network or deployment wrapper"})
    );
}
fn count() {
    use fhe_paper_core::*;
    use fhe_prio3::{AggregateResult, Client, MeasurementType, config::SilentCheck};
    let setup = Instant::now();
    let task = PaperTask::new_native(
        [0xC4; 32],
        MeasurementType::Count,
        SilentCheck::Exact,
        NativeParameters {
            plain_mod: 65537,
            key_switch_digits: 7,
            count_projection: true,
            groups: Some(4),
            ..Default::default()
        },
    )
    .unwrap()
    .with_batch_limit(32)
    .unwrap();
    let profile = task.make_context().unwrap();
    assert_eq!(profile.ring_dim(), 32768);
    assert_eq!(task.mult_depth(), 18);
    let (em, cm, key) = fhe_paper_core::setup(&task).unwrap();
    let evbytes = em.eval_mult_key.len() + em.rotation_keys.iter().map(Vec::len).sum::<usize>();
    let mut ev = PaperEvaluator::new(task.clone(), &em).unwrap();
    let client = Client::new_native(task.config().clone(), &cm.context, &cm.public_key).unwrap();
    let collector = PaperCollector::new(task.clone(), &cm, &key).unwrap();
    let setup_ns = ns(setup);
    let mut reports = vec![];
    let mut sizes = vec![];
    let mut client_ns = 0;
    for i in 0..4 {
        let t = Instant::now();
        let r = client
            .shard_raw_elements_in_group(&[vec![full_cost142::bit(i, 0)]], i as u32)
            .unwrap();
        let wire = messages::encode(&r).unwrap();
        client_ns += ns(t);
        sizes.push(wire.len());
        reports.push(wire);
    }
    let t = Instant::now();
    for wire in reports {
        let r: Report = messages::decode(&wire).unwrap();
        ev.admit(&r).unwrap();
    }
    let aggregate = ev.finish().unwrap();
    let wire = messages::encode(&aggregate).unwrap();
    let server_ns = ns(t);
    let t = Instant::now();
    let aggregate: PaperAggregate = messages::decode(&wire).unwrap();
    let result = collector.decrypt_aggregate(&aggregate).unwrap();
    let collector_ns = ns(t);
    assert_eq!(result.aggregate, AggregateResult::Count(2));
    println!(
        "{}",
        json!({"status":"PASS","backend":"BGV","task":"count","length":1,"batch_size":4,"setup_ns":setup_ns,"client_total_ns":client_ns,"server_total_ns":server_ns,"collector_total_ns":collector_ns,"report_bytes":sizes,"aggregate_wire_bytes":wire.len(),"aggregate_ciphertexts":1,"public_key_bytes":cm.public_key.len(),"evaluation_key_bytes":evbytes,"secret_key_bytes":key.as_bytes().len(),"context_bytes":cm.context.len(),"actual":2,"expected":2,"p":65537,"ring":32768,"depth":18,"digits":7,"scope":"preserved exact Count projection, groups4; loaded keys, no network"})
    );
}
