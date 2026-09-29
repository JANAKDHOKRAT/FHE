//! Attacks on the packed ciphertext wire format. Every ciphertext another
//! party sends is parsed in safe Rust and rebuilt inside the receiver's own
//! context; these tests try to get anything else through, or to crash the
//! receiver, at every layer: codec, aggregator admission, the verdict
//! rounds, the count round and the collector.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::packed::{Expect, HEADER_LEN, MAGIC, WireError};
use fhe_prio3::*;

/// The seeded generator of the earlier fuzz run against OpenFHE's own
/// loader (xorshift64, same seed), so the same mutation recipes can be
/// replayed against the aggregator.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Replays mutation `i` of the earlier OpenFHE fuzz run on `base`
/// (kinds: 0 bit flips anywhere, 1 random bytes in the first 4 KiB,
/// 2 an 8-byte 0xFF window in the first 4 KiB, 3 truncation).
fn legacy_mutants(base: &[u8], wanted: &[usize]) -> Vec<(usize, Vec<u8>)> {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let last = *wanted.iter().max().unwrap();
    let mut out = Vec::new();
    for i in 0..=last {
        let mut m = base.to_vec();
        match i % 4 {
            0 => {
                for _ in 0..1 + rng.below(8) {
                    let p = rng.below(m.len());
                    m[p] ^= 1 << rng.below(8);
                }
            }
            1 => {
                for _ in 0..1 + rng.below(4) {
                    let p = rng.below(4096.min(m.len()));
                    m[p] = rng.next() as u8;
                }
            }
            2 => {
                let p = rng.below(4096.min(m.len()) - 8);
                m[p..p + 8].copy_from_slice(&[0xFF; 8]);
            }
            _ => {
                let len = rng.below(m.len());
                m.truncate(len);
            }
        }
        if wanted.contains(&i) {
            out.push((i, m));
        }
    }
    out
}

/// Rewrites residue `(element, tower, index)` of a packed ciphertext in
/// place, for crafting out-of-range values the encoder would never emit.
fn set_residue(bytes: &mut [u8], widths: &[u32], towers: usize, ring: usize, e: usize, t: usize, i: usize, v: u64) {
    let per_coeff: usize = widths[..towers].iter().map(|&w| w as usize).sum();
    let mut bit = HEADER_LEN * 8 + e * ring * per_coeff;
    for tt in 0..t {
        bit += ring * widths[tt] as usize;
    }
    bit += i * widths[t] as usize;
    for b in 0..widths[t] as usize {
        let (byte, off) = ((bit + b) / 8, (bit + b) % 8);
        bytes[byte] = (bytes[byte] & !(1 << off)) | ((((v >> b) & 1) as u8) << off);
    }
}

fn net_expect_all(v: &[Verdict], want: &Verdict) {
    assert!(v.iter().all(|x| x == want), "expected {want:?}, got {v:?}");
}

fn widths(moduli: &[u64]) -> Vec<u32> {
    moduli.iter().map(|&q| 64 - (q - 1).leading_zeros()).collect()
}

fn reid(r: &mut Report) {
    r.report_id = Report::compute_id(&r.task_id, r.group, &r.chunks);
}

fn verdict_net(seed: u8, t: MeasurementType, n: usize) -> Net {
    Net::new(TaskConfig::new(task_id(seed), t, n))
}

#[test]
fn every_exchanged_object_is_canonical_and_the_sizes_are_as_measured() {
    let _g = serial();
    let mut net = verdict_net(90, MeasurementType::Sum { max_measurement: 100 }, 3);
    let codec = net.aggs[0].codec();
    let fresh = codec.fresh_meta();
    // client chunk
    let report = net.client.shard(&Measurement::Sum(42)).unwrap();
    assert_eq!(report.chunks[0].len(), codec.fresh_len());
    let (m, _) = codec.parse(&report.chunks[0], Expect::Exactly(fresh)).unwrap();
    assert_eq!(m, fresh);
    let back = codec.decode(&report.chunks[0], Expect::Exactly(fresh)).unwrap();
    assert_eq!(codec.encode(&back).unwrap(), report.chunks[0], "decode then encode must reproduce the bytes");
    // the report's own OpenFHE form, for the size comparison
    let openfhe_len = back.serialize().unwrap().len();
    println!("WIRE verdict chunk: packed {} bytes, OpenFHE {} bytes ({:.1}% smaller)", report.chunks[0].len(), openfhe_len, 100.0 * (1.0 - report.chunks[0].len() as f64 / openfhe_len as f64));

    // masks and verifier partials from a real verdict round
    let mask_commits: Vec<MaskCommit> = net.aggs.iter_mut().map(|a| a.prepare_init(&report).unwrap()).collect();
    let mut masks = Vec::new();
    for a in net.aggs.iter_mut() {
        let others: Vec<MaskCommit> = mask_commits.iter().filter(|c| c.aggregator != a.index()).cloned().collect();
        masks.push(a.prepare_mask_reveal(&report.report_id, &others).unwrap());
    }
    for m in &masks {
        let c = net.aggs[0].codec();
        let ct = c.decode(&m.mask, Expect::Exactly(fresh)).unwrap();
        assert_eq!(c.encode(&ct).unwrap(), m.mask);
    }
    let mut commits = Vec::new();
    for a in net.aggs.iter_mut() {
        let others: Vec<MaskMessage> = masks.iter().filter(|m| m.aggregator != a.index()).cloned().collect();
        commits.push(a.prepare_masks(&report.report_id, &others).unwrap());
    }
    let mut verifiers = Vec::new();
    for a in net.aggs.iter_mut() {
        let others: Vec<VerifierCommit> = commits.iter().filter(|c| c.aggregator != a.index()).cloned().collect();
        verifiers.push(a.prepare_reveal(&report.report_id, &others).unwrap());
    }
    let (pm, _) = net.aggs[0].codec().parse(&verifiers[1].partial, Expect::Partial).unwrap();
    assert_eq!(pm.num_elements, 1);
    for v in &verifiers {
        let c = net.aggs[0].codec();
        let ct = c.decode(&v.partial, Expect::Exactly(pm)).unwrap();
        assert_eq!(c.encode(&ct).unwrap(), v.partial);
        assert_eq!(v.partial.len(), c.encoded_len(&pm));
    }
    println!("WIRE verdict check partial: {} bytes, shape {pm:?}", verifiers[0].partial.len());
    for a in net.aggs.iter_mut() {
        let others: Vec<VerifierMessage> = verifiers.iter().filter(|v| v.aggregator != a.index()).cloned().collect();
        assert_eq!(a.prepare_finish(&report.report_id, &others).unwrap(), Verdict::Accepted);
    }
    // aggregate shares
    let shares: Vec<AggregateShare> = net.aggs.iter_mut().map(|a| a.aggregate_share().unwrap()).collect();
    for s in &shares {
        let c = net.aggs[0].codec();
        let ct = c.decode(&s.partials[0], Expect::Partial).unwrap();
        assert_eq!(c.encode(&ct).unwrap(), s.partials[0]);
    }
    let r = net.finish_release(0, shares).unwrap();
    assert_eq!(r.aggregate, AggregateResult::Sum(42));
    // every aggregator's internal message bound covers the masks of the others
    assert_eq!(net.aggs[0].max_message_bytes(), 2 * codec_len(&net));
}

fn codec_len(net: &Net) -> usize {
    net.aggs[0].codec().fresh_len()
}

#[test]
fn every_header_field_is_checked() {
    let _g = serial();
    let mut net = verdict_net(91, MeasurementType::Count, 2);
    let codec = net.aggs[0].codec();
    let fresh = codec.fresh_meta();
    let good = net.client.shard(&Measurement::Count(true)).unwrap();
    let chunk = good.chunks[0].clone();
    let refuse = |bytes: &[u8], what: &str| -> WireError {
        let e = net.aggs[0].codec().parse(bytes, Expect::Exactly(fresh)).expect_err(what);
        println!("REFUSED {what}: {e}");
        e
    };
    let mutate = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = chunk.clone();
        f(&mut b);
        b
    };
    // magic and version
    for i in 0..4 {
        assert_eq!(refuse(&mutate(&|b| b[i] ^= 0x20), "magic byte"), WireError::BadMagic);
    }
    for v in [0u8, 2, 255] {
        assert_eq!(refuse(&mutate(&|b| b[4] = v), "version"), WireError::BadVersion(v));
    }
    // reserved bytes
    for i in 13..16 {
        assert_eq!(refuse(&mutate(&|b| b[i] = 1), "reserved byte"), WireError::NonZeroReserved);
    }
    // fingerprint: any bit of any byte
    for i in 24..56 {
        assert_eq!(refuse(&mutate(&|b| b[i] ^= 1 << (i % 8)), "fingerprint bit"), WireError::WrongParameters);
    }
    // shape fields at their boundaries
    for v in [0u8, 3, 255] {
        assert!(matches!(refuse(&mutate(&|b| b[5] = v), "num_elements"), WireError::BadShape(_)));
    }
    assert!(matches!(refuse(&mutate(&|b| b[5] = 1), "num_elements 1 for a chunk"), WireError::UnexpectedShape { .. }));
    let l = fresh.num_towers as u16;
    for v in [0u16, l + 1, u16::MAX] {
        assert!(matches!(refuse(&mutate(&|b| b[6..8].copy_from_slice(&v.to_le_bytes())), "num_towers"), WireError::BadShape(_)));
    }
    // one tower fewer with a consistent level is a valid shape, but not a fresh one
    let fewer = mutate(&|b| {
        b[6..8].copy_from_slice(&(l - 1).to_le_bytes());
        b[8..12].copy_from_slice(&1u32.to_le_bytes());
    });
    assert!(matches!(refuse(&fewer, "one tower fewer"), WireError::UnexpectedShape { .. }));
    for v in [1u32, 7, u32::MAX] {
        assert!(matches!(refuse(&mutate(&|b| b[8..12].copy_from_slice(&v.to_le_bytes())), "level"), WireError::BadShape(_)));
    }
    for v in [0u8, 3, 255] {
        assert!(matches!(refuse(&mutate(&|b| b[12] = v), "noise_scale_deg"), WireError::BadShape(_)));
    }
    assert!(matches!(refuse(&mutate(&|b| b[12] = 1), "noise_scale_deg 1"), WireError::UnexpectedShape { .. }));
    let p = net.cfg.plain_mod;
    for v in [0u64, p, p + 1, u64::MAX] {
        assert!(matches!(refuse(&mutate(&|b| b[16..24].copy_from_slice(&v.to_le_bytes())), "scaling factor"), WireError::BadShape(_)));
    }
    let other_sf = if fresh.scaling_factor_int + 1 < p { fresh.scaling_factor_int + 1 } else { 1 };
    assert!(matches!(refuse(&mutate(&|b| b[16..24].copy_from_slice(&other_sf.to_le_bytes())), "another valid scaling factor"), WireError::UnexpectedShape { .. }));
    // lengths
    assert!(matches!(refuse(&chunk[..HEADER_LEN - 1], "short header"), WireError::Truncated { .. }));
    assert!(matches!(refuse(&[], "empty"), WireError::Truncated { .. }));
    assert!(matches!(refuse(&chunk[..chunk.len() - 1], "one byte short"), WireError::BadLength { .. }));
    assert!(matches!(refuse(&mutate(&|b| b.push(0)), "one byte extra"), WireError::BadLength { .. }));
    assert!(matches!(refuse(&chunk[..HEADER_LEN], "header only"), WireError::BadLength { .. }));

    // residues at or above their modulus, in every tower of both elements
    let ctx = openfhe_tbgv_rs::Context::deserialize(&net.material.context).unwrap();
    let moduli = ctx.moduli().unwrap();
    let w = widths(&moduli);
    let ring = ctx.ring_dim() as usize;
    let towers = moduli.len();
    for e in 0..2 {
        for t in 0..towers {
            for (i, v) in [(0usize, moduli[t]), (ring - 1, (1u64 << w[t]) - 1)] {
                let mut b = chunk.clone();
                set_residue(&mut b, &w, towers, ring, e, t, i, v);
                assert_eq!(refuse(&b, "residue >= modulus"), WireError::ResidueOutOfRange { element: e, tower: t, index: i });
            }
            // modulus - 1 is legal
            let mut b = chunk.clone();
            set_residue(&mut b, &w, towers, ring, e, t, 7, moduli[t] - 1);
            net.aggs[0].codec().parse(&b, Expect::Exactly(fresh)).unwrap();
        }
    }

    // through admission, the same inputs are clean rejections
    let mut wrong_fp = good.clone();
    wrong_fp.chunks[0][30] ^= 4;
    reid(&mut wrong_fp);
    net.expect_reject(&wrong_fp, RejectReason::WrongParameters);
    let mut high = good.clone();
    set_residue(&mut high.chunks[0], &w, towers, ring, 1, towers - 1, 5, moduli[towers - 1]);
    reid(&mut high);
    match &net.run_report(&high)[0] {
        Verdict::Rejected(RejectReason::MalformedCiphertext(m)) => assert!(m.contains("ResidueOutOfRange"), "{m}"),
        v => panic!("expected a malformed-ciphertext rejection, got {v:?}"),
    }
    net.expect_accept(&good);
}

/// Seeded mutation of packed chunks, parsed exactly as admission parses
/// them. Nothing may panic or reach OpenFHE unless every check passed, and
/// every accepted mutant must re-encode to exactly its own bytes (one
/// ciphertext, one encoding).
#[test]
fn seeded_mutation_fuzz_of_packed_chunks() {
    let _g = serial();
    let mut net = verdict_net(92, MeasurementType::Histogram { length: 8 }, 2);
    let codec = net.aggs[0].codec();
    let fresh = codec.fresh_meta();
    let base = net.client.shard(&Measurement::Histogram(3)).unwrap();
    let chunk = base.chunks[0].clone();
    let mut rng = Rng(0xD1B54A32D192ED03);
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    let mut rebuilt = 0usize;
    let mut sample_for_admission = Vec::new();
    let n = 6000;
    for i in 0..n {
        let mut m = chunk.clone();
        match i % 7 {
            0 => {
                for _ in 0..1 + rng.below(8) {
                    let p = rng.below(m.len());
                    m[p] ^= 1 << rng.below(8);
                }
            }
            1 => {
                for _ in 0..1 + rng.below(4) {
                    let p = rng.below(HEADER_LEN);
                    m[p] = rng.next() as u8;
                }
            }
            2 => {
                let p = rng.below(HEADER_LEN - 8);
                m[p..p + 8].copy_from_slice(&[0xFF; 8]);
            }
            3 => {
                let len = rng.below(m.len());
                m.truncate(len);
            }
            4 => {
                let extra = 1 + rng.below(64);
                for _ in 0..extra {
                    m.push(rng.next() as u8);
                }
            }
            5 => {
                // random payload words: residues often above their modulus
                for _ in 0..1 + rng.below(4) {
                    let p = HEADER_LEN + rng.below(m.len() - HEADER_LEN - 8);
                    m[p..p + 8].copy_from_slice(&rng.next().to_le_bytes());
                }
            }
            _ => {
                // a whole random header with the right magic
                for b in m[4..HEADER_LEN].iter_mut() {
                    *b = rng.next() as u8;
                }
            }
        }
        let codec = net.aggs[0].codec();
        match codec.decode(&m, Expect::Exactly(fresh)) {
            Ok(ct) => {
                assert_eq!(codec.encode(&ct).unwrap(), m, "accepted mutant {i} is not canonical");
                rebuilt += 1;
                *counts.entry("accepted as a (different) ciphertext".into()).or_default() += 1;
                if sample_for_admission.len() < 3 {
                    sample_for_admission.push(m);
                }
            }
            Err(e) => {
                let key = format!("{e:?}").split(['(', ' ', '{']).next().unwrap().to_string();
                *counts.entry(key).or_default() += 1;
            }
        }
    }
    println!("FUZZ {n} packed mutants: {counts:?}");
    assert!(rebuilt > 0, "payload bit flips below the modulus are valid ciphertexts and must be rebuilt");
    // a few accepted mutants through the whole verdict round: well-formed
    // ciphertexts of garbage, refused by the validity check, never a crash
    for m in sample_for_admission {
        let mut r = base.clone();
        r.chunks[0] = m;
        reid(&mut r);
        net.expect_reject(&r, RejectReason::ValidityCheckFailed);
    }
    net.expect_accept(&base);
    assert_eq!(net.collect().unwrap(), (AggregateResult::Histogram(vec![0, 0, 0, 1, 0, 0, 0, 0]), 1));
}

/// The inputs that crashed OpenFHE's own loader (arithmetic faults, an
/// abort, a segmentation fault), regenerated from the same seeded recipes on
/// a fresh OpenFHE serialization, go through the full admission path and are
/// refused before any OpenFHE call. If OpenFHE's loader were ever put back
/// on this path, this test would crash instead of passing.
#[test]
fn legacy_openfhe_bytes_and_the_crash_recipes_are_refused() {
    let _g = serial();
    let mut net = verdict_net(93, MeasurementType::Count, 2);
    let codec = net.aggs[0].codec();
    let good = net.client.shard(&Measurement::Count(true)).unwrap();
    let ct = codec.decode(&good.chunks[0], Expect::Exactly(codec.fresh_meta())).unwrap();
    let legacy = ct.serialize().unwrap();
    assert_ne!(&legacy[..4], &MAGIC);
    let crashing = [425usize, 694, 822, 854, 1118, 1206, 1249, 1561, 1698, 1782, 1857, 1962, 1986, 2009, 2073, 2238];
    let mut inputs = vec![(usize::MAX, legacy.clone())];
    inputs.extend(legacy_mutants(&legacy, &crashing));
    let cap = net.aggs[0].max_report_bytes();
    assert!(legacy.len() > cap, "OpenFHE's encoding is larger than the packed one");
    for (i, bytes) in inputs {
        // as sent: refused by the size bound before any parsing
        let mut r = good.clone();
        r.chunks[0] = bytes.clone();
        reid(&mut r);
        let verdicts = net.run_report(&r);
        let ok = verdicts.iter().all(|v| matches!(v, Verdict::Rejected(RejectReason::TooLarge { limit, .. }) if *limit == cap));
        assert!(ok, "recipe {i}: {verdicts:?}");
        // cut to exactly the packed length, so the size bound passes and
        // the parser itself must refuse it (OpenFHE's encoding does not
        // start with the packed magic)
        let mut r = good.clone();
        r.chunks[0] = bytes[..cap.min(bytes.len())].to_vec();
        reid(&mut r);
        let verdicts = net.run_report(&r);
        let ok = verdicts.iter().all(|v| matches!(v, Verdict::Rejected(RejectReason::MalformedCiphertext(m)) if m.contains("BadMagic")));
        assert!(ok, "recipe {i} cut to the packed length: {verdicts:?}");
    }
    // the same with the packed magic, version and this task's fingerprint
    // written over OpenFHE's first bytes: refused by the shape or residue
    // checks, still in safe Rust
    let mut forged = legacy[..cap].to_vec();
    forged[..HEADER_LEN].copy_from_slice(&good.chunks[0][..HEADER_LEN]);
    let mut r = good.clone();
    r.chunks[0] = forged;
    reid(&mut r);
    let parsed = net.aggs[0].codec().parse(&r.chunks[0], Expect::Exactly(net.aggs[0].codec().fresh_meta()));
    println!("LEGACY bytes under a forged packed header: {:?}", parsed.as_ref().map(|_| "well-formed").map_err(|e| e.clone()));
    let v = net.run_report(&r);
    match parsed {
        // arbitrary residues below their moduli are a well-formed ciphertext
        // of garbage: refused by the validity check
        Ok(_) => net_expect_all(&v, &Verdict::Rejected(RejectReason::ValidityCheckFailed)),
        Err(e) => net_expect_all(&v, &Verdict::Rejected(RejectReason::MalformedCiphertext(e.to_string()))),
    }
    net.expect_accept(&good);
    assert_eq!(net.collect().unwrap(), (AggregateResult::Count(1), 1));
}

/// Hostile partial decryptions: between aggregators they must have exactly
/// the receiver's own shape; at the collector every aggregator's partial of
/// one ciphertext must have the same shape and all bounds hold.
#[test]
fn hostile_partial_decryptions_are_refused_at_every_receiver() {
    let _g = serial();
    let mut net = verdict_net(94, MeasurementType::Count, 2);
    let p = net.cfg.plain_mod;
    // a verifier partial with another valid scaling factor, one tower fewer,
    // or two elements: refused, never a crash. Bytes other than the
    // committed ones stop at the commitment; to reach the parser, the
    // malicious aggregator 0 commits to the hostile bytes themselves.
    let variants: Vec<(&str, fn(&[u8], u64) -> Vec<u8>)> = vec![
        ("other scaling factor", |b, p| {
            let mut v = b.to_vec();
            let sf = u64::from_le_bytes(b[16..24].try_into().unwrap());
            v[16..24].copy_from_slice(&(if sf + 1 < p { sf + 1 } else { 1 }).to_le_bytes());
            v
        }),
        ("two elements", |b, _| {
            let mut v = b.to_vec();
            v[5] = 2;
            v
        }),
        ("one tower fewer", |b, _| {
            let mut v = b.to_vec();
            let towers = u16::from_le_bytes([b[6], b[7]]);
            v[6..8].copy_from_slice(&(towers - 1).to_le_bytes());
            let level = u32::from_le_bytes(b[8..12].try_into().unwrap());
            v[8..12].copy_from_slice(&(level + 1).to_le_bytes());
            v
        }),
    ];
    for (what, make) in variants {
        let report = net.client.shard(&Measurement::Count(true)).unwrap();
        let mc: Vec<MaskCommit> = net.aggs.iter_mut().map(|a| a.prepare_init(&report).unwrap()).collect();
        let masks = [net.aggs[0].prepare_mask_reveal(&report.report_id, &mc[1..]).unwrap(), net.aggs[1].prepare_mask_reveal(&report.report_id, &mc[..1]).unwrap()];
        let c0 = net.aggs[0].prepare_masks(&report.report_id, &masks[1..]).unwrap();
        let c1 = net.aggs[1].prepare_masks(&report.report_id, &masks[..1]).unwrap();
        let v0 = net.aggs[0].prepare_reveal(&report.report_id, &[c1]).unwrap();
        let bad = make(&v0.partial, p);
        let mut context = b"verdict".to_vec();
        context.extend_from_slice(&net.cfg.task_id);
        context.extend_from_slice(&report.report_id);
        context.extend_from_slice(&0u64.to_le_bytes());
        // (bytes other than the committed ones: tests/malicious_aggregator.rs)
        let mut msg = v0.clone();
        msg.partial = bad.clone();
        let forged = VerifierCommit { digest: fhe_prio3::vdec::commit(&context, &bad), ..c0 };
        net.aggs[1].prepare_reveal(&report.report_id, &[forged]).unwrap();
        let e = net.aggs[1].prepare_finish(&report.report_id, &[msg]).err().unwrap_or_else(|| panic!("{what} accepted"));
        assert!(e.to_string().contains("packed ciphertext refused"), "{what}: {e}");
        println!("REFUSED verifier partial, {what}: {e}");
    }
    // honest rounds complete on the same aggregators afterwards
    net.expect_accept(&net.client.shard(&Measurement::Count(true)).unwrap());

    // collector: shares with disagreeing or out-of-bound partial shapes
    let mut net = verdict_net(95, MeasurementType::Count, 2);
    net.expect_accept(&net.client.shard(&Measurement::Count(true)).unwrap());
    let shares: Vec<AggregateShare> = net.aggs.iter_mut().map(|a| a.aggregate_share().unwrap()).collect();
    let rt: Vec<AggregateShare> = shares.iter().map(|s| decode(&encode(s).unwrap()).unwrap()).collect();
    let mut disagree = rt.clone();
    let sf = u64::from_le_bytes(disagree[1].partials[0][16..24].try_into().unwrap());
    disagree[1].partials[0][16..24].copy_from_slice(&(if sf + 1 < p { sf + 1 } else { 1 }).to_le_bytes());
    let e = net.collector.release_challenge(0, disagree).err().expect("refused");
    assert!(e.to_string().contains("partial decryption of accumulator 0") && e.to_string().contains("UnexpectedShape"), "{e}");
    let mut oob = rt.clone();
    oob[0].partials[0][16..24].copy_from_slice(&0u64.to_le_bytes());
    oob[1].partials[0][16..24].copy_from_slice(&0u64.to_le_bytes());
    let e = net.collector.release_challenge(0, oob).err().expect("refused");
    assert!(e.to_string().contains("scaling_factor_int"), "{e}");
    let mut legacy = rt.clone();
    legacy[0].partials[0] = b"not a packed ciphertext at all, long enough to pass the header length check".to_vec();
    assert!(net.collector.release_challenge(0, legacy).err().expect("refused").to_string().contains("BadMagic"));
    assert_eq!(net.finish_release(0, rt).unwrap().aggregate, AggregateResult::Count(1));
}

/// Silent mode: the count-round and aggregate partials live at the last
/// level (few towers); they must round-trip canonically too, and a count
/// share with the wrong shape is refused by the other aggregator.
#[test]
fn silent_mode_low_level_partials() {
    let _g = serial();
    let mut net = Net::new(TaskConfig::new_silent(task_id(96), MeasurementType::Count, 2));
    net.expect_accept(&net.client.shard(&Measurement::Count(true)).unwrap());
    net.expect_accept(&net.client.shard_raw_elements(&[vec![2]]).unwrap()); // invalid: contributes zero
    let counts: Vec<CountShare> = net.aggs.iter_mut().map(|a| a.count_share().unwrap()).collect();
    let c = net.aggs[0].codec();
    let (m, _) = c.parse(&counts[0].partial, Expect::Partial).unwrap();
    println!("WIRE silent count partial: {} bytes, shape {m:?}", counts[0].partial.len());
    assert!(m.num_towers < c.fresh_meta().num_towers, "the counter is at a low level");
    for s in &counts {
        let ct = c.decode(&s.partial, Expect::Exactly(m)).unwrap();
        assert_eq!(c.encode(&ct).unwrap(), s.partial);
    }
    // a count share of the wrong shape is refused before anything is committed
    let mut bad = counts.clone();
    bad[0].partial[12] = if m.noise_scale_deg == 2 { 1 } else { 2 }; // valid bound, wrong shape
    let e = net.aggs[1].count_commit(&bad).err().expect("refused");
    assert!(e.to_string().contains("UnexpectedShape"), "{e}");
    let mut bad = counts.clone();
    bad[1].checks[0][12] ^= 3;
    assert!(net.aggs[0].count_commit(&bad).is_err());
    let r = net.collect_full().unwrap();
    assert_eq!((r.aggregate, r.report_count, r.valid_count), (AggregateResult::Count(1), 2, 1));
}

/// Size and time of the packed format against OpenFHE's own serialization
/// for a fresh ciphertext, under the verdict and the silent parameters.
/// Sizes are asserted exactly (they follow from the modulus chain);
/// timings are printed only, they depend on the machine.
#[test]
fn packed_against_openfhe_size_and_time() {
    let _g = serial();
    for cfg in [TaskConfig::new(task_id(97), MeasurementType::Count, 2), TaskConfig::new_silent(task_id(98), MeasurementType::Count, 2)] {
        let mode = format!("{:?}", cfg.mode);
        let ctx = keys::make_context(&cfg).unwrap();
        let report = openfhe_tbgv_rs::verify_rebuild_once(&ctx, cfg.mult_depth()).unwrap();
        println!(
            "SELFTEST {mode}: {} objects rebuilt and checked down to level {} in {:.1} s",
            report.objects_checked,
            report.deepest_level,
            report.elapsed.as_secs_f64()
        );
        let (pk, _share) = keys::keygen_step(&ctx, None).unwrap();
        let pk_bytes = pk.serialize().unwrap();
        let codec = fhe_prio3::packed::Codec::new(&ctx, &pk, &pk_bytes).unwrap();
        let moduli = ctx.moduli().unwrap();
        let w = widths(&moduli);
        let n = ctx.ring_dim() as usize;
        let ct = ctx.encrypt(&pk, &ctx.plaintext(&[1]).unwrap()).unwrap();
        let reps = 5u32;
        let t = std::time::Instant::now();
        let mut packed = Vec::new();
        for _ in 0..reps {
            packed = codec.encode(&ct).unwrap();
        }
        let t_enc = t.elapsed() / reps;
        let t = std::time::Instant::now();
        for _ in 0..reps {
            codec.parse(&packed, Expect::Exactly(codec.fresh_meta())).unwrap();
        }
        let t_parse = t.elapsed() / reps;
        let t = std::time::Instant::now();
        let mut back = None;
        for _ in 0..reps {
            back = Some(codec.decode(&packed, Expect::Exactly(codec.fresh_meta())).unwrap());
        }
        let t_dec = t.elapsed() / reps;
        let t = std::time::Instant::now();
        let mut legacy = Vec::new();
        for _ in 0..reps {
            legacy = ct.serialize().unwrap();
        }
        let t_ser = t.elapsed() / reps;
        let t = std::time::Instant::now();
        for _ in 0..reps {
            ctx.deserialize_ciphertext(&legacy).unwrap();
        }
        let t_de = t.elapsed() / reps;
        // the rebuilt ciphertext is the original: same residues, and it
        // serializes to the same OpenFHE bytes
        let back = back.unwrap();
        assert_eq!(back.export_residues().unwrap(), ct.export_residues().unwrap());
        assert_eq!(back.serialize().unwrap(), legacy);
        let bits: usize = w.iter().map(|&x| x as usize).sum();
        assert_eq!(packed.len(), HEADER_LEN + (2 * n * bits).div_ceil(8));
        println!(
            "COST {mode}: N={n}, {} towers of widths {w:?}; packed {} bytes, OpenFHE {} bytes, {:.1}% smaller; \
             encode {:.1} ms, parse {:.1} ms, parse+rebuild {:.1} ms; OpenFHE serialize {:.1} ms, deserialize {:.1} ms",
            moduli.len(),
            packed.len(),
            legacy.len(),
            100.0 * (1.0 - packed.len() as f64 / legacy.len() as f64),
            t_enc.as_secs_f64() * 1e3,
            t_parse.as_secs_f64() * 1e3,
            t_dec.as_secs_f64() * 1e3,
            t_ser.as_secs_f64() * 1e3,
            t_de.as_secs_f64() * 1e3,
        );
    }
}
