//! The gated release's rounds (`gate.rs`) end to end at small parameters
//! (ring dimension 32768, depth 6), so they run in seconds: commitments,
//! contributions with their proofs, the verified joint decryption of the
//! masked values, the gates, and the collector's reading of the outputs, in
//! both topologies, plus the attacks on each round. The same rounds run at
//! the task's real parameters in `tests/split_key.rs` and
//! `tests/suppression.rs`; this file exercises every branch of the round
//! logic quickly (and is what the coverage job measures it with).
use fhe_prio3::gate::{self, GateEnv, GatePlan, GateState, Refreshed};
use fhe_prio3::packed::{Codec, Expect};
use fhe_prio3::*;
use openfhe_tbgv_rs::*;
use rand::rngs::OsRng;

struct Party {
    share: SecretShare,
    st: GateState,
}

struct World {
    cfg: TaskConfig,
    layout: fhe_prio3::layout::Layout,
    ctx: Context,
    pk: PublicKey,
    codec: Codec,
    parties: Vec<Party>,
}

/// Two key parties on a small chain, with the eval-mult key installed.
fn world(cfg: TaskConfig) -> World {
    let ctx = Context::new(Params {
        plain_mod: cfg.plain_mod,
        mult_depth: 6,
        security_bits: 128,
    })
    .unwrap();
    let (pk0, s0) = keygen_first(&ctx).unwrap();
    let (pk, s1) = keygen_next(&ctx, &pk0).unwrap();
    let tag = pk.tag().unwrap();
    let r1 = EvalMultKey::round1_first(&ctx, &s0).unwrap();
    let r1b = EvalMultKey::round1_next(&ctx, &s1, &r1).unwrap();
    let r1sum = EvalMultKey::round1_add(&ctx, &r1, &r1b, &tag).unwrap();
    let r2a = EvalMultKey::round2(&ctx, &s0, &r1sum, &tag).unwrap();
    let r2b = EvalMultKey::round2(&ctx, &s1, &r1sum, &tag).unwrap();
    ctx.install_eval_mult_key(&EvalMultKey::round2_add(&ctx, &r2a, &r2b, &tag).unwrap(), &tag)
        .unwrap();
    // every party verifies the packed rebuild once per process (as nodes do)
    openfhe_tbgv_rs::verify_rebuild_once(&ctx, 6).unwrap();
    let layout = cfg.layout(ctx.row_slots()).unwrap();
    let pk_bytes = pk.serialize().unwrap();
    let codec = Codec::new(&ctx, &pk, &pk_bytes).unwrap();
    World {
        cfg,
        layout,
        ctx,
        pk,
        codec,
        parties: vec![
            Party {
                share: s0,
                st: GateState::default(),
            },
            Party {
                share: s1,
                st: GateState::default(),
            },
        ],
    }
}

fn env<'a>(w: &'a World, share: &'a SecretShare, party: usize) -> GateEnv<'a> {
    GateEnv {
        cfg: &w.cfg,
        layout: &w.layout,
        ctx: &w.ctx,
        pk: &w.pk,
        codec: &w.codec,
        share,
        party,
    }
}

/// Encrypted accumulators for the plan: cell counts at the chunk's
/// client slots, the valid count at every element slot of group 0.
fn accumulators(w: &World, cells: &[u64], valid: u64) -> Vec<Ciphertext> {
    let plan = GatePlan::new(&w.cfg, &w.layout).unwrap();
    let row = w.layout.row;
    plan.refreshed
        .iter()
        .map(|r| {
            let mut v = vec![0u64; row];
            match r {
                Refreshed::Chunk(0) => {
                    for (i, &c) in cells.iter().enumerate() {
                        v[w.layout.client_slot(i)] = c;
                    }
                }
                Refreshed::SpreadCount => {
                    for &s in &plan.spread_slots {
                        v[s] = valid;
                    }
                }
                other => panic!("unexpected refreshed value {other:?}"),
            }
            w.ctx.encrypt(&w.pk, &w.ctx.plaintext(&v).unwrap()).unwrap()
        })
        .collect()
}

/// Which messages of which round a test changes before delivery.
enum Tamper {
    None,
    /// Party 1 shifts its partial of the last masked value by +delta.
    ShiftPartial(u64),
    /// Party 1 sends a contribution other than the one it committed to.
    SwapContribution,
    /// Party 1 sends another party's checks.
    ForgeChecks,
}

/// Rounds 0 to 6 between the two parties; returns the aggregator's outputs.
fn rounds(w: &mut World, xs: &[Ciphertext], tamper: Tamper) -> fhe_prio3::Result<Vec<Ciphertext>> {
    let split = w.cfg.collector_holds_key();
    let batch = [7u8; 32];
    // in a split-key task only the aggregator holds (and sends) the accumulators
    let own = |_party: usize| -> Option<Vec<Ciphertext>> { (!split).then(|| xs.iter().map(|c| c.try_clone().unwrap()).collect()) };
    let mut states: Vec<GateState> = w.parties.iter_mut().map(|p| std::mem::take(&mut p.st)).collect();
    let r = (|| -> fhe_prio3::Result<Vec<Ciphertext>> {
        let mut commits = Vec::new();
        for (p, st) in states.iter_mut().enumerate() {
            let sends: &[Ciphertext] = if split && p == 0 { xs } else { &[] };
            commits.push(gate::commit(&env(w, &w.parties[p].share, p), st, batch, sends, &mut OsRng)?);
        }
        let mut contribs = Vec::new();
        for (p, st) in states.iter_mut().enumerate() {
            contribs.push(gate::contribute(&env(w, &w.parties[p].share, p), st, &commits)?);
        }
        if let Tamper::SwapContribution = tamper {
            contribs[1].masks.swap(0, 1);
        }
        let mut shares = Vec::new();
        for (p, st) in states.iter_mut().enumerate() {
            shares.push(gate::share(&env(w, &w.parties[p].share, p), st, &contribs, own(p).as_deref(), &mut OsRng)?);
        }
        let ys = gate::masked_values(&env(w, &w.parties[0].share, 0), &states[0], own(0).as_deref())?;
        match tamper {
            Tamper::ShiftPartial(delta) => {
                let i = ys.len() - 1;
                let honest = w.parties[1].share.partial_decrypt(&ys[i], false)?;
                let n = w.ctx.ring_dim() as usize;
                let shifted = w.ctx.add_plain(honest.ciphertext(), &w.ctx.plaintext(&vec![delta; n])?)?;
                shares[1].partials[i] = w.codec.encode(&shifted)?;
                states[1].own_share = Some(shares[1].clone());
            }
            Tamper::ForgeChecks => {
                shares[1].checks = shares[0].checks.clone();
                states[1].own_share = Some(shares[1].clone());
            }
            _ => {}
        }
        let mut cc = Vec::new();
        for (p, st) in states.iter_mut().enumerate() {
            cc.push(gate::check_commit(&env(w, &w.parties[p].share, p), st, &shares, &ys)?);
        }
        let mut openings = Vec::new();
        for (p, st) in states.iter_mut().enumerate() {
            openings.push(gate::open(&env(w, &w.parties[p].share, p), st, &cc)?);
        }
        let mut reveals = Vec::new();
        for (p, st) in states.iter_mut().enumerate() {
            reveals.push(gate::reveal(&env(w, &w.parties[p].share, p), st, &openings, &ys)?);
        }
        for (p, st) in states.iter_mut().enumerate() {
            gate::finish(&env(w, &w.parties[p].share, p), st, &reveals, &ys)?;
        }
        // idempotent: the same y again, without decrypting anything new
        assert_eq!(
            gate::finish(&env(w, &w.parties[0].share, 0), &mut states[0], &reveals, &ys)?,
            states[0].y.clone().unwrap()
        );
        gate::outputs(&env(w, &w.parties[0].share, 0), &states[0])
    })();
    for (p, st) in states.into_iter().enumerate() {
        w.parties[p].st = st;
    }
    r
}

/// The collector's fusion of the outputs with both shares.
fn fuse(w: &World, outs: &[Ciphertext]) -> Vec<Vec<u64>> {
    let n = w.ctx.ring_dim() as usize;
    outs.iter()
        .map(|c| {
            let a = w.parties[0].share.partial_decrypt(c, true).unwrap();
            let b = w.parties[1].share.partial_decrypt(c, false).unwrap();
            w.ctx.fuse(&[&a, &b], n).unwrap()
        })
        .collect()
}

fn split_cfg(min_batch: usize, k: u64) -> TaskConfig {
    let mut c = TaskConfig::new_split_key([41; 32], MeasurementType::Histogram { length: 4 });
    c.silent_batch_groups = 1;
    c.repetitions = 4;
    c.min_batch_size = min_batch;
    c.min_cell_count = k;
    c
}

#[test]
fn split_key_rounds_release_large_cells_and_suppress_small_ones() {
    let mut w = world(split_cfg(3, 2));
    let xs = accumulators(&w, &[1, 2, 5, 0], 8);
    let outs = rounds(&mut w, &xs, Tamper::None).unwrap();
    let u = gate::ungate(&w.cfg, &w.layout, w.cfg.plain_mod, &fuse(&w, &outs)).unwrap();
    let slots = &GatePlan::new(&w.cfg, &w.layout).unwrap().cell_slots[0];
    assert_eq!(slots.iter().map(|&s| u.values[0][s]).collect::<Vec<_>>(), vec![0, 2, 5, 0]);
    assert_eq!(u.suppressed[0], vec![true, false, false, true]);
    // both parties learned the same y, and it is not x
    assert_eq!(w.parties[0].st.y, w.parties[1].st.y);
    let y = &w.parties[0].st.y.as_ref().unwrap()[0];
    assert_ne!(y[w.layout.client_slot(2)], 5);
    // a repeated round returns the same messages, another set is refused
    let mut st = w.parties[0].st.clone();
    let again = gate::commit(&env(&w, &w.parties[0].share, 0), &mut st, [7u8; 32], &xs, &mut OsRng).unwrap();
    assert_eq!(again.digest, w.parties[0].st.own_contribution.as_ref().unwrap().digest());
    assert!(gate::commit(&env(&w, &w.parties[0].share, 0), &mut st, [8u8; 32], &xs, &mut OsRng).is_err());
}

#[test]
fn split_key_rounds_refuse_a_batch_below_the_minimum() {
    let mut w = world(split_cfg(3, 0));
    let xs = accumulators(&w, &[1, 1, 0, 0], 2);
    let outs = rounds(&mut w, &xs, Tamper::None).unwrap();
    let e = gate::ungate(&w.cfg, &w.layout, w.cfg.plain_mod, &fuse(&w, &outs)).err().unwrap().to_string();
    assert!(e.contains("batch below minimum size"), "{e}");
    // at the minimum, the batch passes and the count comes back
    let mut w = world(split_cfg(3, 0));
    let xs = accumulators(&w, &[1, 1, 1, 0], 3);
    let outs = rounds(&mut w, &xs, Tamper::None).unwrap();
    let u = gate::ungate(&w.cfg, &w.layout, w.cfg.plain_mod, &fuse(&w, &outs)).unwrap();
    let plan = GatePlan::new(&w.cfg, &w.layout).unwrap();
    assert_eq!(u.values[1][plan.spread_slots[0]], 3);
    assert_eq!(u.values[0][w.layout.client_slot(2)], 1);
}

#[test]
fn aggregator_rounds_suppress_cells() {
    let mut cfg = TaskConfig::new_silent([42; 32], MeasurementType::Histogram { length: 4 }, 2);
    cfg.silent_batch_groups = 1;
    cfg.repetitions = 4;
    cfg.min_cell_count = 3;
    let mut w = world(cfg);
    let xs = accumulators(&w, &[2, 3, 4, 9], 0);
    let outs = rounds(&mut w, &xs, Tamper::None).unwrap();
    let u = gate::ungate(&w.cfg, &w.layout, w.cfg.plain_mod, &fuse(&w, &outs)).unwrap();
    let slots = &GatePlan::new(&w.cfg, &w.layout).unwrap().cell_slots[0];
    assert_eq!(slots.iter().map(|&s| u.values[0][s]).collect::<Vec<_>>(), vec![0, 3, 4, 9]);
}

#[test]
fn every_round_refuses_its_attack() {
    // a shifted partial of Y (to pass a gate) fails the other party's checks
    let mut w = world(split_cfg(3, 0));
    let xs = accumulators(&w, &[1, 0, 0, 0], 1);
    let e = rounds(&mut w, &xs, Tamper::ShiftPartial(2)).err().unwrap().to_string();
    assert!(e.contains("fails in slot"), "{e}");
    // a contribution other than the committed one
    let mut w = world(split_cfg(3, 0));
    let xs = accumulators(&w, &[1, 0, 0, 0], 3);
    let e = rounds(&mut w, &xs, Tamper::SwapContribution).err().unwrap().to_string();
    assert!(e.contains("not the one it committed to"), "{e}");
    // checks that are not what the party opens: refused before decryption
    let mut w = world(split_cfg(3, 0));
    let xs = accumulators(&w, &[1, 0, 0, 0], 3);
    let e = rounds(&mut w, &xs, Tamper::ForgeChecks).err().unwrap().to_string();
    assert!(e.contains("refusing to decrypt them"), "{e}");
    // rounds out of order
    let mut w = world(split_cfg(3, 0));
    let mut st = GateState::default();
    let e0 = env(&w, &w.parties[0].share, 0);
    assert!(gate::contribute(&e0, &mut st, &[]).is_err());
    assert!(gate::open(&e0, &mut st, &[]).is_err());
    assert!(gate::finish(&e0, &mut st, &[], &[]).is_err());
    assert!(gate::outputs(&e0, &st).is_err());
    // only the split-key aggregator sends accumulators
    let xs = accumulators(&w, &[1, 0, 0, 0], 3);
    let e1 = env(&w, &w.parties[1].share, 1);
    assert!(gate::commit(&e1, &mut GateState::default(), [1; 32], &xs, &mut OsRng).is_err());
    assert!(gate::commit(&e0, &mut GateState::default(), [1; 32], &[], &mut OsRng).is_err());
    // commitments for another batch, a missing party, a foreign task
    let c0 = gate::commit(&e0, &mut st, [1; 32], &xs, &mut OsRng).unwrap();
    let mut other = c0.clone();
    other.party = 1;
    other.batch_digest = [2; 32];
    assert!(gate::contribute(&e0, &mut st, &[c0.clone(), other.clone()]).is_err());
    assert!(gate::contribute(&e0, &mut st, std::slice::from_ref(&c0)).is_err());
    other.batch_digest = [1; 32];
    other.task_id = [9; 32];
    assert!(gate::contribute(&e0, &mut st, &[c0.clone(), other]).is_err());
    w.parties[0].st = st;
    let _ = Expect::Any;
}
