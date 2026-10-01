//! Batched silent mode at full occupancy. The aggregator masks every
//! report's fresh ciphertext to its group's slots and sums them into one
//! accumulator before the validity circuit runs, so the circuit's input
//! carries the noise of a whole batch of masked reports. Building
//! thousands of reports through the client would take an hour; instead one
//! ciphertext is masked to every group's slots (one plaintext
//! multiplication, as the aggregator does per report) and then doubled 14
//! times, which adds its noise to itself coherently and bounds the noise of
//! 2^14 independent masked fresh ciphertexts from above. The plaintext is chosen so that the doubled
//! value is exactly the encoding of an honest report in every group. The
//! batch then runs through the real count round and release, whose
//! flooding and known-answer checks would catch a noise overflow, and the
//! decoded count and sum must be exact.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::*;

const DOUBLINGS: u32 = 14;

/// `2^-DOUBLINGS mod p`, so that `2^DOUBLINGS` doublings give 1.
fn inverse_of_power_of_two(p: u64) -> u64 {
    // Fermat: 2^(p-1) = 1, so 2^-k = 2^(p-1-k)
    let mut base = 2u128;
    let mut e = (p - 1 - DOUBLINGS as u64) as u128;
    let mut acc = 1u128;
    let m = p as u128;
    while e > 0 {
        if e & 1 == 1 {
            acc = acc * base % m;
        }
        base = base * base % m;
        e >>= 1;
    }
    acc as u64
}

fn id(i: usize) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[..8].copy_from_slice(&(i as u64).to_le_bytes());
    r[31] = 0x5A;
    r
}

/// `groups` reports of `Count(true)` in one batch, one of them made invalid
/// (a 2 in its slot), all carried by a single accumulator whose noise is
/// that of 2^14 fresh ciphertexts added together.
#[test]
fn full_batch_noise_stays_exact_through_count_and_release() {
    let _g = serial();
    let groups = 1024usize;
    let mut cfg = TaskConfig::new_silent(task_id(90), MeasurementType::Count, 2);
    cfg.silent_batch_groups = groups;
    let mut net = Net::new(cfg.clone());
    let layout = net.aggs[0].layout().clone();
    assert_eq!((layout.groups, layout.num_chunks), (groups, 1));
    let ctx = keys::make_context(&cfg).unwrap();
    let pk = ctx.deserialize_public_key(&net.material.public_key).unwrap();
    let p = cfg.plain_mod;
    let inv = inverse_of_power_of_two(p);
    assert_eq!((inv as u128 * (1u128 << DOUBLINGS) % p as u128) as u64, 1);
    let bad_group = 5usize;

    // one plaintext: 2^-14 at every group's slot, 2 * 2^-14 at the bad group's
    let mut slots = vec![0u64; layout.row];
    for r in 0..groups {
        slots[layout.group_slot(r, 0)] = inv;
    }
    slots[layout.group_slot(bad_group, 0)] = (inv as u128 * 2 % p as u128) as u64;
    let fresh = ctx.encrypt(&pk, &ctx.plaintext(&slots).unwrap()).unwrap();
    // the per-report group mask, here over every group's element slots
    let mut mask = vec![0u64; layout.row];
    for r in 0..groups {
        mask[layout.group_slot(r, 0)] = 1;
    }
    let mut x = ctx.mult_plain(&fresh, &ctx.plaintext(&mask).unwrap()).unwrap();
    for _ in 0..DOUBLINGS {
        x = ctx.add(&x, &x).unwrap();
    }
    // the same accumulator lands in every aggregator: group 0 carries it,
    // the other groups register their report with an encryption of zero
    // (the test hook skips the group mask, which `x` already went through)
    let zero = ctx.encrypt(&pk, &ctx.plaintext(&[0]).unwrap()).unwrap();
    for agg in net.aggs.iter_mut() {
        agg.accumulate_silent_for_tests(0, id(0), vec![x.try_clone().unwrap()]).unwrap();
        for r in 1..groups {
            agg.accumulate_silent_for_tests(r, id(r), vec![zero.try_clone().unwrap()]).unwrap();
        }
    }
    let res = net.collect_full().unwrap();
    assert_eq!(
        (res.aggregate, res.report_count, res.valid_count),
        (AggregateResult::Count((groups - 1) as u64), groups as u64, (groups - 1) as u64)
    );
}
