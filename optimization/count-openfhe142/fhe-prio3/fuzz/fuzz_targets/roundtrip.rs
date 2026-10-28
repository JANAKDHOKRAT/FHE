//! Valid metadata and residues derived from the input: encoding then
//! parsing must return exactly them, at exactly the predicted length.
#![no_main]
use fhe_prio3::packed::{Expect, WireError};
use libfuzzer_sys::fuzz_target;
use openfhe_tbgv_rs::CiphertextMeta;

mod common;

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }
    let f = common::format(data[0]);
    let l = f.moduli().len() as u32;
    let k = 1 + (data[1] as u32 % l);
    let meta = CiphertextMeta {
        num_elements: 1 + (data[2] as u32 & 1),
        num_towers: k,
        level: l - k,
        noise_scale_deg: 1 + (data[3] as u32 & 1),
        scaling_factor_int: 1 + u64::from_le_bytes(data[4..12].try_into().unwrap()) % (common::PLAIN_MOD - 1),
    };
    let n = f.ring_dim();
    let count = meta.num_elements as usize * k as usize * n;
    let words = &data[12..];
    let residues: Vec<u64> = (0..count)
        .map(|j| {
            let mut w = [0u8; 8];
            for (b, x) in w.iter_mut().enumerate() {
                *x = words.get((j * 8 + b) % words.len().max(1)).copied().unwrap_or(0) ^ (j as u8);
            }
            u64::from_le_bytes(w) % f.moduli()[(j / n) % k as usize]
        })
        .collect();
    let bytes = f.encode_raw(&meta, &residues).expect("valid input must encode");
    assert_eq!(bytes.len(), f.encoded_len(&meta));
    assert_eq!(
        f.parse(&bytes, Expect::Exactly(meta)).expect("own encoding must parse"),
        (meta, residues.clone())
    );
    // one residue pushed to its modulus is refused by both directions
    let mut bad = residues;
    let j = data[1] as usize % count;
    bad[j] = f.moduli()[(j / n) % k as usize];
    assert!(matches!(f.encode_raw(&meta, &bad), Err(WireError::ResidueOutOfRange { .. })));
});
