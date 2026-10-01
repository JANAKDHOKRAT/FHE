//! Synthetic wire formats for fuzzing. Small ring dimensions make a whole
//! valid payload a few hundred bytes, so the fuzzer reaches every branch of
//! the parser (including padding bits, which the real parameters never
//! produce); the moduli cover 1-bit to 64-bit towers.
use fhe_prio3::packed::WireFormat;

pub const PLAIN_MOD: u64 = 65537;

const CHAINS: [&[u64]; 8] = [
    &[3],
    &[17, 3],
    &[65537, 2, 97],
    &[u64::MAX - 58, (1 << 40) | 1],
    &[(1 << 61) - 1, 7681, 12289, 3],
    &[140737488486401, 1152921504606748673, 786433],
    &[2],
    &[4294967291, 4294967279, 65521, 251, 13],
];
const RING_DIMS: [usize; 6] = [1, 2, 3, 5, 8, 16];

/// Picks a format from one selector byte.
pub fn format(selector: u8) -> WireFormat {
    let chain = CHAINS[(selector & 7) as usize];
    let n = RING_DIMS[(selector >> 3) as usize % RING_DIMS.len()];
    WireFormat::new(PLAIN_MOD, n, chain.to_vec(), b"fuzzing key").expect("valid synthetic format")
}
