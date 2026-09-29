//! Arbitrary bytes into the parser. Properties: never panics; anything it
//! accepts satisfies every bound, parses identically under the matching
//! expectations, and re-encodes to exactly the input (one ciphertext, one
//! encoding).
#![no_main]
use fhe_prio3::packed::{Expect, HEADER_LEN, MAGIC, VERSION};
use libfuzzer_sys::fuzz_target;

mod common;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let f = common::format(data[0]);
    let flags = data[1];
    let mut bytes = data[2..].to_vec();
    // Optionally make the fixed header fields right so that the fuzzer
    // spends its time on the shape, length and residue checks.
    if flags & 1 != 0 && bytes.len() >= HEADER_LEN {
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4] = VERSION;
        bytes[24..56].copy_from_slice(&f.fingerprint());
    }
    if flags & 2 != 0 && bytes.len() >= HEADER_LEN {
        bytes[13..16].copy_from_slice(&[0, 0, 0]);
    }
    let parsed = f.parse(&bytes, Expect::Any);
    if let Ok((meta, residues)) = &parsed {
        assert!(f.check_meta(meta).is_ok());
        assert_eq!(bytes.len(), f.encoded_len(meta));
        let k = meta.num_towers as usize;
        let n = f.ring_dim();
        assert_eq!(residues.len(), meta.num_elements as usize * k * n);
        for (j, &v) in residues.iter().enumerate() {
            assert!(v < f.moduli()[(j / n) % k], "residue above its modulus accepted");
        }
        assert_eq!(f.encode_raw(meta, residues).expect("accepted input must re-encode"), bytes, "non-canonical input accepted");
        assert_eq!(f.parse(&bytes, Expect::Exactly(*meta)).as_ref(), parsed.as_ref().map_err(|e| e));
        assert_eq!(f.parse(&bytes, Expect::Partial).is_ok(), meta.num_elements == 1);
    } else {
        // refused under Any means refused under every expectation
        assert!(f.parse(&bytes, Expect::Partial).is_err());
    }
});
