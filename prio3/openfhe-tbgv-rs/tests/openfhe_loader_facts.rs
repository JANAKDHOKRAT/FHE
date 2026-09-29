//! Facts about OpenFHE's own ciphertext loader that the packed wire format
//! exists to avoid. The loader is used only for trusted local input (a
//! node's own saved state); these tests pin down why received bytes never
//! reach it. If a future OpenFHE starts refusing these inputs, the test
//! fails and the reasoning in the protocol spec (§6b) should be revisited.
use openfhe_tbgv_rs::*;

const P: u64 = 4_293_918_721;

#[test]
fn loader_accepts_a_residue_at_or_above_its_modulus() {
    let ctx = Context::new(Params { plain_mod: P, mult_depth: 3, security_bits: 128 }).unwrap();
    let (pk, sk) = keygen_first(&ctx).unwrap();
    let q0 = ctx.moduli().unwrap()[0];
    let values = [7u64, 1, 0, 5];
    let ct = ctx.encrypt(&pk, &ctx.plaintext(&values).unwrap()).unwrap();
    let bytes = ct.serialize().unwrap();
    let r0 = ct.export_residues().unwrap()[0];
    let at: Vec<usize> = bytes.windows(8).enumerate().filter(|(_, w)| *w == r0.to_le_bytes()).map(|(i, _)| i).collect();
    assert_eq!(at.len(), 1, "the first residue must occur exactly once in the serialization");
    let info = ct.info().unwrap();
    for v in [r0 + q0, q0, u64::MAX] {
        let mut m = bytes.clone();
        m[at[0]..at[0] + 8].copy_from_slice(&v.to_le_bytes());
        let loaded = ctx.deserialize_ciphertext(&m).expect("OpenFHE's loader accepts the out-of-range residue");
        assert_eq!(loaded.export_residues().unwrap()[0], v, "stored unreduced");
        assert_eq!(loaded.info().unwrap(), info, "every structural check of the old admission path still passes");
        if v == r0 + q0 {
            // the same ciphertext with different bytes: a second encoding,
            // hence a second report id for the same report
            assert_eq!(sk.decrypt_alone_for_tests(&loaded, 4).unwrap(), values.to_vec());
            assert_ne!(m, bytes);
        }
    }
}
