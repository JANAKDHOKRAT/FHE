//! PINE's encoding and circuits against what exists outside this crate.
//!
//! 1. The reference implementation's test vectors
//!    (`draft-chen-cfrg-vdaf-pine` at 4d11ac8,
//!    `poc/test_vec/01/Pine32HmacSha256Aes128_*.json`; `Field32` is
//!    FieldPrio2): the gradient encoding of each vector's floats must equal
//!    the sum of the vector's output shares, and decoding the sum of the
//!    gradients must give the vector's aggregate result.
//!
//!    Not compared with the vectors: the bit-checked part of a measurement,
//!    proofs and verifier messages. The helpers' measurement shares are
//!    seeds there, and expanding them with the reference's XOF as shipped
//!    next to the vectors does not reproduce the vectors' own output
//!    shares (several tag formats were tried), so the full measurement
//!    cannot be recombined without running the reference; and the reference
//!    builds on VDAF draft 11 while prio 0.18.1 implements draft 18, which
//!    encodes proofs differently.
//!
//! 2. `pine-bgv-port/port/pine-circuit`, written separately from the same
//!    reference: both circuits must agree with it on random inputs, joint
//!    randomness and share counts, for several chunk lengths.
use fhe_flp::Field;
use fhe_flp::pine::circuit::{Main, NUM_WR_CHECKS, NUM_WR_SUCCESSES, NormEquality, Shape};
use prio::field::FieldElement;
use prio::flp::Flp;
use prio::vdaf::xof::{IntoFieldVec, Xof, XofTurboShake128};
use serde_json::Value;

fn field_vec(v: &Value) -> Vec<Field> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| {
            let s = x.as_str().unwrap();
            let b: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
            Field::from(u32::from_le_bytes(b.try_into().unwrap()))
        })
        .collect()
}

#[test]
fn gradient_encoding_and_decoding_match_the_reference_vectors() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../pine-bgv-port/upstream/poc/test_vec/01");
    let mut reports = 0;
    for n in 0..8 {
        let t: Value = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/Pine32HmacSha256Aes128_{n}.json")).unwrap()).unwrap();
        assert_eq!(t["field"], "Field32");
        let u = |k: &str| t[k].as_u64().unwrap();
        let shape = Shape::new(u("dimension") as usize, u("l2_norm_bound"), u("num_frac_bits") as u32).unwrap();
        let d = shape.dimension();
        let mut sum = vec![Field::zero(); d];
        for prep in t["prep"].as_array().unwrap() {
            let mut gradient = vec![Field::zero(); d];
            for share in prep["out_shares"].as_array().unwrap() {
                for (g, s) in gradient.iter_mut().zip(field_vec(share)) {
                    *g += s;
                }
            }
            let floats: Vec<f64> = prep["measurement"].as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect();
            assert_eq!(shape.encode_gradient_and_norm(&floats).unwrap()[..d], gradient, "vector {n}");
            for (s, g) in sum.iter_mut().zip(&gradient) {
                *s += *g;
            }
            reports += 1;
        }
        let want: Vec<f64> = t["agg_result"].as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect();
        assert_eq!(shape.decode(&sum), want, "vector {n}");
    }
    assert_eq!(reports, 16);
}

#[test]
fn both_circuits_agree_with_the_separately_written_port() {
    let mut stream = XofTurboShake128::seed_stream(&[7; 32], &[b"pine circuit comparison"], &[]);
    let mut random = |n: usize| -> Vec<Field> { (&mut stream).into_field_vec(n) };
    for (d, bound) in [(3, 16), (17, 128), (250, 16), (41, 32768)] {
        let shape = Shape::new(d, bound, 4).unwrap();
        for chunk in [1, 2, 3, 7, 32, 150] {
            let norm_eq = NormEquality::new(shape.clone(), chunk).unwrap();
            let main = Main::new(shape.clone(), chunk).unwrap();
            let other_norm_eq = pine_circuit::Circuit::with_chunk(d, bound as u32, NUM_WR_CHECKS, NUM_WR_SUCCESSES, true, chunk).unwrap();
            let other_main = pine_circuit::Circuit::with_chunk(d, bound as u32, NUM_WR_CHECKS, NUM_WR_SUCCESSES, false, chunk).unwrap();
            assert_eq!(
                (norm_eq.input_len(), norm_eq.proof_len(), norm_eq.verifier_len()),
                (other_norm_eq.input_len(), other_norm_eq.proof_len(), other_norm_eq.verifier_len())
            );
            assert_eq!(
                (main.input_len(), main.proof_len(), main.verifier_len()),
                (other_main.input_len(), other_main.proof_len(), other_main.verifier_len())
            );
            for shares in [1, 2, 3] {
                let input = random(main.input_len());
                let jr = random(3);
                assert_eq!(
                    norm_eq.valid(&mut norm_eq.gadget(), &input, &[], shares).unwrap(),
                    other_norm_eq.valid(&mut other_norm_eq.gadget(), &input, &[], shares).unwrap(),
                    "norm equality d={d} chunk={chunk}"
                );
                assert_eq!(
                    main.valid(&mut main.gadget(), &input, &jr, shares).unwrap(),
                    other_main.valid(&mut other_main.gadget(), &input, &jr, shares).unwrap(),
                    "main d={d} chunk={chunk}"
                );
            }
        }
    }
}
