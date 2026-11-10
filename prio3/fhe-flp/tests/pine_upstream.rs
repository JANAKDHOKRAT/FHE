//! PINE's encoding and circuits against what exists outside this crate.
//!
//! 1. The reference implementation's test vectors
//!    (`draft-chen-cfrg-vdaf-pine` at 4d11ac8,
//!    `poc/test_vec/01/Pine32HmacSha256Aes128_*.json`; `Field32` is
//!    FieldPrio2).
//!
//!    The reference shares a measurement between aggregators. For the four
//!    vectors with the reference's default 100 wraparound tests (8 reports)
//!    each measurement is recombined here: the leader's share is in the
//!    vector, each helper's is expanded from its seed with the reference's
//!    XOF (prio's `XofHmacSha256Aes128`) and domain separation tags. Then:
//!    * the gradient and norm encoding of the vector's floats must equal
//!      the recombined measurement;
//!    * the wraparound tests, run on the stream the reference derives from
//!      the public share, must give the recombined bit-checked part;
//!    * both circuits must output 0 on it, with the verification joint
//!      randomness the reference derives, and not on modified measurements;
//!    * the two joint randomness seeds derived here must be the vector's
//!      prep message.
//!
//!    For all eight vectors (16 reports; four use 75 wraparound tests, which
//!    this crate does not offer) the gradient encoding must equal the sum of
//!    the vector's output shares and decoding the sum of the gradients must
//!    give the vector's aggregate result.
//!
//!    Not compared: proofs and verifier messages. The reference builds on
//!    VDAF draft 11, where a proof holds the coefficients of the gadget
//!    polynomial; prio 0.18.1 implements draft 18, where it holds values
//!    (Lagrange basis). Proving and verifying here are prio's.
//!
//! 2. `pine-bgv-port/port/pine-circuit`, written separately from the same
//!    reference: both circuits must agree with it on random inputs, joint
//!    randomness and share counts, for several chunk lengths.
use fhe_flp::Field;
use fhe_flp::pine::circuit::{Main, NUM_WR_CHECKS, NUM_WR_SUCCESSES, NormEquality, Shape};
use prio::field::FieldElement;
use prio::flp::Flp;
use prio::vdaf::xof::{IntoFieldVec, Xof, XofHmacSha256Aes128, XofTurboShake128};
use rand_core::Rng;
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

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../pine-bgv-port/upstream/poc/test_vec/01");

const USAGE_MEAS_SHARE: u16 = 1;
const USAGE_JOINT_RANDOMNESS: u16 = 3;
const USAGE_JOINT_RAND_SEED: u16 = 6;
const USAGE_WR_JOINT_RANDOMNESS: u16 = 8;
const USAGE_WR_JOINT_RAND_SEED: u16 = 9;

/// The reference's `domain_separation_tag`: PINE draft version 1, the
/// algorithm identifier of `Pine32HmacSha256Aes128` (0xFFFF1005), usage.
fn dst(usage: u16) -> [u8; 7] {
    let u = usage.to_be_bytes();
    [1, 0xff, 0xff, 0x10, 0x05, u[0], u[1]]
}

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The reference's `derive_seed` with an all-zero seed.
fn derive_seed(usage: u16, binder: &[u8]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    XofHmacSha256Aes128::seed_stream(&[0u8; 32], &[&dst(usage)], &[binder]).fill_bytes(&mut seed);
    seed
}

#[test]
fn measurements_wraparound_tests_and_circuits_match_the_reference_vectors() {
    let mut reports = 0;
    for n in 0..4 {
        let t: Value = serde_json::from_str(&std::fs::read_to_string(format!("{DIR}/Pine32HmacSha256Aes128_{n}.json")).unwrap()).unwrap();
        assert_eq!(
            (
                t["alpha"].as_f64().unwrap(),
                t["num_wr_checks"].as_u64().unwrap(),
                t["num_wr_successes"].as_u64().unwrap()
            ),
            (8.7, 100, 100)
        );
        let u = |k: &str| t[k].as_u64().unwrap() as usize;
        let (shares, proofs) = (u("shares"), u("proofs"));
        let shape = Shape::new(u("dimension"), u("l2_norm_bound") as u64, u("num_frac_bits") as u32).unwrap();
        let main = Main::new(shape.clone(), u("chunk_length")).unwrap();
        let norm_eq = NormEquality::new(shape.clone(), u("chunk_length_norm_equality")).unwrap();
        let (d, ml, gl) = (shape.dimension(), shape.meas_len(), shape.gradient_and_norm_len());

        for prep in t["prep"].as_array().unwrap() {
            let input_shares = prep["input_shares"].as_array().unwrap();
            assert_eq!(input_shares.len(), shares);
            let leader = unhex(&input_shares[0]);
            // Leader share: measurement share, proofs share, two blinds.
            assert_eq!(
                leader.len(),
                4 * (ml + u("proofs_norm_equality") * norm_eq.proof_len() + proofs * main.proof_len()) + 64,
                "vector {n}: lengths"
            );
            let mut meas: Vec<Field> = leader[..4 * ml]
                .chunks(4)
                .map(|c| Field::from(u32::from_le_bytes(c.try_into().unwrap())))
                .collect();
            for (j, share) in input_shares.iter().enumerate().skip(1) {
                let seed: [u8; 32] = unhex(share)[..32].try_into().unwrap();
                let helper: Vec<Field> = XofHmacSha256Aes128::seed_stream(&seed, &[&dst(USAGE_MEAS_SHARE)], &[&[j as u8]]).into_field_vec(ml);
                for (m, h) in meas.iter_mut().zip(helper) {
                    *m += h;
                }
            }

            let floats: Vec<f64> = prep["measurement"].as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect();
            assert_eq!(shape.encode_gradient_and_norm(&floats).unwrap(), meas[..gl], "vector {n}: gradient and norm");

            let public = unhex(&prep["public_share"]);
            assert_eq!(public.len(), 2 * 32 * shares);
            let wr_seed = derive_seed(USAGE_WR_JOINT_RAND_SEED, &public[..32 * shares]);
            let vf_seed = derive_seed(USAGE_JOINT_RAND_SEED, &public[32 * shares..]);
            assert_eq!(
                [wr_seed, vf_seed].concat(),
                unhex(&prep["prep_messages"][0]),
                "vector {n}: joint randomness seeds"
            );

            let mut wr_stream = XofHmacSha256Aes128::seed_stream(&wr_seed, &[&dst(USAGE_WR_JOINT_RANDOMNESS)], &[]);
            let vectors = shape.wr_vectors(&mut wr_stream);
            let (wr_bits, wr_results) = shape
                .encode_wr_checks(&meas[..d], &vectors)
                .expect("the reference's report passes every wraparound test");
            assert_eq!(wr_bits, meas[gl..], "vector {n}: wraparound tests");

            let joint_rands: Vec<Field> =
                XofHmacSha256Aes128::seed_stream(&vf_seed, &[&dst(USAGE_JOINT_RANDOMNESS)], &[&[proofs as u8]]).into_field_vec(3 * proofs);
            let mut input = meas.clone();
            input.extend(&wr_results);
            let zero = vec![Field::zero()];
            assert_eq!(norm_eq.valid(&mut norm_eq.gadget(), &input, &[], 1).unwrap(), zero, "vector {n}: norm equality");
            for jr in joint_rands.chunks(3) {
                assert_eq!(main.valid(&mut main.gadget(), &input, jr, 1).unwrap(), zero, "vector {n}: main circuit");
            }
            // A changed gradient coordinate breaks the norm equality; a
            // changed claimed bit, success bit or dot product breaks the
            // main circuit.
            let mut bad = input.clone();
            bad[0] += Field::one();
            assert_ne!(norm_eq.valid(&mut norm_eq.gadget(), &bad, &[], 1).unwrap(), zero);
            for i in [d, d + shape.norm_bits(), gl, ml - 1, ml, ml + NUM_WR_CHECKS - 1] {
                let mut bad = input.clone();
                bad[i] += Field::one();
                assert_ne!(
                    main.valid(&mut main.gadget(), &bad, &joint_rands[..3], 1).unwrap(),
                    zero,
                    "vector {n}: index {i}"
                );
            }
            reports += 1;
        }
    }
    assert_eq!(reports, 8);
}

#[test]
fn gradient_encoding_and_decoding_match_the_reference_vectors() {
    let mut reports = 0;
    for n in 0..8 {
        let t: Value = serde_json::from_str(&std::fs::read_to_string(format!("{DIR}/Pine32HmacSha256Aes128_{n}.json")).unwrap()).unwrap();
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
