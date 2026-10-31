//! Soundness of the FLP check for the Prio3 types this repository runs, in
//! three fields, from `fhe_flp::soundness` (the VDAF draft's formulas, with
//! prio's padded wire length; joint randomness adds `chunk_length / p` per
//! proof). The types are built over Field64 only to read their gadgets; the
//! bound is evaluated for each prime `p`.
use fhe_flp::bitvec::BitVec;
use fhe_flp::soundness::{log2_error_with_joint_rand, proofs_for_with_joint_rand};
use prio::field::Field64;
use prio::flp::Flp;
use prio::flp::gadgets::{Mul, ParallelSum};
use prio::flp::types::{Count, Histogram, MultihotCountVec, Sum, SumVec};
use prio::vdaf::prio3::optimal_chunk_length;

type Ps = ParallelSum<Field64, Mul>;

/// `chunk_length` for the ParallelSum<Mul> types (joint randomness), else 0.
fn row<T: Flp<Field = Field64>>(name: &str, typ: &T) {
    let jrd = if typ.joint_rand_len() > 0 { typ.gadget()[0].arity() / 2 } else { 0 };
    for (fname, p) in [
        ("p=65537", 65537f64),
        ("FieldPrio2 (32-bit)", 4_293_918_721f64),
        ("Field64", 18_446_744_069_414_584_321f64),
    ] {
        let per = log2_error_with_joint_rand(typ, p, 1, jrd);
        let errs: Vec<String> = (1..=6).map(|k| format!("{:>7.1}", log2_error_with_joint_rand(typ, p, k, jrd))).collect();
        println!(
            "| {name:<20} | {fname:<20} | {per:>7.1} | {} | {:>3} | {:>3} | {:>3} |",
            errs.join(" | "),
            proofs_for_with_joint_rand(typ, p, 64.0, jrd),
            proofs_for_with_joint_rand(typ, p, 100.0, jrd),
            proofs_for_with_joint_rand(typ, p, 128.0, jrd)
        );
    }
}

fn main() {
    println!("log2 of the probability that one invalid report is accepted");
    println!("| type | field | 1 proof | k=1 | k=2 | k=3 | k=4 | k=5 | k=6 | proofs for 2^-64 | 2^-100 | 2^-128 |");
    println!("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    row("Count", &Count::<Field64>::new());
    for len in [10, 25, 50, 100] {
        row(&format!("BitVec({len})"), &BitVec::<Field64>::new(len).unwrap());
    }
    row("Sum(100)", &Sum::<Field64>::new(100).unwrap());
    row("SumVec(10, max 3)", &SumVec::<Field64, Ps>::new(3, 10, optimal_chunk_length(20)).unwrap());
    row("SumVec(100, max 1)", &SumVec::<Field64, Ps>::new(1, 100, optimal_chunk_length(100)).unwrap());
    row("Histogram(100)", &Histogram::<Field64, Ps>::new(100, optimal_chunk_length(100)).unwrap());
    row(
        "Multihot(100, w 10)",
        &MultihotCountVec::<Field64, Ps>::new(100, 10, optimal_chunk_length(104)).unwrap(),
    );
}
