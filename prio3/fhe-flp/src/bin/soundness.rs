//! Soundness of the FLP check for Count and BitVec(len) in three fields,
//! from `fhe_flp::soundness` (the VDAF draft's formulas). Field64 and the
//! 17-bit 65537 are evaluated analytically: this protocol runs in FieldPrio2.
use fhe_flp::bitvec::BitVec;
use fhe_flp::soundness::{log2_error, log2_per_proof, proofs_for};
use prio::field::Field64;
use prio::flp::types::Count;

fn row<T: prio::flp::Flp>(name: &str, typ: &T)
where
    T::Field: prio::field::NttFriendlyFieldElement,
{
    for (fname, p) in [
        ("p=65537", 65537f64),
        ("FieldPrio2 (32-bit)", 4_293_918_721f64),
        ("Field64", 18_446_744_069_414_584_321f64),
    ] {
        let per = log2_per_proof(typ, p);
        let errs: Vec<String> = (1..=6).map(|k| format!("{:>7.1}", log2_error(typ, p, k))).collect();
        println!(
            "| {name:<12} | {fname:<20} | {per:>7.1} | {} | {:>3} | {:>3} | {:>3} |",
            errs.join(" | "),
            proofs_for(typ, p, 64.0),
            proofs_for(typ, p, 100.0),
            proofs_for(typ, p, 128.0)
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
}
