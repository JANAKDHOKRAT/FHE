//! Startup self-test of ciphertext rebuilding against the OpenFHE library
//! actually loaded in this process.
//!
//! [`Context::build_ciphertext`] reconstructs a ciphertext from its residues
//! and five metadata values (element count, tower count, level, noise-scale
//! degree, scaling factor), taking everything else from a fresh reference
//! encryption. That is exact only as long as OpenFHE gives those fields the
//! meaning they have in the tested version. A library upgrade (the binaries
//! link OpenFHE by major version only, so a newer library can be picked up
//! without a rebuild) could change it, and a wrong rebuild would not crash:
//! it would silently evaluate or decrypt something else.
//!
//! The self-test therefore runs, once per parameter set and process, the
//! checks of the exactness test on the loaded library: with throwaway
//! 2-of-2 threshold keys generated in the same context, it builds every
//! object kind the protocol exchanges (fresh encryptions, sums, plaintext
//! products, ciphertext products, rotations, squarings down to the deepest
//! level, and lead and main partial decryptions of each), rebuilds each from
//! its residues and metadata, and requires identical metadata and residues,
//! `original - rebuilt` to decrypt to zero in every slot, the rebuilt object
//! to decrypt to the expected values, fresh encryptions to re-serialize byte
//! for byte, and fusion of rebuilt partial decryptions to equal fusion of
//! the originals. `build_ciphertext` refuses to run for parameters that
//! have not passed.
//!
//! The throwaway keys are installed under their own key tag and removed
//! when the test ends, whether it passes or not. Key generation and
//! installation touch OpenFHE's process-global key tables, so, like key
//! installation elsewhere in this crate, the self-test must not run
//! concurrently with evaluation on another thread: run it at startup.

use crate::*;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// What a passed self-test covered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildReport {
    /// OpenFHE version this crate was built against (see `build.rs`).
    pub openfhe_version: String,
    /// Resolved paths of the OpenFHE libraries loaded in this process.
    pub libraries: Vec<String>,
    /// Objects rebuilt and checked, partial decryptions included.
    pub objects_checked: usize,
    /// Deepest level reached (the context's multiplicative depth).
    pub deepest_level: u32,
    pub elapsed: Duration,
}

type Rebuild<'a> = &'a dyn Fn(&Context, &Ciphertext, &CiphertextMeta, &[u64]) -> Result<Ciphertext>;

type Outcome = std::result::Result<RebuildReport, String>;

/// Outcomes by (parameters, depth).
type Outcomes = HashMap<(Vec<u64>, u32), Outcome>;

fn cache() -> &'static Mutex<Outcomes> {
    static CACHE: OnceLock<Mutex<Outcomes>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn params_key(ctx: &Context) -> Result<Vec<u64>> {
    let mut k = vec![ctx.plain_mod(), ctx.ring_dim() as u64];
    k.extend(ctx.moduli()?);
    Ok(k)
}

/// OpenFHE refuses partial decryption in `NOISE_FLOODING_MULTIPARTY` mode
/// below three towers, so no protocol object is ever decrypted deeper.
const MIN_DECRYPTABLE_TOWERS: u32 = 3;

/// Runs the self-test for `ctx`'s parameters down to level `depth` (the
/// deepest level the caller's protocol produces: its multiplicative depth)
/// unless it already passed in this process at that depth or deeper, and
/// returns its outcome. A failure is remembered too: the library does not
/// change while the process runs.
pub fn verify_rebuild_once(ctx: &Context, depth: u32) -> Result<RebuildReport> {
    check_loaded_openfhe()?;
    let l = ctx.num_towers();
    if depth == 0 || depth + MIN_DECRYPTABLE_TOWERS > l {
        return Err(Error(format!(
            "self-test depth {depth} is outside 1..={} for a chain of {l} towers (threshold decryption needs {MIN_DECRYPTABLE_TOWERS} towers)",
            l.saturating_sub(MIN_DECRYPTABLE_TOWERS)
        )));
    }
    let params = params_key(ctx)?;
    let mut cache = cache().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(r) = cache
        .iter()
        .find(|((p, d), r)| *p == params && *d >= depth && r.is_ok())
        .map(|(_, r)| r.clone())
    {
        return r.map_err(Error);
    }
    if let Some(r) = cache.get(&(params.clone(), depth)) {
        return r.clone().map_err(Error);
    }
    let outcome = run(ctx, depth, &|c, r, m, v| c.build_ciphertext_unverified(r, m, v)).map_err(|e| {
        format!(
            "ciphertext rebuild self-test failed on OpenFHE {OPENFHE_VERSION} as loaded ({}): {}. \
             Received ciphertexts cannot be rebuilt exactly with this library; refusing to run.",
            loaded_openfhe_libraries().map(|l| l.join(", ")).unwrap_or_else(|e| e.0),
            e.0
        )
    });
    cache.insert((params, depth), outcome.clone());
    outcome.map_err(Error)
}

/// The deepest level at which the self-test has passed for `ctx`'s
/// parameters in this process, if any. [`Context::build_ciphertext`]
/// refuses objects deeper than this.
pub fn rebuild_verified(ctx: &Context) -> Result<Option<u32>> {
    let params = params_key(ctx)?;
    let cache = cache().lock().unwrap_or_else(|e| e.into_inner());
    Ok(cache.iter().filter(|((p, _), r)| *p == params && r.is_ok()).map(|((_, d), _)| *d).max())
}

/// Removes the throwaway keys however the test ends.
struct ClearTag(String);
impl Drop for ClearTag {
    fn drop(&mut self) {
        let _ = Context::clear_keys_for_tag(&self.0);
    }
}

fn fail<T>(msg: String) -> Result<T> {
    Err(Error(msg))
}

fn run(ctx: &Context, depth: u32, rebuild: Rebuild<'_>) -> Result<RebuildReport> {
    let start = Instant::now();
    let p = ctx.plain_mod();
    let n = ctx.ring_dim() as usize;
    let l = ctx.num_towers();

    // throwaway 2-of-2 keys: public key, relinearisation key, rotation by 1
    let (pk0, s0) = keygen_first(ctx)?;
    let (pk, s1) = keygen_next(ctx, &pk0)?;
    let tag = pk.tag()?;
    let _clear = ClearTag(tag.clone());
    let r1 = EvalMultKey::round1_first(ctx, &s0)?;
    let r1b = EvalMultKey::round1_next(ctx, &s1, &r1)?;
    let r1sum = EvalMultKey::round1_add(ctx, &r1, &r1b, &tag)?;
    let r2a = EvalMultKey::round2(ctx, &s0, &r1sum, &tag)?;
    let r2b = EvalMultKey::round2(ctx, &s1, &r1sum, &tag)?;
    ctx.install_eval_mult_key(&EvalMultKey::round2_add(ctx, &r2a, &r2b, &tag)?, &tag)?;
    let rk0 = RotationKeys::first(ctx, &s0, &[1])?;
    let rk1 = RotationKeys::next(ctx, &s1, &rk0, &[1], &tag)?;
    ctx.install_rotation_keys(&RotationKeys::add(ctx, &rk0, &rk1, &tag)?, &tag)?;

    let reference = ctx.encrypt(&pk, &ctx.plaintext(&[0])?)?;
    let fresh_meta = reference.meta()?;
    if fresh_meta.num_towers != l || fresh_meta.level != 0 || fresh_meta.num_elements != 2 {
        return fail(format!("a fresh encryption has unexpected metadata {fresh_meta:?} for a chain of {l} towers"));
    }

    let mut checked = 0usize;
    // Rebuilds `ct` and checks, over every slot of both rows, that it is the
    // same ciphertext: identical metadata and residues; the same key and
    // type (OpenFHE's own check when the two are combined); decryption of
    // the rebuilt object equal to `expected`; lead and main partial
    // decryptions of it that rebuild exactly and fuse to the same values.
    let mut check = |name: &str, ct: &Ciphertext, expected: &[u64], fresh: bool| -> Result<Ciphertext> {
        let meta = ct.meta()?;
        if meta.level + meta.num_towers != l {
            return fail(format!("{name}: level {} with {} towers of {l}", meta.level, meta.num_towers));
        }
        let res = ct.export_residues()?;
        let back = rebuild(ctx, &reference, &meta, &res)?;
        if back.meta()? != meta {
            return fail(format!("{name}: rebuilt metadata {:?} differs from {meta:?}", back.meta()?));
        }
        if back.export_residues()? != res {
            return fail(format!("{name}: rebuilt residues differ"));
        }
        ctx.sub(ct, &back)?;
        if fresh && back.serialize()? != ct.serialize()? {
            return fail(format!("{name}: rebuilt fresh encryption does not re-serialize identically"));
        }
        let pa = s0.partial_decrypt(&back, true)?;
        let pb = s1.partial_decrypt(&back, false)?;
        let got = ctx.fuse(&[&pa, &pb], n)?;
        if got != expected {
            let i = got.iter().zip(expected).position(|(a, b)| a != b).unwrap_or(0);
            return fail(format!(
                "{name}: rebuilt object decrypts wrongly (slot {i}: {} instead of {})",
                got[i], expected[i]
            ));
        }
        let mut rebuilt_partials = Vec::with_capacity(2);
        for (which, pd) in [("lead", &pa), ("main", &pb)] {
            let pm = pd.ciphertext().meta()?;
            if pm.num_elements != 1 || pm.level != meta.level || pm.num_towers != meta.num_towers {
                return fail(format!("{name}: {which} partial decryption has metadata {pm:?}"));
            }
            let pres = pd.ciphertext().export_residues()?;
            let pback = rebuild(ctx, &reference, &pm, &pres)?;
            if pback.meta()? != pm || pback.export_residues()? != pres {
                return fail(format!("{name}: rebuilt {which} partial decryption differs"));
            }
            rebuilt_partials.push(PartialDecryption::from_ciphertext(pback, which == "lead"));
        }
        if ctx.fuse(&[&rebuilt_partials[0], &rebuilt_partials[1]], n)? != got {
            return fail(format!("{name}: fusion of rebuilt partial decryptions differs"));
        }
        checked += 3;
        Ok(back)
    };

    // Slot vectors over all N slots; values in the first 16 slots of each
    // row, zero elsewhere.
    let half = n / 2;
    let mulp = |x: u64, y: u64| ((x as u128 * y as u128) % p as u128) as u64;
    let spread = |f: &dyn Fn(u64) -> u64| -> Vec<u64> {
        (0..n)
            .map(|j| {
                if j % half < 16 {
                    f(j as u64 % half as u64 + 17 * (j / half) as u64) % p
                } else {
                    0
                }
            })
            .collect()
    };
    let a = spread(&|i| i + 2);
    let b = spread(&|i| 3 * i + 5);
    // rotation by one within each row: slot i takes slot i + 1, cyclically
    let rotated = |v: &[u64]| -> Vec<u64> { (0..n).map(|j| v[(j / half) * half + (j % half + 1) % half]).collect() };
    let ca = ctx.encrypt(&pk, &ctx.plaintext(&a)?)?;
    let cb = ctx.encrypt(&pk, &ctx.plaintext(&b)?)?;
    let ra = check("fresh", &ca, &a, true)?;
    check("fresh (second)", &cb, &b, true)?;
    let sum: Vec<u64> = a.iter().zip(&b).map(|(x, y)| (x + y) % p).collect();
    check("sum", &ctx.add(&ca, &cb)?, &sum, false)?;
    let prod: Vec<u64> = a.iter().zip(&b).map(|(&x, &y)| mulp(x, y)).collect();
    check("plaintext product", &ctx.mult_plain(&ca, &ctx.plaintext(&b)?)?, &prod, false)?;
    check("product", &ctx.mult(&ca, &cb)?, &prod, false)?;
    // a rebuilt ciphertext is a working operand
    check("product of a rebuilt operand", &ctx.mult(&ra, &cb)?, &prod, false)?;
    check("rotation", &ctx.rotate(&ca, 1)?, &rotated(&a), false)?;

    // squarings down to level `depth`, with a rotation half way and at the end
    let mut x = ca;
    let mut xv = a.clone();
    for d in 1..=depth {
        x = ctx.square(&x)?;
        xv = xv.iter().map(|&v| mulp(v, v)).collect();
        x = check(&format!("square at level {d}"), &x, &xv, false)?;
        if d == depth / 2 || d == depth {
            check(&format!("rotation at level {d}"), &ctx.rotate(&x, 1)?, &rotated(&xv), false)?;
        }
    }
    let deepest = x.meta()?.level;
    if deepest != depth {
        return fail(format!("the squaring chain ended at level {deepest}, expected the depth {depth}"));
    }
    Ok(RebuildReport {
        openfhe_version: OPENFHE_VERSION.to_string(),
        libraries: loaded_openfhe_libraries()?,
        objects_checked: checked,
        deepest_level: deepest,
        elapsed: start.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: u64 = 4_293_918_721;

    fn ctx() -> Context {
        Context::new(Params {
            plain_mod: P,
            mult_depth: 3,
            security_bits: 128,
        })
        .unwrap()
    }

    #[test]
    fn passes_on_the_loaded_library_and_gates_build_ciphertext() {
        let ctx = ctx();
        let r = verify_rebuild_once(&ctx, 3).unwrap();
        assert_eq!(r.deepest_level, 3);
        assert!(r.objects_checked >= 3 * 12, "{r:?}");
        assert_eq!(rebuild_verified(&ctx).unwrap(), Some(3));
        // cached: the same or a shallower depth returns the same report
        assert_eq!(verify_rebuild_once(&ctx, 3).unwrap(), r);
        assert_eq!(verify_rebuild_once(&ctx, 2).unwrap(), r);
        // a depth threshold decryption cannot reach is refused
        let l = ctx.num_towers();
        assert!(verify_rebuild_once(&ctx, l - 2).is_err());
        assert!(verify_rebuild_once(&ctx, 0).is_err());
        println!("SELFTEST {r:?}");
    }

    // Each faulty rebuild below still produces a well-formed ciphertext; the
    // self-test must notice that it is not the same ciphertext.

    #[test]
    fn detects_a_rebuild_that_ignores_the_scaling_factor() {
        let ctx = ctx();
        let e = run(&ctx, 3, &|c, r, m, v| {
            let fresh = r.meta()?;
            c.build_ciphertext_unverified(
                r,
                &CiphertextMeta {
                    scaling_factor_int: fresh.scaling_factor_int,
                    ..*m
                },
                v,
            )
        })
        .unwrap_err();
        println!("SELFTEST scaling factor: {e}");
    }

    #[test]
    fn detects_a_rebuild_that_ignores_the_noise_degree() {
        let ctx = ctx();
        let e = run(&ctx, 3, &|c, r, m, v| {
            c.build_ciphertext_unverified(r, &CiphertextMeta { noise_scale_deg: 1, ..*m }, v)
        })
        .unwrap_err();
        println!("SELFTEST noise degree: {e}");
    }

    #[test]
    fn detects_a_rebuild_that_alters_one_residue() {
        let ctx = ctx();
        let q0 = ctx.moduli().unwrap()[0];
        let e = run(&ctx, 3, &|c, r, m, v| {
            let mut w = v.to_vec();
            w[5] = (w[5] + 1) % q0;
            c.build_ciphertext_unverified(r, m, &w)
        })
        .unwrap_err();
        println!("SELFTEST residue: {e}");
    }

    #[test]
    fn detects_a_rebuild_from_a_reference_under_another_key() {
        // Metadata and residues are identical; only a field outside them
        // (the key tag the reference carries) differs, so only the
        // decryption checks can notice.
        let ctx = ctx();
        let (other_pk, _other_sk) = keygen_first(&ctx).unwrap();
        let other_ref = ctx.encrypt(&other_pk, &ctx.plaintext(&[0]).unwrap()).unwrap();
        let e = run(&ctx, 3, &|c, _r, m, v| c.build_ciphertext_unverified(&other_ref, m, v)).unwrap_err();
        println!("SELFTEST other key: {e}");
    }

    #[test]
    fn detects_a_rebuild_at_the_wrong_level() {
        let ctx = ctx();
        let e = run(&ctx, 3, &|c, r, m, v| {
            // keeps the tower count, claims the fresh level: refused by the shim
            c.build_ciphertext_unverified(r, &CiphertextMeta { level: 0, ..*m }, v)
        })
        .unwrap_err();
        println!("SELFTEST level: {e}");
    }
}
