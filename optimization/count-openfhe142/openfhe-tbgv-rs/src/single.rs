//! Native-key startup qualification; threshold verification remains separate.
use crate::*;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

type Outcomes = HashMap<(Vec<u64>, u32), std::result::Result<RebuildReport, String>>;
fn cache() -> &'static Mutex<Outcomes> {
    static CACHE: OnceLock<Mutex<Outcomes>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}
fn params(ctx: &Context) -> Result<Vec<u64>> {
    let mut p = vec![ctx.plain_mod(), ctx.ring_dim() as u64, u64::from(ctx.is_single_mode()?)];
    let q = ctx.moduli()?;
    let qp = ctx.key_basis_moduli(KeyBasis::KeySwitch)?;
    p.extend([ctx.key_num_parts()? as u64, q.len() as u64, qp.len() as u64]);
    p.extend(q);
    p.extend(qp);
    Ok(p)
}
pub(crate) fn verified(ctx: &Context) -> Result<Option<u32>> {
    let p = params(ctx)?;
    Ok(cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|((k, _), v)| *k == p && v.is_ok())
        .map(|((_, d), _)| *d)
        .max())
}

/// Qualifies bit-exact rebuilding, ordinary decryption and evaluation through
/// every requested level. Never invokes threshold decryption or records a
/// threshold qualification. Finite correctness evidence, not a security proof.
pub fn verify_single_rebuild_once(ctx: &Context, depth: u32) -> Result<RebuildReport> {
    let _serial = crate::selftest::qualification_lock().lock().unwrap_or_else(|e| e.into_inner());
    check_loaded_openfhe()?;
    if !ctx.is_single_mode()? || depth == 0 || depth >= ctx.num_towers() {
        return Err(Error("native self-test requires non-flooding mode and 0 < depth < towers".into()));
    }
    let p = params(ctx)?;
    let mut entries = cache().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(v) = entries.iter().find(|((k, d), v)| *k == p && *d >= depth && v.is_ok()).map(|(_, v)| v.clone()) {
        return v.map_err(Error);
    }
    if let Some(v) = entries.get(&(p.clone(), depth)) {
        return v.clone().map_err(Error);
    }
    let outcome = run(ctx, depth).map_err(|e| format!("native rebuild qualification failed: {}", e.0));
    entries.insert((p, depth), outcome.clone());
    outcome.map_err(Error)
}
struct Clear(String);
impl Drop for Clear {
    fn drop(&mut self) {
        let _ = Context::clear_keys_for_tag(&self.0);
    }
}
fn run(ctx: &Context, depth: u32) -> Result<RebuildReport> {
    let start = Instant::now();
    let (pk, sk) = keygen_first(ctx)?;
    let tag = pk.tag()?;
    let _clear = Clear(tag.clone());
    ctx.install_eval_mult_key(&EvalMultKey::single(ctx, &sk)?, &tag)?;
    ctx.install_rotation_keys(&RotationKeys::first(ctx, &sk, &[1])?, &tag)?;
    let n = ctx.ring_dim() as usize;
    let p = ctx.plain_mod();
    let a: Vec<u64> = (0..n)
        .map(|i| match i % 5 {
            0 => 0,
            1 => 1,
            2 => p - 1,
            _ => i as u64 % p,
        })
        .collect();
    let b: Vec<u64> = (0..n).map(|i| (3 * i as u64 + 5) % p).collect();
    let ca = ctx.encrypt(&pk, &ctx.plaintext(&a)?)?;
    let cb = ctx.encrypt(&pk, &ctx.plaintext(&b)?)?;
    let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;
    let mut checked = 0;
    let mut check = |ct: &Ciphertext, want: &[u64]| -> Result<Ciphertext> {
        let meta = ct.meta()?;
        let residues = ct.export_residues()?;
        let back = ctx.build_ciphertext_unverified(&ca, &meta, &residues)?;
        if back.meta()? != meta
            || back.export_residues()? != residues
            || sk.decrypt_single(ct, n)? != want
            || sk.decrypt_single(&back, n)? != want
            || sk.decrypt_single(&ctx.sub(ct, &back)?, n)?.iter().any(|&v| v != 0)
            || (meta.level == 0 && back.serialize()? != ct.serialize()?)
        {
            return Err(Error(format!("native roundtrip/evaluation mismatch at level {}", meta.level)));
        }
        checked += 1;
        Ok(back)
    };
    let rebuilt = check(&ca, &a)?;
    check(&cb, &b)?;
    check(&ctx.add(&ca, &cb)?, &a.iter().zip(&b).map(|(&a, &b)| (a + b) % p).collect::<Vec<_>>())?;
    let products: Vec<u64> = a.iter().zip(&b).map(|(&a, &b)| mul(a, b)).collect();
    check(&ctx.mult(&rebuilt, &cb)?, &products)?;
    check(&ctx.mult_plain(&ca, &ctx.plaintext(&b)?)?, &products)?;
    let mut x = ca.try_clone()?;
    let mut values = a;
    for level in 1..=depth {
        x = ctx.square(&x)?;
        values = values.iter().map(|&v| mul(v, v)).collect();
        x = check(&x, &values)?;
        if x.meta()?.level != level {
            return Err(Error("native level accounting mismatch".into()));
        }
        let half = n / 2;
        let rotated: Vec<u64> = (0..n).map(|i| values[(i / half) * half + (i % half + 1) % half]).collect();
        check(&ctx.rotate(&x, 1)?, &rotated)?;
    }
    Ok(RebuildReport {
        openfhe_version: OPENFHE_VERSION.into(),
        libraries: loaded_openfhe_libraries()?,
        objects_checked: checked,
        deepest_level: depth,
        elapsed: start.elapsed(),
    })
}
