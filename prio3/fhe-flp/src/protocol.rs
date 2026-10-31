//! Client, aggregators and collector.
//!
//! Report (client -> every aggregator):
//!   `nonce (16 bytes) || fresh coefficient-encoded BGV ciphertext of
//!   z = input || proof_1 || .. || proof_k`, residues packed canonically.
//!
//! Preparation (each aggregator, same report):
//!   1. derive the query randomness of every proof from the aggregators'
//!      secret `verify_key`, the nonce and SHA-256 of the report, as Prio3
//!      derives it from `verify_key` and the nonce, resampling any gadget
//!      point that is a root of unity of the wire-polynomial order (where
//!      `prio::flp::Flp::query` would refuse) instead of rejecting the
//!      report;
//!   2. compute the affine map `z -> verifier` of every proof at that
//!      randomness: the type's closed form (checked against prio's unchanged
//!      `Flp::query` when the task is created), or read off `Flp::query`
//!      (num_shares = 1) column by column;
//!   3. per group of verifier rows, one plaintext x ciphertext product whose
//!      coefficient `j * |z|` is row `j`'s inner product with `z`;
//!   4. a flooded partial decryption restricted to those coefficients: the
//!      verifier share.
//!
//! Every aggregator fuses all shares (the verifier message, which is what
//! Prio3's aggregators exchange and learn), adds the constants and runs
//! `Flp::decide` on each proof's verifier. Accepted reports are added to a
//! running sum. The aggregate share is a flooded partial decryption of the
//! sum restricted to the output coefficients `0 .. output_len`.
use crate::bitvec::{BitVec, mul_bits_map};
use crate::codec::ResidueCodec;
use crate::{Error, Field, PLAIN_MOD, Result};
use openfhe_tbgv_rs::{Ciphertext, Context, PartialDecryption, PublicKey, SecretShare, keygen_first, keygen_next, verify_linear_rebuild_once};
use prio::field::{FieldElement, FieldElementWithInteger};
use prio::flp::types::Count;
use prio::flp::{Flp, Type};
use prio::vdaf::xof::{IntoFieldVec, Xof, XofTurboShake128};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ops::Range;

const DST_PROVE: &[u8] = b"fhe-flp/1 prove randomness";
const DST_QUERY: &[u8] = b"fhe-flp/1 query randomness";
pub const NONCE_LEN: usize = 16;
pub const MAX_PROOFS: usize = 16;
/// Largest number of reports added into one aggregate. Counts are exact
/// below `p` (no wrap-around for `MAX_BATCH < p`), and the sum's noise grows
/// linearly in the batch size, far inside the flooding margin.
pub const MAX_BATCH: u64 = 1 << 24;
/// Allowance for honest noise in the flooding-range check, as in
/// `fhe_prio3::vdec::FLOODING_SLACK_BITS`. Honest noise after the densest
/// possible query product is more than 64 bits below the flooding range
/// (75.4 measured; `openfhe-tbgv-rs/tests/linear_coeffs.rs`).
pub const FLOODING_SLACK_BITS: u32 = 20;
/// BV digit size handed to OpenFHE's parameter estimate. No key switching
/// ever happens; the value only sizes the last tower of the chain, which a
/// plaintext product drops. 30 (OpenFHE's maximum for BV) makes it 36 bits:
/// Q = 203 bits (ring 8192 still allows 218) and a worst-case flooding
/// margin of 75 bits instead of 52 with digit size 1, for 4% larger reports.
pub const DIGIT_SIZE: u32 = 30;

pub(crate) fn to_u64(x: Field) -> u64 {
    u64::from(u32::from(x))
}
pub(crate) fn from_u64(v: u64) -> Field {
    Field::from(u32::try_from(v).expect("value below p < 2^32"))
}

/// The FLP types this protocol runs. A type may give its verifier map in
/// closed form (checked against `Flp::query` at random points by
/// `Task::new`); otherwise `Task::linear_map` reads it off `Flp::query`
/// column by column, which costs `|input| + |proof| + 1` queries per proof.
pub trait VerifierMap: Type<Field = Field> + Sync {
    /// Rows over `input || proof` and constants, for one proof's query
    /// randomness.
    fn closed_form(&self, _query_rand: &[Field]) -> Option<(Vec<Vec<Field>>, Vec<Field>)> {
        None
    }
}

impl VerifierMap for Count<Field> {
    fn closed_form(&self, query_rand: &[Field]) -> Option<(Vec<Vec<Field>>, Vec<Field>)> {
        Some(mul_bits_map(1, false, query_rand))
    }
}

impl VerifierMap for BitVec<Field> {
    fn closed_form(&self, query_rand: &[Field]) -> Option<(Vec<Vec<Field>>, Vec<Field>)> {
        Some(mul_bits_map(self.calls(), self.calls() > 1, query_rand))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskParams {
    pub task_id: [u8; 32],
    pub num_aggregators: usize,
    pub num_proofs: usize,
}

/// Where everything lives in the plaintext polynomial and the verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    pub input_len: usize,
    pub proof_len: usize,
    pub num_proofs: usize,
    pub verifier_len: usize,
    /// `|z| = input_len + num_proofs * proof_len` coefficients.
    pub z_len: usize,
    pub ring: usize,
    /// Verifier rows evaluated by one plaintext product: `floor(ring / |z|)`.
    pub rows_per_group: usize,
}

impl Layout {
    fn new<T: Flp>(typ: &T, num_proofs: usize, ring: usize) -> Result<Self> {
        let z_len = typ.input_len() + num_proofs * typ.proof_len();
        if z_len > ring {
            return Err(Error::Protocol(format!("input and proofs need {z_len} coefficients; the ring has {ring}")));
        }
        Ok(Self {
            input_len: typ.input_len(),
            proof_len: typ.proof_len(),
            num_proofs,
            verifier_len: typ.verifier_len(),
            z_len,
            ring,
            rows_per_group: ring / z_len,
        })
    }
    pub fn num_rows(&self) -> usize {
        self.num_proofs * self.verifier_len
    }
    pub fn groups(&self) -> Vec<Range<usize>> {
        let rows = self.num_rows();
        (0..rows).step_by(self.rows_per_group).map(|s| s..(s + self.rows_per_group).min(rows)).collect()
    }
    /// Coefficients holding the inner products of a group of `rows` rows.
    pub fn group_coeffs(&self, rows: usize) -> Vec<u32> {
        (0..rows).map(|j| (j * self.z_len) as u32).collect()
    }
    pub fn output_coeffs(&self) -> Vec<u32> {
        (0..self.input_len as u32).collect()
    }
}

/// The FLP side of a task, shared by the threshold [`Task`] and the
/// one-aggregator [`crate::single::SingleTask`]: the type, the proofs, where
/// everything sits in the plaintext polynomial, and the verifier.
pub struct FlpPlan<T: VerifierMap> {
    typ: T,
    task_id: [u8; 32],
    num_proofs: usize,
    layout: Layout,
}

impl<T: VerifierMap> FlpPlan<T> {
    /// Refused: zero or more than `MAX_PROOFS` proofs; types that need joint
    /// randomness (input and proof share one ciphertext, so there is no
    /// input commitment to derive it from; see `bitvec` for a circuit without
    /// it); types whose aggregate is not the input itself (`truncate` must be
    /// the identity); a closed-form verifier map that disagrees with
    /// `Flp::query`; input and proofs that do not fit `ring` coefficients.
    pub(crate) fn new(typ: T, task_id: [u8; 32], num_proofs: usize, ring: usize) -> Result<Self> {
        if !(1..=MAX_PROOFS).contains(&num_proofs) {
            return Err(Error::Protocol(format!("between 1 and {MAX_PROOFS} proofs are supported")));
        }
        if typ.joint_rand_len() != 0 {
            return Err(Error::Protocol("types that use joint randomness are not supported".into()));
        }
        if typ.output_len() != typ.input_len() {
            return Err(Error::Protocol("the aggregate must be the encoded input (output_len == input_len)".into()));
        }
        let probe: Vec<Field> = (0..typ.input_len() as u32)
            .map(|i| Field::from(i.wrapping_mul(2_654_435_761) % 1_000_003))
            .collect();
        if typ.truncate(probe.clone())? != probe {
            return Err(Error::Protocol("truncate must be the identity".into()));
        }
        if u64::from(Field::modulus()) != PLAIN_MOD {
            return Err(Error::Protocol("field and plaintext modulus differ".into()));
        }
        let layout = Layout::new(&typ, num_proofs, ring)?;
        check_closed_form(&typ)?;
        Ok(Self {
            typ,
            task_id,
            num_proofs,
            layout,
        })
    }

    pub fn typ(&self) -> &T {
        &self.typ
    }
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// `z = input || proof_1 || .. || proof_k`, each proof from prio's
    /// unchanged `Flp::prove` with fresh randomness.
    pub(crate) fn prove(&self, input: &[Field]) -> Result<Vec<Field>> {
        let typ = &self.typ;
        let k = self.num_proofs;
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let prove_rands: Vec<Field> = XofTurboShake128::seed_stream(&seed, &[DST_PROVE, &self.task_id], &[&[k as u8]]).into_field_vec(typ.prove_rand_len() * k);
        let mut z = input.to_vec();
        for p in 0..k {
            let pr = &prove_rands[p * typ.prove_rand_len()..(p + 1) * typ.prove_rand_len()];
            z.extend(typ.prove(input, pr, &[])?);
        }
        Ok(z)
    }

    /// Prio3's `decide` on every proof's verifier.
    pub(crate) fn decide(&self, verifier: &[Field]) -> Result<bool> {
        let v = self.layout.verifier_len;
        if verifier.len() != self.layout.num_rows() {
            return Err(Error::Protocol("verifier has the wrong length".into()));
        }
        let mut ok = true;
        for p in 0..self.num_proofs {
            ok &= self.typ.decide(&verifier[p * v..(p + 1) * v])?;
        }
        Ok(ok)
    }

    /// Query randomness for every proof of one report (see the module docs).
    pub fn query_rands(&self, verify_key: &[u8; 32], report: &[u8]) -> Result<Vec<Vec<Field>>> {
        if report.len() < NONCE_LEN {
            return Err(Error::Codec("report shorter than its nonce".into()));
        }
        let digest = Sha256::digest(report);
        let k = self.num_proofs;
        let qlen = self.typ.query_rand_len();
        let compress = if self.typ.eval_output_len() > 1 { self.typ.eval_output_len() } else { 0 };
        let wire_orders: Vec<u32> = self.typ.gadget().iter().map(|g| (1 + g.calls()).next_power_of_two() as u32).collect();
        // Each gadget point is rejected with probability below 2^-11 for
        // calls < 2^20, so 64 spare elements per proof make running out
        // impossible in practice; it is still an error, not a panic.
        let pool: Vec<Field> = XofTurboShake128::seed_stream(verify_key, &[DST_QUERY, &self.task_id], &[&[k as u8], &report[..NONCE_LEN], &digest])
            .into_field_vec(k * (qlen + 64));
        let mut it = pool.into_iter();
        let mut out = Vec::with_capacity(k);
        for _ in 0..k {
            let mut qr = Vec::with_capacity(qlen);
            for i in 0..qlen {
                loop {
                    let r = it.next().ok_or_else(|| Error::Protocol("query randomness exhausted".into()))?;
                    if i >= compress && r.pow(wire_orders[i - compress]) == Field::one() {
                        continue;
                    }
                    qr.push(r);
                    break;
                }
            }
            out.push(qr);
        }
        Ok(out)
    }

    /// The verifier of every proof as an affine map of `z`: `rows[p * V + r]`
    /// (length `|z|`) and `constants[p * V + r]`: the type's closed form, or
    /// read off `Flp::query` column by column. `query` is affine in
    /// `(input, proof)` for fixed randomness and `num_shares`
    /// (`tests/protocol.rs` checks both paths on random points).
    pub fn linear_map(&self, query_rands: &[Vec<Field>]) -> Result<(Vec<Vec<Field>>, Vec<Field>)> {
        let l = &self.layout;
        let (il, pl, v) = (l.input_len, l.proof_len, l.verifier_len);
        if query_rands.len() != l.num_proofs {
            return Err(Error::Protocol("one query randomness per proof".into()));
        }
        let mut rows = vec![vec![Field::zero(); l.z_len]; l.num_rows()];
        let mut constants = vec![Field::zero(); l.num_rows()];
        for (p, qr) in query_rands.iter().enumerate() {
            let Some((local, c)) = self.typ.closed_form(qr) else {
                return self.linear_map_by_query(query_rands);
            };
            for r in 0..v {
                rows[p * v + r][..il].copy_from_slice(&local[r][..il]);
                rows[p * v + r][il + p * pl..il + (p + 1) * pl].copy_from_slice(&local[r][il..]);
            }
            constants[p * v..(p + 1) * v].copy_from_slice(&c);
        }
        Ok((rows, constants))
    }

    /// [`Self::linear_map`] read off `Flp::query` column by column, for
    /// types without a closed form (and to test closed forms).
    pub fn linear_map_by_query(&self, query_rands: &[Vec<Field>]) -> Result<(Vec<Vec<Field>>, Vec<Field>)> {
        let l = &self.layout;
        let (il, pl, v) = (l.input_len, l.proof_len, l.verifier_len);
        let zero = Field::zero();
        let mut rows = vec![vec![zero; l.z_len]; l.num_rows()];
        let mut constants = vec![zero; l.num_rows()];
        let zin = vec![zero; il];
        let zpf = vec![zero; pl];
        for (p, qr) in query_rands.iter().enumerate() {
            let c = self.typ.query(&zin, &zpf, qr, &[], 1)?;
            for j in 0..il {
                let mut x = zin.clone();
                x[j] = Field::one();
                let col = self.typ.query(&x, &zpf, qr, &[], 1)?;
                for r in 0..v {
                    rows[p * v + r][j] = col[r] - c[r];
                }
            }
            for j in 0..pl {
                let mut y = zpf.clone();
                y[j] = Field::one();
                let col = self.typ.query(&zin, &y, qr, &[], 1)?;
                for r in 0..v {
                    rows[p * v + r][il + p * pl + j] = col[r] - c[r];
                }
            }
            constants[p * v..(p + 1) * v].copy_from_slice(&c);
        }
        Ok((rows, constants))
    }

    /// Plaintext polynomial whose product with `z(X)` holds `<rows[j], z>` at
    /// coefficient `j * |z|`: row `j` reversed and shifted, with `X^-i =
    /// -X^(N-i)`. Rows of one group never alias (`rows.len() * |z| <= N`).
    pub fn query_poly(&self, rows: &[Vec<Field>]) -> Vec<u64> {
        let (n, zl) = (self.layout.ring as i64, self.layout.z_len as i64);
        let mut q = vec![0u64; n as usize];
        for (j, row) in rows.iter().enumerate() {
            for (i, &c) in row.iter().enumerate() {
                let c = to_u64(c);
                if c == 0 {
                    continue;
                }
                let pos = j as i64 * zl - i as i64;
                if pos >= 0 {
                    q[pos as usize] = (q[pos as usize] + c) % PLAIN_MOD;
                } else {
                    let w = (n + pos) as usize;
                    q[w] = (q[w] + PLAIN_MOD - c) % PLAIN_MOD;
                }
            }
        }
        q
    }
}

/// Everything all parties agree on for one aggregation task.
pub struct Task<T: VerifierMap> {
    plan: FlpPlan<T>,
    params: TaskParams,
    ctx: Context,
    /// Residues of fresh ciphertexts and of the sum (all towers).
    codec: ResidueCodec,
    /// Residues of verifier shares: partials of a plaintext product, which
    /// sits lower in the chain.
    share_codec: ResidueCodec,
}

impl<T: VerifierMap> Task<T> {
    /// Creates the task: the FLP type, its parameters, and the depth-0 BGV
    /// context (`p = 4293918721`, 128-bit HE-standard security; OpenFHE
    /// chooses ring 8192 for it).
    ///
    /// Refused: fewer than two or more than 255 aggregators, and everything
    /// [`FlpPlan::new`] refuses.
    pub fn new(typ: T, params: TaskParams) -> Result<Self> {
        if !(2..=255).contains(&params.num_aggregators) {
            return Err(Error::Protocol("between 2 and 255 aggregators are supported".into()));
        }
        let ctx = Context::new_linear(PLAIN_MOD, 128, params.num_aggregators as u32, DIGIT_SIZE)?;
        if ctx.plain_mod() != PLAIN_MOD {
            return Err(Error::Protocol("context has another plaintext modulus".into()));
        }
        let plan = FlpPlan::new(typ, params.task_id, params.num_proofs, ctx.ring_dim() as usize)?;
        let moduli = ctx.moduli()?;
        // The tower counts of the two kinds of partials, read off real objects
        // under a throwaway key rather than assumed.
        let (pk, sk) = keygen_first(&ctx)?;
        let fresh = ctx.encrypt(&pk, &ctx.coef_plaintext(&[0])?)?;
        let prod = ctx.mult_plain(&fresh, &ctx.coef_plaintext(&[1])?)?;
        let towers = |c: &Ciphertext| -> Result<usize> { Ok(sk.partial_decrypt_coeffs(c, true, &[0])?.ciphertext().meta()?.num_towers as usize) };
        let (sum_towers, share_towers) = (towers(&fresh)?, towers(&prod)?);
        if sum_towers != moduli.len() || share_towers == 0 || share_towers > sum_towers {
            return Err(Error::Fhe(format!(
                "unexpected partial tower counts {sum_towers}, {share_towers} of {}",
                moduli.len()
            )));
        }
        let codec = ResidueCodec::new(&moduli)?;
        let share_codec = ResidueCodec::new(&moduli[..share_towers])?;
        Ok(Self {
            plan,
            params,
            ctx,
            codec,
            share_codec,
        })
    }

    pub fn typ(&self) -> &T {
        self.plan.typ()
    }
    pub fn params(&self) -> &TaskParams {
        &self.params
    }
    pub fn context(&self) -> &Context {
        &self.ctx
    }
    pub fn layout(&self) -> &Layout {
        self.plan.layout()
    }
    pub fn report_len(&self) -> usize {
        NONCE_LEN + self.codec.len(2, self.layout().ring)
    }
    pub fn verifier_share_len(&self) -> usize {
        1 + self.layout().groups().iter().map(|g| self.share_codec.len(1, g.len())).sum::<usize>()
    }
    pub fn aggregate_share_len(&self) -> usize {
        1 + 8 + self.codec.len(1, self.layout().input_len)
    }

    /// Query randomness for every proof of one report.
    pub fn query_rands(&self, verify_key: &[u8; 32], report: &[u8]) -> Result<Vec<Vec<Field>>> {
        self.plan.query_rands(verify_key, report)
    }
    /// See [`FlpPlan::linear_map`].
    pub fn linear_map(&self, query_rands: &[Vec<Field>]) -> Result<(Vec<Vec<Field>>, Vec<Field>)> {
        self.plan.linear_map(query_rands)
    }
    /// See [`FlpPlan::linear_map_by_query`].
    pub fn linear_map_by_query(&self, query_rands: &[Vec<Field>]) -> Result<(Vec<Vec<Field>>, Vec<Field>)> {
        self.plan.linear_map_by_query(query_rands)
    }
    /// See [`FlpPlan::query_poly`].
    pub fn query_poly(&self, rows: &[Vec<Field>]) -> Vec<u64> {
        self.plan.query_poly(rows)
    }
}

/// A closed-form verifier map must agree with `Flp::query`: checked at
/// fresh random query randomness and random `(input, proof)` (an affine map
/// that differs anywhere differs at a random point with probability at
/// least `1 - 1/p`), three times.
fn check_closed_form<T: VerifierMap>(typ: &T) -> Result<()> {
    let (il, pl) = (typ.input_len(), typ.proof_len());
    for _ in 0..3 {
        let qr: Vec<Field> = Field::random_vector(typ.query_rand_len());
        let Some((rows, c)) = typ.closed_form(&qr) else { return Ok(()) };
        let z: Vec<Field> = Field::random_vector(il + pl);
        let want = match typ.query(&z[..il], &z[il..], &qr, &[], 1) {
            Ok(v) => v,
            Err(_) => continue, // a root of unity drawn: try other randomness
        };
        if rows.len() != want.len() || c.len() != want.len() || rows.iter().any(|r| r.len() != il + pl) {
            return Err(Error::Protocol("closed-form verifier map has the wrong shape".into()));
        }
        for (r, row) in rows.iter().enumerate() {
            if row.iter().zip(&z).fold(c[r], |a, (&x, &y)| a + x * y) != want[r] {
                return Err(Error::Protocol("closed-form verifier map disagrees with Flp::query".into()));
            }
        }
    }
    Ok(())
}

/// n-of-n key generation run in one process, for simulations and tests. In
/// a deployment party 0 runs `keygen_first` and each next party runs
/// `keygen_next` on the public key it receives, each on its own machine;
/// every party keeps its share.
pub fn key_ceremony<T: VerifierMap>(task: &Task<T>) -> Result<(PublicKey, Vec<SecretShare>)> {
    let (mut pk, s0) = keygen_first(&task.ctx)?;
    let mut shares = vec![s0];
    for _ in 1..task.params.num_aggregators {
        let (p, s) = keygen_next(&task.ctx, &pk)?;
        pk = p;
        shares.push(s);
    }
    Ok((pk, shares))
}

pub struct Client<'a, T: VerifierMap> {
    task: &'a Task<T>,
    pk: &'a PublicKey,
}

impl<'a, T: VerifierMap> Client<'a, T> {
    pub fn new(task: &'a Task<T>, pk: &'a PublicKey) -> Self {
        Self { task, pk }
    }

    pub fn shard(&self, measurement: &T::Measurement) -> Result<Vec<u8>> {
        let input = self.task.typ().encode_measurement(measurement)?;
        Ok(self.shard_with_witness(&input)?.0)
    }

    /// Proves and encrypts an already-encoded input, valid or not, and also
    /// returns `z = input || proofs` (the client's own secret). Honest
    /// clients call [`Self::shard`]; tests use this to act as a malicious
    /// client and to compare with prio's plaintext FLP.
    pub fn shard_with_witness(&self, input: &[Field]) -> Result<(Vec<u8>, Vec<Field>)> {
        let z = self.task.plan.prove(input)?;
        Ok((self.report_from_coefficients(&z)?, z))
    }

    /// Encrypts arbitrary coefficients as a report (malicious-client tests).
    pub fn report_from_coefficients(&self, z: &[Field]) -> Result<Vec<u8>> {
        let ctx = &self.task.ctx;
        if z.len() > self.task.layout().ring {
            return Err(Error::Protocol("too many coefficients".into()));
        }
        let vals: Vec<u64> = z.iter().map(|&x| to_u64(x)).collect();
        let ct = ctx.encrypt(self.pk, &ctx.coef_plaintext(&vals)?)?;
        let meta = ct.meta()?;
        if meta.level != 0 || meta.num_elements != 2 || meta.num_towers as usize != self.task.codec.num_towers() {
            return Err(Error::Fhe(format!("unexpected fresh ciphertext metadata {meta:?}")));
        }
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let mut out = nonce.to_vec();
        out.extend(self.task.codec.pack(&ct.export_residues()?, 2, self.task.layout().ring)?);
        Ok(out)
    }
}

/// An aggregator's state between its verifier share and the verdict.
pub struct PrepState {
    ct: Ciphertext,
    partials: Vec<PartialDecryption>,
    constants: Vec<Field>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub accepted: bool,
    /// The verifier message (all proofs), as Prio3's aggregators learn it;
    /// empty if the report was refused before fusion.
    pub verifier: Vec<Field>,
    pub reason: Option<String>,
}

pub struct Aggregator<'a, T: VerifierMap> {
    task: &'a Task<T>,
    agg_id: usize,
    share: SecretShare,
    verify_key: [u8; 32],
    reference: Ciphertext,
    seen: HashSet<[u8; NONCE_LEN]>,
    sum: Option<Ciphertext>,
    accepted: u64,
}

impl<'a, T: VerifierMap> Aggregator<'a, T> {
    /// `verify_key` is secret to the aggregators (generated jointly, as
    /// Prio3's); the self-test of ciphertext rebuilding runs here.
    pub fn new(task: &'a Task<T>, agg_id: usize, share: SecretShare, joint_pk: &PublicKey, verify_key: [u8; 32]) -> Result<Self> {
        if agg_id >= task.params.num_aggregators {
            return Err(Error::Protocol("aggregator id out of range".into()));
        }
        verify_linear_rebuild_once(&task.ctx)?;
        let reference = task.ctx.encrypt(joint_pk, &task.ctx.coef_plaintext(&[0])?)?;
        Ok(Self {
            task,
            agg_id,
            share,
            verify_key,
            reference,
            seen: HashSet::new(),
            sum: None,
            accepted: 0,
        })
    }

    pub fn accepted(&self) -> u64 {
        self.accepted
    }

    fn parse(&self, report: &[u8]) -> Result<([u8; NONCE_LEN], Ciphertext)> {
        if report.len() != self.task.report_len() {
            return Err(Error::Codec(format!("report has {} bytes, expected {}", report.len(), self.task.report_len())));
        }
        let nonce: [u8; NONCE_LEN] = report[..NONCE_LEN].try_into().expect("length checked");
        let residues = self.task.codec.unpack(&report[NONCE_LEN..], 2, self.task.layout().ring)?;
        let ct = self.task.ctx.build_ciphertext(&self.reference, &self.reference.meta()?, &residues)?;
        Ok((nonce, ct))
    }

    /// Verifier share for one report. Refuses malformed bytes and a nonce
    /// already seen by this aggregator.
    pub fn prepare_init(&mut self, report: &[u8]) -> Result<(PrepState, Vec<u8>)> {
        let (nonce, ct) = self.parse(report)?;
        if !self.seen.insert(nonce) {
            return Err(Error::Protocol("duplicate report nonce".into()));
        }
        let task = self.task;
        let qrs = task.query_rands(&self.verify_key, report)?;
        let (rows, constants) = task.linear_map(&qrs)?;
        let mut partials = Vec::new();
        let mut msg = vec![self.agg_id as u8];
        for g in task.layout().groups() {
            let q = task.ctx.coef_plaintext(&task.query_poly(&rows[g.clone()]))?;
            let prod = task.ctx.mult_plain(&ct, &q)?;
            let idx = task.layout().group_coeffs(g.len());
            let pd = self.share.partial_decrypt_coeffs(&prod, self.agg_id == 0, &idx)?;
            msg.extend(task.share_codec.pack(&pd.export_coeffs(&idx)?, 1, idx.len())?);
            partials.push(pd);
        }
        Ok((PrepState { ct, partials, constants }, msg))
    }

    /// Combines all aggregators' verifier shares (this one's included, in
    /// any order), decides, and adds an accepted report to the sum.
    pub fn prepare_finish(&mut self, state: PrepState, shares: &[Vec<u8>]) -> Result<Verdict> {
        let task = self.task;
        let n = task.params.num_aggregators;
        if shares.len() != n {
            return Err(Error::Protocol(format!("expected {n} verifier shares, got {}", shares.len())));
        }
        let mut by_id: Vec<Option<&[u8]>> = vec![None; n];
        for s in shares {
            if s.len() != task.verifier_share_len() {
                return Err(Error::Codec("verifier share has the wrong length".into()));
            }
            let id = s[0] as usize;
            if id >= n || by_id[id].replace(&s[1..]).is_some() {
                return Err(Error::Protocol("verifier shares must come from distinct aggregators".into()));
            }
        }
        let mut fused = Vec::with_capacity(task.layout().num_rows());
        let mut off = 0;
        for (gi, g) in task.layout().groups().iter().enumerate() {
            let idx = task.layout().group_coeffs(g.len());
            let len = task.share_codec.len(1, g.len());
            let own = &state.partials[gi];
            let mut parts = Vec::with_capacity(n);
            for (id, body) in by_id.iter().enumerate() {
                if id == self.agg_id {
                    continue;
                }
                let vals = task.share_codec.unpack(&body.expect("all present")[off..off + len], 1, g.len())?;
                parts.push(PartialDecryption::from_coeffs(&task.ctx, own, &idx, &vals, id == 0)?);
            }
            off += len;
            let mut refs: Vec<&PartialDecryption> = parts.iter().collect();
            refs.push(own);
            let (within, ratio) = task.ctx.fuse_flooding_check(&refs, FLOODING_SLACK_BITS)?;
            if !within {
                return Ok(Verdict {
                    accepted: false,
                    verifier: Vec::new(),
                    reason: Some(format!("fused value outside the flooding range (ratio {ratio:.3})")),
                });
            }
            fused.extend(task.ctx.fuse_coeffs(&refs, &idx)?.into_iter().map(from_u64));
        }
        let verifier: Vec<Field> = fused.iter().zip(&state.constants).map(|(&a, &c)| a + c).collect();
        let accepted = task.plan.decide(&verifier)?;
        if accepted {
            if self.accepted >= MAX_BATCH {
                return Err(Error::Protocol("batch is full".into()));
            }
            self.sum = Some(match self.sum.take() {
                None => state.ct,
                Some(s) => task.ctx.add(&s, &state.ct)?,
            });
            self.accepted += 1;
        }
        Ok(Verdict {
            accepted,
            verifier,
            reason: (!accepted).then(|| "FLP rejected".into()),
        })
    }

    /// This aggregator's share of the aggregate: a flooded partial
    /// decryption of the sum, restricted to the output coefficients.
    pub fn aggregate_share(&self) -> Result<Vec<u8>> {
        let sum = self.sum.as_ref().ok_or_else(|| Error::Protocol("no accepted reports".into()))?;
        let idx = self.task.layout().output_coeffs();
        let pd = self.share.partial_decrypt_coeffs(sum, self.agg_id == 0, &idx)?;
        let mut msg = vec![self.agg_id as u8];
        msg.extend(self.accepted.to_le_bytes());
        msg.extend(self.task.codec.pack(&pd.export_coeffs(&idx)?, 1, idx.len())?);
        Ok(msg)
    }
}

pub struct Collector<'a, T: VerifierMap> {
    task: &'a Task<T>,
    template: PartialDecryption,
}

impl<'a, T: VerifierMap> Collector<'a, T> {
    /// The collector holds no key share. Rebuilding the aggregators'
    /// restricted partials needs only their shape (context, level, towers,
    /// encoding), which a partial made under a throwaway key provides.
    pub fn new(task: &'a Task<T>) -> Result<Self> {
        let (pk, sk) = keygen_first(&task.ctx)?;
        let ct = task.ctx.encrypt(&pk, &task.ctx.coef_plaintext(&[0])?)?;
        let template = sk.partial_decrypt_coeffs(&ct, true, &task.layout().output_coeffs())?;
        Ok(Self { task, template })
    }

    pub fn unshard(&self, shares: &[Vec<u8>]) -> Result<T::AggregateResult> {
        let task = self.task;
        let n = task.params.num_aggregators;
        if shares.len() != n {
            return Err(Error::Protocol(format!("expected {n} aggregate shares, got {}", shares.len())));
        }
        let idx = task.layout().output_coeffs();
        let mut seen = vec![false; n];
        let mut count = None;
        let mut parts = Vec::with_capacity(n);
        for s in shares {
            if s.len() != task.aggregate_share_len() {
                return Err(Error::Codec("aggregate share has the wrong length".into()));
            }
            let id = s[0] as usize;
            if id >= n || std::mem::replace(&mut seen[id], true) {
                return Err(Error::Protocol("aggregate shares must come from distinct aggregators".into()));
            }
            let c = u64::from_le_bytes(s[1..9].try_into().expect("length checked"));
            if *count.get_or_insert(c) != c {
                return Err(Error::Protocol("aggregators disagree on the number of accepted reports".into()));
            }
            let vals = task.codec.unpack(&s[9..], 1, idx.len())?;
            parts.push(PartialDecryption::from_coeffs(&task.ctx, &self.template, &idx, &vals, id == 0)?);
        }
        let refs: Vec<&PartialDecryption> = parts.iter().collect();
        let (within, ratio) = task.ctx.fuse_flooding_check(&refs, FLOODING_SLACK_BITS)?;
        if !within {
            return Err(Error::Protocol(format!("aggregate outside the flooding range (ratio {ratio:.3})")));
        }
        let data: Vec<Field> = task.ctx.fuse_coeffs(&refs, &idx)?.into_iter().map(from_u64).collect();
        Ok(task.typ().decode_result(&data, count.unwrap_or(0) as usize)?)
    }
}
