//! SIMD slot layouts of the verification circuit.
//!
//! * `Blocked` (verdict mode): repetition `j` occupies the contiguous block
//!   `[j*block, (j+1)*block)`; its result lands in slot `j*block`; the other
//!   slots of the block hold partial sums and are masked before decryption.
//! * `Interleaved` (silent mode): repetition `j` occupies residue class `j`
//!   modulo `classes` (a power of two), i.e. slots `j + classes*i`. Summing
//!   a class with rotations by `classes*2^t` wraps around the whole row, so
//!   every slot of class `j` ends up holding `E_j`: there are no junk slots,
//!   and a product over the classes (rotations by `2^t`) is replicated in
//!   every slot. That is what lets silent mode multiply the report by the
//!   validity bit without any masking or decryption.
//!
//! In both layouts an encoded measurement is split into chunks of at most
//! `block` elements, one ciphertext per chunk. A client packs element `i` of
//! a chunk at slot `client_slot(i)`.

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutKind {
    Blocked,
    Interleaved,
    /// Silent mode with `groups` reports sharing one verification ciphertext.
    /// Report `r` (its *group*), repetition `j`, element `i` lives at slot
    /// `j + classes*r + classes*groups*i`. Class sums wrap the whole row as
    /// in `Interleaved`, so every slot of class `(r, j)` holds `E_{r,j}`.
    Batched,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub kind: LayoutKind,
    pub input_len: usize,
    pub repetitions: usize,
    /// Interleaved/Batched: number of residue classes per report, `repetitions.next_power_of_two()`.
    pub classes: usize,
    /// Batched only: reports per verification ciphertext (a power of two). 1 otherwise.
    pub groups: usize,
    pub row: usize,
    /// Largest number of elements per chunk (a power of two).
    pub block: usize,
    pub num_chunks: usize,
    /// Global input range of each chunk, in order and contiguous. Cut at
    /// `block` boundaries and at the task's visibility-class boundaries.
    pub chunks: Vec<std::ops::Range<usize>>,
    /// Second-moment accumulation enabled: the `(start, bits)` slot map of
    /// the values (see `MeasurementType::value_slots`).
    pub moments: Option<Vec<(usize, u32)>>,
    /// Digit width `D` of the second-moment decomposition
    /// (`TaskConfig::moment_digit_bits`); 0 when moments are off.
    pub moment_digit: u32,
    /// For each entry of `moments`: the element the piece belongs to and
    /// the multiplier its value carries there (`MeasurementType::moment_pieces`).
    /// Empty when moments are off.
    pub moment_pieces: Vec<(usize, u64)>,
}

/// One second-moment accumulator: value pair `a <= b` and digit shift `s`.
/// For `s >= 0` digit position `i` accumulates `d_a[i] * d_b[i + s]`; for
/// `s < 0` position `j` accumulates `d_a[j - s] * d_b[j]`, where `d_v[i]`
/// is digit `i` (bits `[i*D, (i+1)*D)`) of value `v`. For `a == b` only
/// `s >= 0` exists: the negative shifts are the same products.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MomentTerm {
    pub a: usize,
    pub b: usize,
    pub shift: isize,
}

impl Layout {
    pub fn new(kind: LayoutKind, input_len: usize, repetitions: usize, row: usize) -> Result<Self> {
        Self::with_groups(kind, input_len, repetitions, row, 1)
    }

    pub fn with_groups(kind: LayoutKind, input_len: usize, repetitions: usize, row: usize, groups: usize) -> Result<Self> {
        Self::with_cuts(kind, input_len, repetitions, row, groups, &[])
    }

    /// As [`Self::with_groups`], with chunk boundaries forced at `cuts`
    /// (ascending input indices in `(0, input_len)`), in addition to the
    /// `block`-size boundaries.
    pub fn with_cuts(kind: LayoutKind, input_len: usize, repetitions: usize, row: usize, groups: usize, cuts: &[usize]) -> Result<Self> {
        if input_len == 0 || repetitions == 0 || !row.is_power_of_two() {
            return Err(Error::Config(
                "layout: input_len and repetitions must be >= 1; row must be a power of two".into(),
            ));
        }
        if !groups.is_power_of_two() || (kind != LayoutKind::Batched && groups != 1) {
            return Err(Error::Config(
                "layout: groups must be a power of two and only Batched layouts have more than one".into(),
            ));
        }
        let classes = repetitions.next_power_of_two();
        let block = match kind {
            LayoutKind::Blocked => {
                let mut max_block = row;
                while max_block * repetitions > row {
                    max_block /= 2;
                }
                if max_block == 0 {
                    return Err(Error::Config(format!("layout: {repetitions} repetitions do not fit in a row of {row} slots")));
                }
                input_len.next_power_of_two().min(max_block)
            }
            LayoutKind::Interleaved => {
                if classes > row {
                    return Err(Error::Config(format!("layout: {classes} classes do not fit in a row of {row} slots")));
                }
                row / classes
            }
            LayoutKind::Batched => {
                if classes * groups > row {
                    return Err(Error::Config(format!(
                        "layout: {groups} groups of {classes} classes do not fit in a row of {row} slots"
                    )));
                }
                row / (classes * groups)
            }
        };
        if cuts.windows(2).any(|w| w[0] >= w[1]) || cuts.iter().any(|&c| c == 0 || c >= input_len) {
            return Err(Error::Config("layout: cuts must be ascending and strictly inside the input".into()));
        }
        let mut chunks = Vec::new();
        let mut start = 0usize;
        for &end in cuts.iter().chain(std::iter::once(&input_len)) {
            let mut s = start;
            while s < end {
                let e = (s + block).min(end);
                chunks.push(s..e);
                s = e;
            }
            start = end;
        }
        let num_chunks = chunks.len();
        Ok(Self {
            kind,
            input_len,
            repetitions,
            classes,
            groups,
            row,
            block,
            num_chunks,
            chunks,
            moments: None,
            moment_digit: 0,
            moment_pieces: Vec::new(),
        })
    }

    /// Chunk holding global input index `i`.
    pub fn chunk_of(&self, i: usize) -> usize {
        self.chunks.iter().position(|r| r.contains(&i)).expect("index inside the input")
    }

    /// Digits of a `bits`-wide value.
    pub fn moment_digits(&self, bits: u32) -> usize {
        debug_assert!(self.moment_digit >= 1);
        bits.div_ceil(self.moment_digit) as usize
    }

    /// Bits of digit `i` of a `bits`-wide value (the last may be narrower).
    pub fn moment_digit_width(&self, bits: u32, i: usize) -> u32 {
        self.moment_digit.min(bits - i as u32 * self.moment_digit)
    }

    fn moment_max_digits(&self) -> usize {
        match &self.moments {
            Some(map) => map.iter().map(|&(_, b)| self.moment_digits(b)).max().unwrap_or(1),
            None => 1,
        }
    }

    /// Length (in elements) of the window that sums a value's weighted
    /// bits into its digits. With a single digit per value it is the
    /// smallest power of two not below the widest value (bits beyond a
    /// value's width are zero, so the window may exceed it); with several
    /// it is exactly `D`, so that no digit's sum reaches into the next.
    pub fn moment_window(&self) -> usize {
        match &self.moments {
            Some(map) => {
                let widest = map.iter().map(|&(_, b)| b as usize).max().unwrap_or(1);
                if self.moment_max_digits() == 1 {
                    widest.next_power_of_two()
                } else {
                    self.moment_digit as usize
                }
            }
            None => 1,
        }
    }

    /// Rotations used by the second-moment computation: powers of two
    /// `2^j <= window/2` (the window sum is composed from them), alignment
    /// of each value's start slot onto element 0, and a shift by one digit
    /// when some value has more than one.
    pub fn moment_rotations(&self) -> Vec<i32> {
        let Some(map) = &self.moments else { return Vec::new() };
        let stride = self.element_stride();
        let mut v = Vec::new();
        let mut d = 1usize;
        while 2 * d <= self.moment_window() {
            v.push((stride * d) as i32);
            d *= 2;
        }
        for &(start, _) in map {
            let local = start - self.chunk_range(self.chunk_of(start)).start;
            if local != 0 {
                v.push((local * stride) as i32);
            }
        }
        if self.moment_max_digits() > 1 {
            v.push((stride * self.moment_digit as usize) as i32);
        }
        let mut out = Vec::with_capacity(v.len());
        for r in v {
            if !out.contains(&r) {
                out.push(r);
            }
        }
        out
    }

    /// Accumulators of value pair `a <= b`, in accumulator order: shifts
    /// `0 .. k_b`, then `-1 .. -(k_a - 1)` (none for `a == b`).
    pub fn moment_pair_terms(&self, a: usize, b: usize) -> Vec<MomentTerm> {
        let map = self.moments.as_ref().expect("moments enabled");
        let (ka, kb) = (self.moment_digits(map[a].1) as isize, self.moment_digits(map[b].1) as isize);
        let mut v: Vec<MomentTerm> = (0..kb).map(|s| MomentTerm { a, b, shift: s }).collect();
        if a != b {
            v.extend((1..ka).map(|t| MomentTerm { a, b, shift: -t }));
        }
        v
    }

    /// Every accumulator, pairs `a <= b` row-major over `a`, then `b` from `a`.
    pub fn moment_terms(&self) -> Vec<MomentTerm> {
        let Some(map) = &self.moments else { return Vec::new() };
        let mut v = Vec::new();
        for a in 0..map.len() {
            for b in a..map.len() {
                v.extend(self.moment_pair_terms(a, b));
            }
        }
        v
    }

    /// Digit positions of a term that carry a product: `(position, digit
    /// of a, digit of b)`. Every other slot of the accumulator is zero.
    pub fn moment_term_cells(&self, t: MomentTerm) -> Vec<(usize, usize, usize)> {
        let map = self.moments.as_ref().expect("moments enabled");
        let (ka, kb) = (self.moment_digits(map[t.a].1), self.moment_digits(map[t.b].1));
        if t.shift >= 0 {
            let s = t.shift as usize;
            (0..ka).filter(|&i| i + s < kb).map(|i| (i, i, i + s)).collect()
        } else {
            let s = (-t.shift) as usize;
            (0..kb).filter(|&j| j + s < ka).map(|j| (j, j + s, j)).collect()
        }
    }

    /// Slots of a decrypted accumulator that the collector reads: through
    /// the last digit position either value can occupy.
    pub fn moment_term_span(&self, t: MomentTerm) -> usize {
        let map = self.moments.as_ref().expect("moments enabled");
        let k = self.moment_digits(map[t.a].1).max(self.moment_digits(map[t.b].1));
        self.group_slot(0, (k - 1) * self.moment_digit as usize) + 1
    }

    /// The integer sum of `a * b` products that accumulator `t`
    /// contributes, from its decrypted slots `0 .. moment_term_span(t)`
    /// over `valid` reports: `sum 2^((i+j)*D) * S[i,j]` over its cells,
    /// counted twice for the off-diagonal terms of a square. Refuses a
    /// cell above `valid` times its largest digit product (the digit width
    /// keeps that bound below `p`, so it is a corrupted contribution, not a
    /// wrap) and any non-zero slot outside the cells.
    pub fn moment_term_sum(&self, t: MomentTerm, slots: &[u64], valid: u64) -> std::result::Result<u128, String> {
        let map = self.moments.as_ref().expect("moments enabled");
        let d = self.moment_digit;
        let span = self.moment_term_span(t);
        if slots.len() != span {
            return Err(format!(
                "second moment ({},{}) accumulator has {} slots, expected {span}",
                t.a,
                t.b,
                slots.len()
            ));
        }
        let twice = if t.a == t.b && t.shift > 0 { 2u128 } else { 1 };
        let mut read = vec![false; span];
        let mut acc = 0u128;
        for (pos, da, db) in self.moment_term_cells(t) {
            let slot = self.group_slot(0, pos * d as usize);
            let v = slots[slot] as u128;
            let cap = (valid as u128) * ((1u128 << self.moment_digit_width(map[t.a].1, da)) - 1) * ((1u128 << self.moment_digit_width(map[t.b].1, db)) - 1);
            if v > cap {
                return Err(format!("second moment ({},{}) digit product ({da},{db}) exceeds its bound", t.a, t.b));
            }
            read[slot] = true;
            acc += (twice * v) << ((da + db) as u32 * d);
        }
        if slots.iter().zip(&read).any(|(&v, &r)| !r && v != 0) {
            return Err(format!("second moment ({},{}) accumulator has data outside its digit slots", t.a, t.b));
        }
        Ok(acc)
    }

    /// Every slot a moment computation touches for a report in the last
    /// group lies inside the row: value digits, their shifts by up to
    /// `k_a + k_b - 2` digits, and the window reads past each digit.
    pub fn moment_slots_fit(&self) -> bool {
        let Some(map) = &self.moments else { return true };
        let k = self.moment_max_digits();
        let d = self.moment_digit as usize;
        let reach = ((2 * k - 1) * d).max(
            map.iter()
                .map(|&(s, b)| s - self.chunk_range(self.chunk_of(s)).start + b as usize)
                .max()
                .unwrap_or(0)
                + self.moment_window(),
        );
        self.group_slot(self.groups - 1, reach) < self.row
    }

    /// Batched: stride between consecutive elements of one report.
    pub fn element_stride(&self) -> usize {
        match self.kind {
            LayoutKind::Blocked => 1,
            LayoutKind::Interleaved => self.classes,
            LayoutKind::Batched => self.classes * self.groups,
        }
    }

    /// Batched: slot of element `i` of the report in group `r` (repetition 0).
    pub fn group_slot(&self, r: usize, i: usize) -> usize {
        debug_assert!(r < self.groups);
        self.classes * r + self.element_stride() * i
    }

    /// Batched: rotation (left shift) that moves group `r`'s slots onto group 0's.
    pub fn group_fold_rotation(&self, r: usize) -> i32 {
        (self.classes * r) as i32
    }

    /// Batched: the power-of-two rotations from which any group fold is composed.
    pub fn group_fold_keys(&self) -> Vec<i32> {
        let mut v = Vec::new();
        let mut d = 1;
        while d < self.groups {
            v.push((self.classes * d) as i32);
            d *= 2;
        }
        v
    }

    /// Number of encoded elements carried by chunk `c`.
    pub fn chunk_len(&self, c: usize) -> usize {
        self.chunks[c].len()
    }

    /// Global input indices carried by chunk `c`.
    pub fn chunk_range(&self, c: usize) -> std::ops::Range<usize> {
        self.chunks[c].clone()
    }

    /// Slot in which a client places element `i` of a chunk (group 0 for Batched).
    pub fn client_slot(&self, i: usize) -> usize {
        i * self.element_stride()
    }

    /// Slots a fused chunk decryption must cover to read all its elements.
    pub fn chunk_span(&self, c: usize) -> usize {
        self.client_slot(self.chunk_len(c) - 1) + 1
    }

    /// Blocked only: slot holding the result of repetition `j`.
    pub fn result_slot(&self, j: usize) -> usize {
        debug_assert_eq!(self.kind, LayoutKind::Blocked);
        j * self.block
    }

    /// Blocked only: number of slots to decrypt to read every result slot.
    pub fn result_span(&self) -> usize {
        self.result_slot(self.repetitions - 1) + 1
    }

    /// Rotation that moves repetition 0's data onto repetition `j`'s position.
    pub fn replicate_rotation(&self, j: usize) -> i32 {
        match self.kind {
            LayoutKind::Blocked => -((j * self.block) as i32),
            LayoutKind::Interleaved | LayoutKind::Batched => -(j as i32),
        }
    }

    /// Rotations that sum each repetition's elements into its result position(s).
    pub fn sum_rotations(&self) -> Vec<i32> {
        let stride = self.element_stride();
        let mut v = Vec::new();
        let mut d = self.block / 2;
        while d >= 1 {
            v.push((d * stride) as i32);
            d /= 2;
        }
        v
    }

    /// Interleaved only: rotations whose product tree multiplies all classes.
    pub fn product_rotations(&self) -> Vec<i32> {
        debug_assert_ne!(self.kind, LayoutKind::Blocked);
        let mut v = Vec::new();
        let mut d = 1;
        while d < self.classes {
            v.push(d as i32);
            d *= 2;
        }
        v
    }

    /// Every rotation index the joint rotation keys must cover.
    pub fn rotation_indices(&self) -> Vec<i32> {
        let mut v = self.sum_rotations();
        for j in 1..self.repetitions {
            v.push(self.replicate_rotation(j));
        }
        if self.kind != LayoutKind::Blocked {
            v.extend(self.product_rotations());
        }
        if self.kind == LayoutKind::Batched {
            v.extend(self.group_fold_keys());
        }
        for r in self.moment_rotations() {
            if !v.contains(&r) {
                v.push(r);
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocked() {
        let l = Layout::new(LayoutKind::Blocked, 1, 4, 16384).unwrap();
        assert_eq!((l.block, l.num_chunks), (1, 1));
        assert_eq!(l.sum_rotations(), Vec::<i32>::new());
        assert_eq!(l.rotation_indices(), vec![-1, -2, -3]);

        let l = Layout::new(LayoutKind::Blocked, 14, 4, 16384).unwrap();
        assert_eq!((l.block, l.num_chunks), (16, 1));
        assert_eq!(l.sum_rotations(), vec![8, 4, 2, 1]);
        assert_eq!(l.result_slot(3), 48);
        assert_eq!(l.client_slot(5), 5);

        let l = Layout::new(LayoutKind::Blocked, 10_000, 4, 16384).unwrap();
        assert_eq!((l.block, l.num_chunks), (4096, 3));
        assert_eq!(l.chunk_len(2), 10_000 - 8192);
        assert_eq!(l.chunk_range(1), 4096..8192);

        assert_eq!(Layout::new(LayoutKind::Blocked, 5, 3, 16384).unwrap().block, 8);
        assert!(Layout::new(LayoutKind::Blocked, 0, 4, 16384).is_err());
        assert!(Layout::new(LayoutKind::Blocked, 1, 4, 100).is_err());
    }

    #[test]
    fn interleaved() {
        let l = Layout::new(LayoutKind::Interleaved, 14, 7, 32768).unwrap();
        assert_eq!((l.classes, l.block, l.num_chunks), (8, 4096, 1));
        assert_eq!(l.client_slot(3), 24);
        assert_eq!(l.chunk_span(0), 13 * 8 + 1);
        assert_eq!(l.sum_rotations().len(), 12);
        assert_eq!(l.sum_rotations()[0], 8 * 2048);
        assert_eq!(l.sum_rotations()[11], 8);
        assert_eq!(l.product_rotations(), vec![1, 2, 4]);
        assert_eq!(l.replicate_rotation(3), -3);
        assert_eq!(l.rotation_indices().len(), 12 + 6 + 3);

        let l = Layout::new(LayoutKind::Interleaved, 5000, 7, 32768).unwrap();
        assert_eq!((l.block, l.num_chunks), (4096, 2));
        assert_eq!(l.chunk_len(1), 904);
    }

    #[test]
    fn batched() {
        let l = Layout::with_groups(LayoutKind::Batched, 14, 4, 32768, 64).unwrap();
        assert_eq!((l.classes, l.groups, l.block, l.num_chunks), (4, 64, 128, 1));
        assert_eq!(l.element_stride(), 256);
        assert_eq!(l.group_slot(5, 3), 4 * 5 + 256 * 3);
        assert_eq!(l.client_slot(3), 768);
        assert_eq!(l.sum_rotations().len(), 7); // log2(128)
        assert_eq!(l.sum_rotations()[0], 256 * 64);
        assert_eq!(l.group_fold_keys(), vec![4, 8, 16, 32, 64, 128]);
        assert_eq!(l.group_fold_rotation(5), 20);
        assert_eq!(l.rotation_indices().len(), 7 + 3 + 2 + 6);
        assert!(Layout::with_groups(LayoutKind::Batched, 14, 4, 32768, 48).is_err());
        assert!(Layout::with_groups(LayoutKind::Interleaved, 14, 4, 32768, 2).is_err());
        // capacity: block must hold the input
        let l = Layout::with_groups(LayoutKind::Batched, 4800, 4, 32768, 4).unwrap();
        assert_eq!((l.block, l.num_chunks), (2048, 3));
    }

    /// Plaintext model of the batched circuit's slot algebra: class sums wrap
    /// the row, the product over the 4 classes lands on class-0 slots of the
    /// same group, and a group fold moves a group exactly onto group 0.
    #[test]
    fn batched_slot_algebra() {
        let l = Layout::with_groups(LayoutKind::Batched, 3, 4, 256, 8).unwrap(); // row 256, block 8
        let row = l.row;
        let rot = |v: &Vec<u64>, d: i32| -> Vec<u64> { (0..row).map(|s| v[((s as i64 + d as i64).rem_euclid(row as i64)) as usize]).collect() };
        // T: report r, repetition j, element i holds value 1000*r + 100*j + i
        let mut t = vec![0u64; row];
        for r in 0..l.groups {
            for j in 0..l.classes {
                for i in 0..l.block {
                    t[j + l.classes * r + l.element_stride() * i] = 1000 * r as u64 + 100 * j as u64 + i as u64;
                }
            }
        }
        let mut s = t.clone();
        for d in l.sum_rotations() {
            let r = rot(&s, d);
            s = s.iter().zip(&r).map(|(a, b)| a + b).collect();
        }
        for r in 0..l.groups {
            for j in 0..l.classes {
                let expect: u64 = (0..l.block).map(|i| 1000 * r as u64 + 100 * j as u64 + i as u64).sum();
                for i in 0..l.block {
                    assert_eq!(
                        s[j + l.classes * r + l.element_stride() * i],
                        expect,
                        "class sum must be replicated over the whole class"
                    );
                }
            }
        }
        // group fold: group r's class-0 slots land on group 0's class-0 slots
        let mut y = vec![0u64; row];
        let r = 5;
        for i in 0..l.block {
            y[l.group_slot(r, i)] = 7 + i as u64;
        }
        let folded = rot(&y, l.group_fold_rotation(r));
        for i in 0..l.block {
            assert_eq!(folded[l.group_slot(0, i)], 7 + i as u64);
        }
    }

    /// Cyclic left rotation, as `Context::rotate`: `out[x] = v[x + r]`.
    fn rot(v: &[u64], r: i64) -> Vec<u64> {
        let n = v.len() as i64;
        (0..n).map(|x| v[(x + r).rem_euclid(n) as usize]).collect()
    }

    /// Plaintext mirror of `Circuit::moment_products` for one report (slot
    /// vectors mod `p`), recording every rotation it uses.
    fn model_products(l: &Layout, chunks: &[Vec<u64>], group: usize, p: u64, used: &mut Vec<i32>) -> Vec<Vec<u64>> {
        let map = l.moments.as_ref().unwrap();
        let stride = l.element_stride();
        let d = l.moment_digit as usize;
        let rotate = |v: &[u64], r: usize, used: &mut Vec<i32>| {
            used.push(r as i32);
            rot(v, r as i64)
        };
        let add = |x: &[u64], y: &[u64]| x.iter().zip(y).map(|(a, b)| (a + b) % p).collect::<Vec<u64>>();
        let mul = |x: &[u64], y: &[u64]| {
            x.iter()
                .zip(y)
                .map(|(a, b)| ((*a as u128 * *b as u128) % p as u128) as u64)
                .collect::<Vec<u64>>()
        };
        let mut values = Vec::new();
        for &(start, bits) in map {
            let k = l.chunk_of(start);
            let local = start - l.chunk_range(k).start;
            let mut w = vec![0u64; l.row];
            for t in 0..bits as usize {
                w[l.group_slot(group, local + t)] = 1 << (t % d);
            }
            let z = mul(&chunks[k], &w);
            // window sum, as Circuit::window_sum
            let win = l.moment_window();
            let (mut acc, mut off, mut pp, mut span): (Option<Vec<u64>>, usize, Vec<u64>, usize) = (None, 0, z, 1);
            loop {
                if win & span != 0 {
                    let mut t = pp.clone();
                    let mut bit = 1;
                    while bit <= off {
                        if off & bit != 0 {
                            t = rotate(&t, stride * bit, used);
                        }
                        bit *= 2;
                    }
                    acc = Some(match acc {
                        None => t,
                        Some(a) => add(&a, &t),
                    });
                    off += span;
                }
                if 2 * span > win {
                    break;
                }
                let r = rotate(&pp, stride * span, used);
                pp = add(&pp, &r);
                span *= 2;
            }
            let z = acc.unwrap();
            let aligned = if local == 0 { z } else { rotate(&z, local * stride, used) };
            let digits = l.moment_digits(bits);
            let mut m = vec![0u64; l.row];
            for i in 0..digits {
                m[l.group_slot(group, i * d)] = 1;
            }
            let mut shifted = vec![mul(&aligned, &m)];
            for _ in 1..digits {
                let next = rotate(shifted.last().unwrap(), d * stride, used);
                shifted.push(next);
            }
            values.push(shifted);
        }
        l.moment_terms()
            .into_iter()
            .map(|t| {
                let (x, y) = if t.shift >= 0 {
                    (&values[t.a][0], &values[t.b][t.shift as usize])
                } else {
                    (&values[t.a][(-t.shift) as usize], &values[t.b][0])
                };
                let prod = mul(x, y);
                // silent batched mode folds the group onto group 0
                if group == 0 { prod } else { rot(&prod, (l.classes * group) as i64) }
            })
            .collect()
    }

    fn moments_layout(kind: LayoutKind, map: &[(usize, u32)], d: u32) -> Layout {
        let input_len = map.iter().map(|&(s, b)| s + b as usize).max().unwrap() + 2;
        let (reps, row, groups) = match kind {
            LayoutKind::Blocked => (1, 64, 1),
            LayoutKind::Interleaved => (3, 256, 1),
            LayoutKind::Batched => (3, 1024, 4),
        };
        let mut l = Layout::with_groups(kind, input_len, reps, row, groups).unwrap();
        l.moments = Some(map.to_vec());
        l.moment_digit = d;
        l.moment_pieces = (0..map.len()).map(|i| (i, 1)).collect();
        l
    }

    #[test]
    fn moment_cells_cover_every_digit_product_once() {
        for map in [vec![(0usize, 8u32), (8, 8), (16, 8)], vec![(0, 7), (14, 3), (20, 4)], vec![(0, 1), (2, 5)]] {
            let widest = map.iter().map(|&(_, b)| b).max().unwrap();
            for d in 1..=widest {
                let l = moments_layout(LayoutKind::Blocked, &map, d);
                for a in 0..map.len() {
                    for b in a..map.len() {
                        let (ka, kb) = (l.moment_digits(map[a].1), l.moment_digits(map[b].1));
                        let mut seen = std::collections::BTreeMap::new();
                        for t in l.moment_pair_terms(a, b) {
                            for (_, da, db) in l.moment_term_cells(t) {
                                let key = if a == b { (da.min(db), da.max(db)) } else { (da, db) };
                                *seen.entry(key).or_insert(0) += 1;
                            }
                        }
                        let want: Vec<(usize, usize)> = (0..ka).flat_map(|i| (0..kb).map(move |j| (i, j))).filter(|&(i, j)| a != b || i <= j).collect();
                        assert_eq!(seen.keys().copied().collect::<Vec<_>>(), want, "d={d} a={a} b={b}");
                        assert!(seen.values().all(|&c| c == 1));
                        let mults = l.moment_pair_terms(a, b).len();
                        assert_eq!(mults, if a == b { ka } else { ka + kb - 1 });
                    }
                }
            }
        }
    }

    /// The slot pipeline and the recombination, in plaintext mod small
    /// primes, over every layout kind, digit width and group, with batches
    /// at the largest size the digit width allows and every value at its
    /// maximum (each cell reaches its bound) or random. Junk the client
    /// wrote in slots outside a value's bits must not enter.
    #[test]
    fn moment_recombination_is_exact_at_the_digit_bound() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for p in [65537u64, 786433] {
            for kind in [LayoutKind::Blocked, LayoutKind::Interleaved, LayoutKind::Batched] {
                for map in [vec![(0usize, 8u32), (8, 8), (16, 8)], vec![(0, 7), (14, 3), (20, 4)]] {
                    let widest = map.iter().map(|&(_, b)| b).max().unwrap();
                    for d in 1..=widest {
                        let m = (1u64 << d) - 1;
                        let batch = (p - 1) / (m * m);
                        let l = moments_layout(kind, &map, d);
                        assert!(l.moment_slots_fit());
                        let reports = batch.min(if d == widest { batch } else { 3000 });
                        let all_max = rng.gen_bool(0.5);
                        let terms = l.moment_terms();
                        let mut acc = vec![vec![0u64; l.row]; terms.len()];
                        let mut exact = vec![vec![0u128; map.len()]; map.len()];
                        let mut used = Vec::new();
                        for r in 0..reports {
                            let group = r as usize % l.groups;
                            let vals: Vec<u64> = map
                                .iter()
                                .map(|&(_, b)| if all_max { (1 << b) - 1 } else { rng.gen_range(0..1u64 << b) })
                                .collect();
                            // chunk with junk everywhere, then the bits
                            let mut chunk: Vec<u64> = (0..l.row).map(|_| rng.gen_range(0..p)).collect();
                            for (&(start, bits), &v) in map.iter().zip(&vals) {
                                for t in 0..bits as usize {
                                    chunk[l.group_slot(group, start + t)] = (v >> t) & 1;
                                }
                            }
                            for (a, row) in acc.iter_mut().zip(model_products(&l, &[chunk], group, p, &mut used)) {
                                for (x, y) in a.iter_mut().zip(row) {
                                    *x = (*x + y) % p;
                                }
                            }
                            for a in 0..map.len() {
                                for b in 0..map.len() {
                                    exact[a][b] += vals[a] as u128 * vals[b] as u128;
                                }
                            }
                        }
                        let keys = l.moment_rotations();
                        assert!(used.iter().all(|r| keys.contains(r)), "rotation outside the key set: {used:?} vs {keys:?}");
                        let mut got = vec![vec![0u128; map.len()]; map.len()];
                        for (t, slots) in terms.iter().zip(&acc) {
                            let span = l.moment_term_span(*t);
                            assert!(slots[span..].iter().all(|&v| v == 0), "data past the span");
                            got[t.a][t.b] += l.moment_term_sum(*t, &slots[..span], reports).unwrap();
                        }
                        for a in 0..map.len() {
                            for b in a..map.len() {
                                assert_eq!(got[a][b], exact[a][b], "p={p} {kind:?} map={map:?} d={d} ({a},{b}) all_max={all_max}");
                            }
                        }
                        if all_max && d < widest && reports == batch {
                            // the undecomposed square would have wrapped
                            assert!(exact[0][0] >= p as u128);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn moment_term_sum_refuses_out_of_bound_and_stray_slots() {
        let l = moments_layout(LayoutKind::Interleaved, &[(0, 8), (8, 8)], 4);
        let t = MomentTerm { a: 0, b: 1, shift: 1 };
        let span = l.moment_term_span(t);
        let mut slots = vec![0u64; span];
        slots[0] = 10 * 15 * 15;
        assert_eq!(l.moment_term_sum(t, &slots, 10).unwrap(), (10 * 225) << 4);
        slots[0] += 1;
        assert!(l.moment_term_sum(t, &slots, 10).unwrap_err().contains("exceeds its bound"));
        slots[0] = 0;
        slots[1] = 1;
        assert!(l.moment_term_sum(t, &slots, 10).unwrap_err().contains("outside its digit slots"));
        // position 1 of shift 1 has no cell (digit 2 of b does not exist)
        slots[1] = 0;
        slots[l.group_slot(0, 4)] = 1;
        assert!(l.moment_term_sum(t, &slots, 10).unwrap_err().contains("outside its digit slots"));
        assert!(l.moment_term_sum(t, &slots[..span - 1], 10).is_err());
    }
}
