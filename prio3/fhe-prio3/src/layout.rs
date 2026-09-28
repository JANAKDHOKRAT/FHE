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
    /// Elements per chunk (a power of two).
    pub block: usize,
    pub num_chunks: usize,
    /// Second-moment accumulation enabled for a SumVec of (length, bits).
    pub moments: Option<(usize, u32)>,
}

impl Layout {
    pub fn new(kind: LayoutKind, input_len: usize, repetitions: usize, row: usize) -> Result<Self> {
        Self::with_groups(kind, input_len, repetitions, row, 1)
    }

    pub fn with_groups(kind: LayoutKind, input_len: usize, repetitions: usize, row: usize, groups: usize) -> Result<Self> {
        if input_len == 0 || repetitions == 0 || !row.is_power_of_two() {
            return Err(Error::Config("layout: input_len and repetitions must be >= 1; row must be a power of two".into()));
        }
        if !groups.is_power_of_two() || (kind != LayoutKind::Batched && groups != 1) {
            return Err(Error::Config("layout: groups must be a power of two and only Batched layouts have more than one".into()));
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
                    return Err(Error::Config(format!("layout: {groups} groups of {classes} classes do not fit in a row of {row} slots")));
                }
                row / (classes * groups)
            }
        };
        let num_chunks = input_len.div_ceil(block);
        Ok(Self { kind, input_len, repetitions, classes, groups, row, block, num_chunks, moments: None })
    }

    /// Rotations used by the second-moment computation: value sums over each
    /// value's `bits` elements, and alignment of value `a` onto element 0.
    pub fn moment_rotations(&self) -> Vec<i32> {
        let Some((length, bits)) = self.moments else { return Vec::new() };
        let stride = self.element_stride();
        let mut v = Vec::new();
        let mut d = 1usize;
        while d < bits as usize {
            v.push((stride * d) as i32);
            d *= 2;
        }
        for a in 1..length {
            v.push((a * bits as usize * stride) as i32);
        }
        v
    }

    /// Number of (a <= b) value pairs whose products are accumulated.
    pub fn moment_pairs(&self) -> usize {
        match self.moments {
            Some((length, _)) => length * (length + 1) / 2,
            None => 0,
        }
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
        let start = c * self.block;
        (self.input_len - start).min(self.block)
    }

    /// Global input indices carried by chunk `c`.
    pub fn chunk_range(&self, c: usize) -> std::ops::Range<usize> {
        let start = c * self.block;
        start..start + self.chunk_len(c)
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
                    assert_eq!(s[j + l.classes * r + l.element_stride() * i], expect, "class sum must be replicated over the whole class");
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
}
