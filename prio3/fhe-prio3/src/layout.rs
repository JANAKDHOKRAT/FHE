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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub kind: LayoutKind,
    pub input_len: usize,
    pub repetitions: usize,
    /// Interleaved only: number of residue classes, `repetitions.next_power_of_two()`.
    pub classes: usize,
    pub row: usize,
    /// Elements per chunk (a power of two).
    pub block: usize,
    pub num_chunks: usize,
}

impl Layout {
    pub fn new(kind: LayoutKind, input_len: usize, repetitions: usize, row: usize) -> Result<Self> {
        if input_len == 0 || repetitions == 0 || !row.is_power_of_two() {
            return Err(Error::Config("layout: input_len and repetitions must be >= 1; row must be a power of two".into()));
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
        };
        let num_chunks = input_len.div_ceil(block);
        Ok(Self { kind, input_len, repetitions, classes, row, block, num_chunks })
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

    /// Slot in which a client places element `i` of a chunk.
    pub fn client_slot(&self, i: usize) -> usize {
        match self.kind {
            LayoutKind::Blocked => i,
            LayoutKind::Interleaved => i * self.classes,
        }
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
            LayoutKind::Interleaved => -(j as i32),
        }
    }

    /// Rotations that sum each repetition's elements into its result position(s).
    pub fn sum_rotations(&self) -> Vec<i32> {
        let stride = match self.kind {
            LayoutKind::Blocked => 1,
            LayoutKind::Interleaved => self.classes,
        };
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
        debug_assert_eq!(self.kind, LayoutKind::Interleaved);
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
        if self.kind == LayoutKind::Interleaved {
            v.extend(self.product_rotations());
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
}
