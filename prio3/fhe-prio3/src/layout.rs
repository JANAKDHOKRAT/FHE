//! SIMD slot layout of the verification circuit.
//!
//! An encoded measurement of `m` bits is split into chunks of at most
//! `block` slots, one ciphertext per chunk. Inside a verification ciphertext
//! the row of `row` slots is divided into `repetitions` blocks of `block`
//! slots; repetition `j` of the check is accumulated in block `j`, and its
//! result ends up in slot `j * block`.

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub input_len: usize,
    pub repetitions: usize,
    pub row: usize,
    pub block: usize,
    pub num_chunks: usize,
}

impl Layout {
    pub fn new(input_len: usize, repetitions: usize, row: usize) -> Result<Self> {
        if input_len == 0 || repetitions == 0 || !row.is_power_of_two() {
            return Err(Error::Config("layout: input_len and repetitions must be >= 1; row must be a power of two".into()));
        }
        // Largest power-of-two block such that all repetitions fit in one row.
        let max_block = {
            let mut b = row;
            while b * repetitions > row {
                b /= 2;
            }
            b
        };
        if max_block == 0 {
            return Err(Error::Config(format!("layout: {repetitions} repetitions do not fit in a row of {row} slots")));
        }
        let block = input_len.next_power_of_two().min(max_block);
        let num_chunks = input_len.div_ceil(block);
        Ok(Self { input_len, repetitions, row, block, num_chunks })
    }

    /// Number of encoded slots carried by chunk `c`.
    pub fn chunk_len(&self, c: usize) -> usize {
        let start = c * self.block;
        (self.input_len - start).min(self.block)
    }

    /// Global input indices carried by chunk `c`.
    pub fn chunk_range(&self, c: usize) -> std::ops::Range<usize> {
        let start = c * self.block;
        start..start + self.chunk_len(c)
    }

    /// Slot holding the result of repetition `j`.
    pub fn result_slot(&self, j: usize) -> usize {
        j * self.block
    }

    /// Rotation by these amounts sums each block into its first slot.
    pub fn block_sum_rotations(&self) -> Vec<i32> {
        let mut v = Vec::new();
        let mut d = self.block / 2;
        while d >= 1 {
            v.push(d as i32);
            d /= 2;
        }
        v
    }

    /// Rotation that moves block 0 onto block `j` (a right shift).
    pub fn replicate_rotation(&self, j: usize) -> i32 {
        -((j * self.block) as i32)
    }

    /// Every rotation index the joint rotation keys must cover.
    pub fn rotation_indices(&self) -> Vec<i32> {
        let mut v = self.block_sum_rotations();
        for j in 1..self.repetitions {
            v.push(self.replicate_rotation(j));
        }
        v
    }

    /// Number of slots that must be decrypted to read every result slot.
    pub fn result_span(&self) -> usize {
        self.result_slot(self.repetitions - 1) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn small_and_chunked() {
        let l = Layout::new(1, 4, 16384).unwrap();
        assert_eq!((l.block, l.num_chunks), (1, 1));
        assert_eq!(l.block_sum_rotations(), Vec::<i32>::new());
        assert_eq!(l.rotation_indices(), vec![-1, -2, -3]);

        let l = Layout::new(14, 4, 16384).unwrap();
        assert_eq!((l.block, l.num_chunks), (16, 1));
        assert_eq!(l.block_sum_rotations(), vec![8, 4, 2, 1]);
        assert_eq!(l.result_slot(3), 48);

        let l = Layout::new(10_000, 4, 16384).unwrap();
        assert_eq!((l.block, l.num_chunks), (4096, 3));
        assert_eq!(l.chunk_len(2), 10_000 - 8192);
        assert_eq!(l.chunk_range(1), 4096..8192);

        let l = Layout::new(5, 3, 16384).unwrap();
        assert_eq!(l.block, 8);
        assert!(Layout::new(0, 4, 16384).is_err());
        assert!(Layout::new(1, 4, 100).is_err());
    }
}
