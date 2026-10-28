pub fn bit(i: usize, j: usize) -> u64 {
    ((17 * i + 31 * j + j / 3 + i * j / 7) % 2) as u64
}
