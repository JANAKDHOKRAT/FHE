//! Bounded framing for local, directly connected role-process pipes.
//! Framing detects malformed streams; it is NOT cryptographic authentication.
//! Do not expose it over a network without authenticated transport and peer/key
//! provisioning. The current cryptographic evaluator-authentication gap remains.
use crate::{Error, Result};
use std::io::{Read, Write};

const MAGIC: &[u8; 8] = b"PNEIPC01";
pub const PUBLIC_KEY: u8 = 1;
pub const REPORT: u8 = 2;
pub const CHECK: u8 = 3;
pub const VERDICT: u8 = 4;
pub const AGGREGATE: u8 = 5;
pub const RELEASE: u8 = 6;
pub const IDENTITY: u8 = 7;
pub const MAX_PUBLIC_KEY: usize = 4 * 1024 * 1024;

pub fn read_frame(reader: &mut impl Read, expected: u8, limit: usize) -> Result<Vec<u8>> {
    let refuse = || Error::Protocol("invalid role frame".into());
    let mut header = [0; 17];
    reader.read_exact(&mut header).map_err(|_| refuse())?;
    if &header[..8] != MAGIC || header[8] != expected {
        return Err(refuse());
    }
    let count = u64::from_le_bytes(header[9..].try_into().expect("fixed header"));
    let count = usize::try_from(count).map_err(|_| refuse())?;
    if count > limit {
        return Err(refuse());
    }
    let mut body = Vec::new();
    body.try_reserve_exact(count).map_err(|_| refuse())?;
    body.resize(count, 0);
    reader.read_exact(&mut body).map_err(|_| refuse())?;
    Ok(body)
}
pub fn write_frame(writer: &mut impl Write, kind: u8, bytes: &[u8]) -> Result<()> {
    writer
        .write_all(MAGIC)
        .and_then(|()| writer.write_all(&[kind]))
        .and_then(|()| writer.write_all(&(bytes.len() as u64).to_le_bytes()))
        .and_then(|()| writer.write_all(bytes))
        .and_then(|()| writer.flush())
        .map_err(|_| Error::Protocol("role stream unavailable".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_limits_and_roles_are_enforced_before_reading_body() {
        let mut encoded = Vec::new();
        write_frame(&mut encoded, REPORT, &[1, 2, 3]).unwrap();
        assert_eq!(read_frame(&mut &encoded[..], REPORT, 3).unwrap(), vec![1, 2, 3]);
        assert!(read_frame(&mut &encoded[..], CHECK, 3).is_err());
        assert!(read_frame(&mut &encoded[..], REPORT, 2).is_err());
        assert!(read_frame(&mut &encoded[..encoded.len() - 1], REPORT, 3).is_err());
        encoded[9..17].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(read_frame(&mut &encoded[..17], REPORT, 1024).is_err());
        encoded[0] ^= 1;
        assert!(read_frame(&mut &encoded[..], REPORT, usize::MAX).is_err());
    }
}
