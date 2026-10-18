//! Keccak-256 (Ethereum flavour).
//!
//! One function, one primitive, zero ambiguity: every digest in the protocol —
//! `ctRoot` steps, weight digests, transcripts, trace digests, CIDs — is
//! Keccak-256 over an exactly-specified preimage. NOT NIST SHA3-256: the two
//! differ in padding and silently disagree on every input.

use sha3::{Digest, Keccak256};

/// Keccak-256 of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let out = Keccak256::digest(data);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_keccak_matches_the_known_vector() {
        assert_eq!(
            keccak256(b""),
            [
                0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
                0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
                0x5d, 0x85, 0xa4, 0x70
            ]
        );
    }
}
