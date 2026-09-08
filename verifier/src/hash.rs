//! Hashing of SP1 public values into the `committed_values_digest` public input.
//!
//! SP1 commits `sha256(public_values)` (default) or `blake3(public_values)`
//! into the Groth16 wrapper, with the top 3 bits zeroed so the digest fits in
//! the 254-bit BN254 scalar field. Both are reproduced here.
//!
//! On the Solana SBF target (`target_os = "solana"`) `solana-sha256-hasher` and
//! `solana-blake3-hasher` dispatch to the `sol_sha256` / `sol_blake3` runtime
//! syscalls; on the host they use the pure-Rust `sha2` / `blake3` crates.
//! Either way the call site here is the same.

/// Which hash function the SP1 guest program used to commit its public values.
///
/// `sp1_zkvm::io::commit` uses SHA-256. Blake3 is selected by guest programs
/// compiled with the SP1 blake3 public-values feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicValuesHash {
    Sha256,
    Blake3,
}

/// Zero the top 3 bits so a 256-bit digest is a canonical BN254 scalar.
/// Mirrors `sp1-verifier::hash_public_inputs_with_fn`.
#[inline]
fn mask_to_field(mut digest: [u8; 32]) -> [u8; 32] {
    digest[0] &= 0x1F;
    digest
}

/// `sha256(public_values)` with the field mask applied.
pub fn hash_public_values_sha256(public_values: &[u8]) -> [u8; 32] {
    mask_to_field(solana_sha256_hasher::hash(public_values).to_bytes())
}

/// `blake3(public_values)` with the field mask applied.
pub fn hash_public_values_blake3(public_values: &[u8]) -> [u8; 32] {
    mask_to_field(solana_blake3_hasher::hash(public_values).to_bytes())
}

/// Hash public values with the selected function.
pub fn hash_public_values(public_values: &[u8], hash: PublicValuesHash) -> [u8; 32] {
    match hash {
        PublicValuesHash::Sha256 => hash_public_values_sha256(public_values),
        PublicValuesHash::Blake3 => hash_public_values_blake3(public_values),
    }
}
