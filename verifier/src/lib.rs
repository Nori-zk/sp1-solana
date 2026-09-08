//! # sp1-solana
//!
//! Verifies SP1 Groth16 proofs on Solana using the BN254 `alt_bn128` syscalls,
//! via [`groth16-solana`](https://github.com/Lightprotocol/groth16-solana).
//!
//! Supports SP1 circuit version **v6.1.0** (shipped by `sp1-sdk` 6.5.x). One
//! crate version is bound to one circuit version: the Groth16 verifying key
//! and the recursion vk root are compiled in as constants.
//!
//! ## SP1 v6 Groth16 proof layout
//!
//! `SP1ProofWithPublicValues::bytes()` returns 356 bytes:
//!
//! ```text
//! [ 0..  4)  groth16 vk hash prefix  sha256(groth16_vk.bin)[..4]
//! [ 4.. 36)  exit_code               u256 BE, 0 for a program that returned normally
//! [36.. 68)  vk_root                 recursion vk merkle root, fixed per SP1 release
//! [68..100)  proof_nonce             per-proof randomness
//! [100..356) groth16 proof           A (G1 64) || B (G2 128) || C (G1 64), BE, as gnark emits
//! ```
//!
//! The circuit has 5 public inputs, in order:
//! `vkey_hash, committed_values_digest, exit_code, vk_root, proof_nonce`.
//!
//! ## Example
//! ```no_run
//! use sp1_sdk::SP1ProofWithPublicValues;
//! use sp1_solana::verify_proof;
//!
//! let proof = SP1ProofWithPublicValues::load("../proofs/fibonacci_proof.bin").unwrap();
//! // `vk.bytes32()` from `ProverClient::setup(ELF)`.
//! let vkey_hash = "0x00bb9e57314d7ee4f65a4b9fb46fbeae0495f2015c5a8a737333680ce6bb424e";
//! verify_proof(&proof.bytes(), proof.public_values.as_slice(), vkey_hash).unwrap();
//! ```

pub mod error;
pub mod hash;
pub mod vk;

#[cfg(not(target_os = "solana"))]
pub mod vkgen;

#[cfg(test)]
mod test;

pub use error::Error;
pub use hash::PublicValuesHash;
pub use vk::{GROTH16_VK, GROTH16_VK_HASH_PREFIX, NR_PUBLIC_INPUTS, SP1_CIRCUIT_VERSION};

use groth16_solana::groth16::{negate_g1_be, Groth16Verifier};

/// Length of the vk hash prefix SP1 prepends to the proof.
pub const VK_HASH_PREFIX_LEN: usize = 4;
/// Length of the raw gnark Groth16 proof (A || B || C, uncompressed BE).
pub const GROTH16_PROOF_LEN: usize = 256;
/// Total length of `SP1ProofWithPublicValues::bytes()` for a Groth16 proof.
pub const SP1_GROTH16_PROOF_LEN: usize = VK_HASH_PREFIX_LEN + 32 * 3 + GROTH16_PROOF_LEN;

/// Merkle root of the SP1 recursion verifying keys for circuit `v6.1.0`.
///
/// Copied from `sp1-verifier` at tag `v6.5.0` (`VK_ROOT_BYTES`). Every proof for
/// this circuit version commits to this root as its 4th public input; a
/// different root means the proof came from another SP1 release.
pub const VK_ROOT_BYTES: [u8; 32] = [
    0x00, 0x2f, 0x85, 0x0e, 0xe9, 0x98, 0x97, 0x4d, 0x6c, 0xc0, 0x0e, 0x50, 0xcd, 0x08, 0x14, 0xb0,
    0x98, 0xc0, 0x5b, 0xfa, 0xde, 0x46, 0x6d, 0x28, 0x57, 0x32, 0x40, 0xd0, 0x57, 0xf2, 0x53, 0x52,
];

/// Exit code committed by a guest program that returned normally.
pub const EXIT_CODE_SUCCESS: [u8; 32] = [0u8; 32];

/// Verify an SP1 Groth16 proof whose guest program exited successfully.
///
/// Tries the SHA-256 public-values digest first and falls back to blake3, so
/// it accepts proofs from either commit mode at the cost of a second pairing
/// (~80k CU) when the first fails. Production programs that know their commit
/// mode should call [`verify_proof_with_hash`] instead.
///
/// * `proof` — `SP1ProofWithPublicValues::bytes()`
/// * `sp1_public_values` — `SP1ProofWithPublicValues::public_values.as_slice()`
/// * `sp1_vkey_hash` — `vk.bytes32()` of the guest program, `0x`-prefixed hex
#[inline]
pub fn verify_proof(
    proof: &[u8],
    sp1_public_values: &[u8],
    sp1_vkey_hash: &str,
) -> Result<(), Error> {
    verify_proof_with_exit_code(proof, sp1_public_values, sp1_vkey_hash, EXIT_CODE_SUCCESS)
}

/// Like [`verify_proof`], but for guest programs that exit with a non-zero code
/// (e.g. a proven panic). Tries SHA-256 then blake3.
pub fn verify_proof_with_exit_code(
    proof: &[u8],
    sp1_public_values: &[u8],
    sp1_vkey_hash: &str,
    expected_exit_code: [u8; 32],
) -> Result<(), Error> {
    match verify_proof_with_hash(
        proof,
        sp1_public_values,
        sp1_vkey_hash,
        expected_exit_code,
        PublicValuesHash::Sha256,
    ) {
        // Only a pairing failure can be explained by the wrong digest; every
        // other error is definitive and retrying would just burn CU.
        Err(Error::Groth16(_)) => verify_proof_with_hash(
            proof,
            sp1_public_values,
            sp1_vkey_hash,
            expected_exit_code,
            PublicValuesHash::Blake3,
        ),
        other => other,
    }
}

/// Verify an SP1 Groth16 proof with an explicit public-values hash function.
/// Exactly one pairing check; the cheapest entry point.
pub fn verify_proof_with_hash(
    proof: &[u8],
    sp1_public_values: &[u8],
    sp1_vkey_hash: &str,
    expected_exit_code: [u8; 32],
    hash: PublicValuesHash,
) -> Result<(), Error> {
    if proof.len() != SP1_GROTH16_PROOF_LEN {
        return Err(Error::InvalidProofLength);
    }

    // 1. The proof must come from the Groth16 circuit this crate has the vk for.
    if proof[..VK_HASH_PREFIX_LEN] != GROTH16_VK_HASH_PREFIX {
        return Err(Error::Groth16VkeyHashMismatch);
    }

    let exit_code: [u8; 32] = proof[4..36].try_into().expect("length checked");
    let vk_root: [u8; 32] = proof[36..68].try_into().expect("length checked");
    let proof_nonce: [u8; 32] = proof[68..100].try_into().expect("length checked");

    // 2. The recursion vk root is fixed per SP1 release.
    if vk_root != VK_ROOT_BYTES {
        return Err(Error::VkRootMismatch);
    }

    // 3. The guest exited how the caller expects.
    if exit_code != expected_exit_code {
        return Err(Error::ExitCodeMismatch);
    }

    let sp1_vkey_hash = decode_sp1_vkey_hash(sp1_vkey_hash)?;
    let committed_values_digest = hash::hash_public_values(sp1_public_values, hash);

    let public_inputs: [[u8; 32]; NR_PUBLIC_INPUTS] = [
        sp1_vkey_hash,
        committed_values_digest,
        exit_code,
        vk_root,
        proof_nonce,
    ];

    verify_groth16_raw(&proof[VK_HASH_PREFIX_LEN + 96..], &public_inputs)
}

/// Run the bare Groth16 pairing check on a 256-byte gnark proof.
///
/// gnark emits `A`; the Solana pairing syscall checks
/// `e(A,B) · e(inputs,γ) · e(C,δ) · e(α,β) == 1`, which needs `-A`.
pub fn verify_groth16_raw(
    groth16_proof: &[u8],
    public_inputs: &[[u8; 32]; NR_PUBLIC_INPUTS],
) -> Result<(), Error> {
    if groth16_proof.len() != GROTH16_PROOF_LEN {
        return Err(Error::InvalidProofLength);
    }
    let proof_a: [u8; 64] = groth16_proof[..64].try_into().expect("length checked");
    let proof_a = negate_g1_be(&proof_a);
    let proof_b: &[u8; 128] = groth16_proof[64..192].try_into().expect("length checked");
    let proof_c: &[u8; 64] = groth16_proof[192..256].try_into().expect("length checked");

    let mut verifier =
        Groth16Verifier::new(&proof_a, proof_b, proof_c, public_inputs, &GROTH16_VK)?;
    // `verify` (not `verify_unchecked`) also rejects public inputs >= the Fr modulus.
    verifier.verify()?;
    Ok(())
}

/// Decode `vk.bytes32()` (`0x` + 64 hex chars) into 32 bytes.
pub fn decode_sp1_vkey_hash(sp1_vkey_hash: &str) -> Result<[u8; 32], Error> {
    let hex_str = sp1_vkey_hash
        .strip_prefix("0x")
        .ok_or(Error::InvalidProgramVkeyHash)?;
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out).map_err(|_| Error::InvalidProgramVkeyHash)?;
    Ok(out)
}
