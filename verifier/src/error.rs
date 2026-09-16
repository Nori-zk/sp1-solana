use thiserror::Error;

/// Errors returned by the SP1 Solana verifier.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    /// Proof bytes are not exactly [`crate::SP1_GROTH16_PROOF_LEN`] bytes.
    #[error("Invalid proof length")]
    InvalidProofLength,
    /// The first 4 bytes of the proof do not match `sha256(groth16_vk)[..4]`:
    /// the proof was produced for a different SP1 circuit version.
    #[error("Groth16 vkey hash mismatch")]
    Groth16VkeyHashMismatch,
    /// The `vk_root` public input does not match the recursion vk root baked
    /// into this crate for the supported SP1 version.
    #[error("Recursion vk root mismatch")]
    VkRootMismatch,
    /// The guest program exit code committed in the proof differs from the
    /// one the caller expects.
    #[error("Exit code mismatch")]
    ExitCodeMismatch,
    /// `sp1_vkey_hash` is not a `0x`-prefixed 64-hex-char string.
    #[error("Invalid program vkey hash")]
    InvalidProgramVkeyHash,
    /// A public input is not a canonical BN254 scalar (>= field modulus).
    #[error("Public input out of field")]
    PublicInputOutOfField,
    /// groth16-solana rejected the proof / vk pairing.
    #[error("Groth16 verification error: {0}")]
    Groth16(groth16_solana::errors::Groth16Error),
}

impl From<groth16_solana::errors::Groth16Error> for Error {
    fn from(e: groth16_solana::errors::Groth16Error) -> Self {
        Error::Groth16(e)
    }
}
