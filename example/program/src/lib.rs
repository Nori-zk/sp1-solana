//! Example Solana program: verifies an SP1 Groth16 proof of the fibonacci
//! guest program (`example/sp1-program`) and logs its public values.
//!
//! Instruction data is a borsh-encoded [`SP1Groth16Proof`]. No accounts are
//! read or written; verification is pure computation over the instruction
//! data and the constants compiled into `sp1-solana`.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, msg, program_error::ProgramError,
    pubkey::Pubkey,
};
use sp1_solana::{verify_proof, Error};

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

/// `vk.bytes32()` of the fibonacci guest program. Printed by
/// `example/script --prove`; the script also asserts it matches this constant
/// so a rebuilt guest can't silently drift from the on-chain expectation.
pub const FIBONACCI_VKEY_HASH: &str =
    "0x0034abe3cbf32aa5b9fd0f17bba8e3dafa0adfd63d6ef7a5d127f6df78ab4e93";

/// The instruction data for the program.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone)]
pub struct SP1Groth16Proof {
    /// `SP1ProofWithPublicValues::bytes()` — 356 bytes for SP1 v6.
    pub proof: Vec<u8>,
    /// `SP1ProofWithPublicValues::public_values` — the guest's committed bytes.
    pub sp1_public_inputs: Vec<u8>,
}

/// Map verifier errors onto distinct custom program error codes so a client
/// can tell *why* a proof was rejected from the transaction error alone.
fn to_program_error(e: Error) -> ProgramError {
    let code = match e {
        Error::InvalidProofLength => 1,
        Error::Groth16VkeyHashMismatch => 2,
        Error::VkRootMismatch => 3,
        Error::ExitCodeMismatch => 4,
        Error::InvalidProgramVkeyHash => 5,
        Error::PublicInputOutOfField => 6,
        Error::Groth16(_) => 7,
    };
    msg!("sp1-solana: {}", e);
    ProgramError::Custom(code)
}

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let groth16_proof = SP1Groth16Proof::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    verify_proof(
        &groth16_proof.proof,
        &groth16_proof.sp1_public_inputs,
        FIBONACCI_VKEY_HASH,
    )
    .map_err(to_program_error)?;

    // The guest committed three u32s: n, fib(n-1), fib(n) (mod 7919).
    let mut reader = groth16_proof.sp1_public_inputs.as_slice();
    let n =
        u32::deserialize_reader(&mut reader).map_err(|_| ProgramError::InvalidInstructionData)?;
    let a =
        u32::deserialize_reader(&mut reader).map_err(|_| ProgramError::InvalidInstructionData)?;
    let b =
        u32::deserialize_reader(&mut reader).map_err(|_| ProgramError::InvalidInstructionData)?;
    msg!(
        "Proof verified. Public values: (n: {}, a: {}, b: {})",
        n,
        a,
        b
    );

    Ok(())
}
