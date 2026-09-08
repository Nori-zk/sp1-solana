//! Host-side conversion of SP1's `groth16_vk.bin` into a `Groth16Verifyingkey`.
//!
//! SP1 ships the Groth16 verifying key in gnark's *compressed* `WriteTo`
//! layout (32-byte G1, 64-byte G2, x-coordinate only + 2 flag bits):
//!
//! ```text
//! [α]1        G1  32   compressed
//! [β]1        G1  32   compressed   (unused by the verifier)
//! [β]2        G2  64   compressed
//! [γ]2        G2  64   compressed
//! [δ]1        G1  32   compressed   (unused by the verifier)
//! [δ]2        G2  64   compressed
//! nbK         u32 BE
//! K[]         nbK × G1 32 compressed
//! PublicAndCommitmentCommitted   [][]u64  (outerLen u32, then innerLen u32 + innerLen × u64)
//! nbCommitmentKeys               u32
//! CommitmentKeys[]               nbCommitmentKeys × (G2 64 + G2 64) compressed
//! ```
//!
//! `groth16-solana` wants uncompressed big-endian points, so decompression has
//! to happen somewhere. Doing it on-chain costs one `sol_alt_bn128_compression`
//! syscall per point (10 for this vk) on *every* transaction, for a key that
//! never changes. Instead this module decompresses once on the host and emits
//! `src/vk.rs` as a `pub const`, which ends up in the program's `.rodata`.
//!
//! Regenerate with `cargo run -p sp1-solana --example gen_vk`. The test
//! `vk::tests::generated_const_matches_bin` fails if `src/vk.rs` drifts from
//! `vk/<version>/groth16_vk.bin`.

extern crate std;

use groth16_solana::decompression::{decompress_g1, decompress_g2};
use groth16_solana::groth16::Groth16Verifyingkey;
use std::fmt::Write as _;
use std::string::String;
use std::vec::Vec;

/// Error while parsing SP1's `groth16_vk.bin`.
#[derive(Debug, PartialEq, Eq)]
pub enum VkGenError {
    /// Buffer too short for the fixed head / declared K count.
    Truncated,
    /// Compressed point flag byte is not one of gnark's three legal values.
    InvalidPointFlag,
    /// The BN254 syscall shim refused to decompress a point.
    Decompression,
    /// The vk carries BSB22 commitment keys; SP1 proofs never do, and this
    /// crate's verify path is plain Groth16 only.
    UnexpectedCommitmentKeys,
}

/// Owned, decompressed SP1 Groth16 verifying key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedVk {
    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamma_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],
    pub vk_ic: Vec<[u8; 64]>,
}

impl OwnedVk {
    /// Number of public inputs this vk expects (`nbK - 1`).
    pub fn nr_public_inputs(&self) -> usize {
        self.vk_ic.len() - 1
    }

    /// Borrow as the type `groth16_solana::Groth16Verifier::new` consumes.
    pub fn as_borrowed(&self) -> Groth16Verifyingkey<'_> {
        Groth16Verifyingkey {
            nr_pubinputs: self.nr_public_inputs(),
            vk_alpha_g1: self.vk_alpha_g1,
            vk_beta_g2: self.vk_beta_g2,
            vk_gamma_g2: self.vk_gamma_g2,
            vk_delta_g2: self.vk_delta_g2,
            vk_ic: &self.vk_ic,
            vk_commitment: None,
        }
    }
}

// gnark encodes the compression flag in the top two bits of the first byte
// (big-endian x). arkworks — which Solana's decompression syscall follows —
// uses a different encoding for the same three states.
// https://github.com/Consensys/gnark-crypto/blob/master/ecc/bn254/marshal.go
const GNARK_MASK: u8 = 0b11 << 6;
const GNARK_COMPRESSED_POSITIVE: u8 = 0b10 << 6; // y is the lexicographically smaller root
const GNARK_COMPRESSED_NEGATIVE: u8 = 0b11 << 6; // y is the larger root
const GNARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

const ARK_COMPRESSED_POSITIVE: u8 = 0b00 << 6;
const ARK_COMPRESSED_NEGATIVE: u8 = 0b10 << 6;
const ARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

fn gnark_flag_to_ark_flag(msb: u8) -> Result<u8, VkGenError> {
    let ark_flag = match msb & GNARK_MASK {
        GNARK_COMPRESSED_POSITIVE => ARK_COMPRESSED_POSITIVE,
        GNARK_COMPRESSED_NEGATIVE => ARK_COMPRESSED_NEGATIVE,
        GNARK_COMPRESSED_INFINITY => ARK_COMPRESSED_INFINITY,
        _ => return Err(VkGenError::InvalidPointFlag),
    };
    Ok((msb & !GNARK_MASK) | ark_flag)
}

/// gnark compressed G1 (32 B, BE) → uncompressed BE (64 B).
fn decompress_gnark_g1(bytes: &[u8; 32]) -> Result<[u8; 64], VkGenError> {
    let mut x = *bytes;
    x[0] = gnark_flag_to_ark_flag(x[0])?;
    decompress_g1(&x).map_err(|_| VkGenError::Decompression)
}

/// gnark compressed G2 (64 B, BE, `x.A1 || x.A0`) → uncompressed BE (128 B).
fn decompress_gnark_g2(bytes: &[u8; 64]) -> Result<[u8; 128], VkGenError> {
    let mut x = *bytes;
    x[0] = gnark_flag_to_ark_flag(x[0])?;
    decompress_g2(&x).map_err(|_| VkGenError::Decompression)
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], VkGenError> {
        let end = self.pos.checked_add(N).ok_or(VkGenError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(VkGenError::Truncated)?;
        self.pos = end;
        Ok(slice.try_into().expect("length checked"))
    }
    fn skip(&mut self, n: usize) -> Result<(), VkGenError> {
        let end = self.pos.checked_add(n).ok_or(VkGenError::Truncated)?;
        if end > self.buf.len() {
            return Err(VkGenError::Truncated);
        }
        self.pos = end;
        Ok(())
    }
    fn u32(&mut self) -> Result<u32, VkGenError> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }
}

/// Parse and decompress SP1's `groth16_vk.bin`.
pub fn parse_sp1_groth16_vk(bytes: &[u8]) -> Result<OwnedVk, VkGenError> {
    let mut c = Cursor { buf: bytes, pos: 0 };

    let vk_alpha_g1 = decompress_gnark_g1(&c.take::<32>()?)?;
    c.skip(32)?; // [β]1
    let vk_beta_g2 = decompress_gnark_g2(&c.take::<64>()?)?;
    let vk_gamma_g2 = decompress_gnark_g2(&c.take::<64>()?)?;
    c.skip(32)?; // [δ]1
    let vk_delta_g2 = decompress_gnark_g2(&c.take::<64>()?)?;

    let nb_k = c.u32()? as usize;
    if nb_k == 0 || nb_k > (bytes.len() - c.pos) / 32 {
        return Err(VkGenError::Truncated);
    }
    let mut vk_ic = Vec::with_capacity(nb_k);
    for _ in 0..nb_k {
        vk_ic.push(decompress_gnark_g1(&c.take::<32>()?)?);
    }

    // PublicAndCommitmentCommitted: consume to stay aligned.
    let outer = c.u32()?;
    for _ in 0..outer {
        let inner = c.u32()? as usize;
        c.skip(inner.checked_mul(8).ok_or(VkGenError::Truncated)?)?;
    }
    let nb_commitment_keys = c.u32()?;
    if nb_commitment_keys != 0 {
        return Err(VkGenError::UnexpectedCommitmentKeys);
    }

    Ok(OwnedVk {
        vk_alpha_g1,
        vk_beta_g2,
        vk_gamma_g2,
        vk_delta_g2,
        vk_ic,
    })
}

fn write_array(out: &mut String, bytes: &[u8]) {
    out.push('[');
    for (i, b) in bytes.iter().enumerate() {
        if i % 16 == 0 {
            out.push_str("\n        ");
        } else {
            out.push(' ');
        }
        let _ = write!(out, "{b},");
    }
    out.push_str("\n    ]");
}

/// Render `src/vk.rs` for the given vk. `version` is the SP1 circuit version
/// (e.g. `v6.1.0`); `vk_bin_sha256` is the full SHA-256 of the `.bin`, whose
/// first 4 bytes SP1 prepends to every proof.
pub fn render_vk_rs(vk: &OwnedVk, version: &str, vk_bin_sha256: &[u8; 32]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "//! SP1 Groth16 verifying key for circuit version `{version}`.\n\
         //!\n\
         //! GENERATED by `cargo run -p sp1-solana --example gen_vk` from\n\
         //! `vk/{version}/groth16_vk.bin` (sha256 {}). Do not edit by hand.\n",
        hex::encode(vk_bin_sha256)
    );
    out.push_str("use groth16_solana::groth16::Groth16Verifyingkey;\n\n");
    let _ = writeln!(out, "/// SP1 circuit version this vk belongs to.");
    let _ = writeln!(
        out,
        "pub const SP1_CIRCUIT_VERSION: &str = \"{version}\";\n"
    );
    let _ = writeln!(
        out,
        "/// `sha256(groth16_vk.bin)[..4]`: SP1 prepends this to every Groth16 proof."
    );
    out.push_str("pub const GROTH16_VK_HASH_PREFIX: [u8; 4] = ");
    write_array(&mut out, &vk_bin_sha256[..4]);
    out.push_str(";\n\n");
    let _ = writeln!(
        out,
        "/// Number of public inputs the circuit exposes (`nbK - 1`)."
    );
    let _ = writeln!(
        out,
        "pub const NR_PUBLIC_INPUTS: usize = {};\n",
        vk.nr_public_inputs()
    );

    let _ = writeln!(out, "const VK_IC: [[u8; 64]; {}] = [", vk.vk_ic.len());
    for ic in &vk.vk_ic {
        out.push_str("    ");
        write_array(&mut out, ic);
        out.push_str(",\n");
    }
    out.push_str("];\n\n");

    out.push_str("/// The decompressed Groth16 verifying key, ready for `Groth16Verifier::new`.\n");
    out.push_str("pub const GROTH16_VK: Groth16Verifyingkey<'static> = Groth16Verifyingkey {\n");
    let _ = writeln!(out, "    nr_pubinputs: NR_PUBLIC_INPUTS,");
    out.push_str("    vk_alpha_g1: ");
    write_array(&mut out, &vk.vk_alpha_g1);
    out.push_str(",\n    vk_beta_g2: ");
    write_array(&mut out, &vk.vk_beta_g2);
    out.push_str(",\n    vk_gamma_g2: ");
    write_array(&mut out, &vk.vk_gamma_g2);
    out.push_str(",\n    vk_delta_g2: ");
    write_array(&mut out, &vk.vk_delta_g2);
    out.push_str(",\n    vk_ic: &VK_IC,\n    vk_commitment: None,\n};\n");
    out
}
