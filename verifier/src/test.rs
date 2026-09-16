//! Unit tests. Anything needing a real v6 proof lives in
//! `test_verify_from_sp1` and reads `proofs/fibonacci_proof.bin`.

use crate::*;
use hex_literal::hex;

const VK_BIN: &[u8] = include_bytes!("../vk/v6.1.0/groth16_vk.bin");

/// `src/vk.rs` must be exactly what `gen_vk` produces from the committed `.bin`.
#[test]
fn generated_vk_matches_bin() {
    use sha2::{Digest, Sha256};
    let parsed = vkgen::parse_sp1_groth16_vk(VK_BIN).unwrap();
    let digest: [u8; 32] = Sha256::digest(VK_BIN).into();

    assert_eq!(SP1_CIRCUIT_VERSION, "v6.1.0");
    assert_eq!(GROTH16_VK_HASH_PREFIX, digest[..4]);
    assert_eq!(NR_PUBLIC_INPUTS, parsed.nr_public_inputs());
    // Value equality is what matters; `src/vk.rs` is rustfmt-normalised
    // after generation so a text comparison would be brittle.
    assert_eq!(
        GROTH16_VK,
        parsed.as_borrowed(),
        "src/vk.rs is stale: run `cargo run -p sp1-solana --example gen_vk`"
    );

    // The renderer itself must at least produce something mentioning the version.
    let rendered = vkgen::render_vk_rs(&parsed, SP1_CIRCUIT_VERSION, &digest);
    assert!(rendered.contains("pub const SP1_CIRCUIT_VERSION: &str = \"v6.1.0\";"));
}

#[test]
fn vk_shape() {
    // 5 public inputs: vkey_hash, committed_values_digest, exit_code, vk_root, proof_nonce
    assert_eq!(NR_PUBLIC_INPUTS, 5);
    assert_eq!(GROTH16_VK.vk_ic.len(), NR_PUBLIC_INPUTS + 1);
    assert_eq!(SP1_GROTH16_PROOF_LEN, 356);
}

#[test]
fn vkgen_rejects_truncated() {
    assert_eq!(
        vkgen::parse_sp1_groth16_vk(&VK_BIN[..VK_BIN.len() - 1]),
        Err(vkgen::VkGenError::Truncated)
    );
    assert_eq!(
        vkgen::parse_sp1_groth16_vk(&VK_BIN[..100]),
        Err(vkgen::VkGenError::Truncated)
    );
}

#[test]
fn hash_masks_top_bits() {
    // Independent of the input, the digest must be < 2^253.
    for input in [&b""[..], b"abc", &[0xffu8; 200][..]] {
        let s = hash::hash_public_values_sha256(input);
        let b = hash::hash_public_values_blake3(input);
        assert_eq!(s[0] & 0xE0, 0);
        assert_eq!(b[0] & 0xE0, 0);
        assert_ne!(s, b);
    }
    // Known vector: sha256("abc") = ba7816bf... → masked first byte 0x1a
    let s = hash::hash_public_values_sha256(b"abc");
    assert_eq!(
        s,
        hex!("1a7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn decode_vkey_hash() {
    let h = "0x0054c0e58911dd8b993c6d8f249aa50a2e523114ec4b7ef9dd355c5f6bfbf3ce";
    assert_eq!(
        decode_sp1_vkey_hash(h).unwrap(),
        hex!("0054c0e58911dd8b993c6d8f249aa50a2e523114ec4b7ef9dd355c5f6bfbf3ce")
    );
    assert_eq!(
        decode_sp1_vkey_hash("0x00"),
        Err(Error::InvalidProgramVkeyHash)
    );
    assert_eq!(
        decode_sp1_vkey_hash("0054c0"),
        Err(Error::InvalidProgramVkeyHash)
    );
    assert_eq!(
        decode_sp1_vkey_hash("0xzz"),
        Err(Error::InvalidProgramVkeyHash)
    );
}

const VKEY: &str = "0x0054c0e58911dd8b993c6d8f249aa50a2e523114ec4b7ef9dd355c5f6bfbf3ce";

fn well_formed_header() -> Vec<u8> {
    let mut p = Vec::with_capacity(SP1_GROTH16_PROOF_LEN);
    p.extend_from_slice(&GROTH16_VK_HASH_PREFIX);
    p.extend_from_slice(&EXIT_CODE_SUCCESS);
    p.extend_from_slice(&VK_ROOT_BYTES);
    p.extend_from_slice(&[7u8; 32]); // nonce
    p.extend_from_slice(&[0u8; GROTH16_PROOF_LEN]);
    p
}

/// The cheap checks must fire, in order, before any pairing work.
#[test]
fn header_checks_before_pairing() {
    assert_eq!(
        verify_proof(&[0u8; 260], b"", VKEY),
        Err(Error::InvalidProofLength)
    );

    let mut p = well_formed_header();
    p[0] ^= 1;
    assert_eq!(
        verify_proof(&p, b"", VKEY),
        Err(Error::Groth16VkeyHashMismatch)
    );

    let mut p = well_formed_header();
    p[36] ^= 1;
    assert_eq!(verify_proof(&p, b"", VKEY), Err(Error::VkRootMismatch));

    let mut p = well_formed_header();
    p[35] = 1; // exit code 1
    assert_eq!(verify_proof(&p, b"", VKEY), Err(Error::ExitCodeMismatch));
    // ...unless that's what the caller expects; then we get through to the pairing,
    // which fails on the all-zero proof points.
    let mut expected = [0u8; 32];
    expected[31] = 1;
    assert!(matches!(
        verify_proof_with_exit_code(&p, b"", VKEY, expected),
        Err(Error::Groth16(_))
    ));

    let p = well_formed_header();
    assert_eq!(
        verify_proof(&p, b"", "0x00"),
        Err(Error::InvalidProgramVkeyHash)
    );
}

/// End-to-end against the committed proof from `example/`.
#[test]
fn test_verify_from_sp1() {
    use sp1_sdk::SP1ProofWithPublicValues;

    let path = "../proofs/fibonacci_proof.bin";
    let Ok(proof) = SP1ProofWithPublicValues::load(path) else {
        panic!("{path} missing or not a v6 proof: run the example script with --prove");
    };

    let groth16 = proof
        .proof
        .clone()
        .try_as_groth_16()
        .expect("not a Groth16 proof");
    // The proof's own record of the guest vkey (as a decimal Fr string) must
    // agree with the hex form callers pass in.
    let vkey_hash_from_proof = {
        let n: [u8; 32] = groth16_public_input_be(&groth16.public_inputs[0]);
        format!("0x{}", hex::encode(n))
    };

    let proof_bytes = proof.bytes();
    let public_values = proof.public_values.as_slice();

    assert_eq!(proof_bytes.len(), SP1_GROTH16_PROOF_LEN);
    verify_proof(&proof_bytes, public_values, &vkey_hash_from_proof).expect("valid proof rejected");
    verify_proof_with_hash(
        &proof_bytes,
        public_values,
        &vkey_hash_from_proof,
        EXIT_CODE_SUCCESS,
        PublicValuesHash::Sha256,
    )
    .expect("sha256 path rejected");

    // Negative controls.
    assert!(matches!(
        verify_proof_with_hash(
            &proof_bytes,
            public_values,
            &vkey_hash_from_proof,
            EXIT_CODE_SUCCESS,
            PublicValuesHash::Blake3
        ),
        Err(Error::Groth16(_))
    ));
    let mut tampered = public_values.to_vec();
    tampered[0] ^= 1;
    assert!(matches!(
        verify_proof(&proof_bytes, &tampered, &vkey_hash_from_proof),
        Err(Error::Groth16(_))
    ));
    let mut tampered = proof_bytes.clone();
    tampered[200] ^= 1;
    assert!(matches!(
        verify_proof(&tampered, public_values, &vkey_hash_from_proof),
        Err(Error::Groth16(_))
    ));
    let other_vkey = "0x0054c0e58911dd8b993c6d8f249aa50a2e523114ec4b7ef9dd355c5f6bfbf3ce";
    assert!(matches!(
        verify_proof(&proof_bytes, public_values, other_vkey),
        Err(Error::Groth16(_))
    ));
}

/// gnark reports public inputs as decimal strings; convert to 32-byte BE.
fn groth16_public_input_be(decimal: &str) -> [u8; 32] {
    // Small hand-rolled base-10 → bytes to avoid pulling num-bigint into dev-deps.
    let mut bytes = [0u8; 32];
    for ch in decimal.bytes() {
        let d = (ch - b'0') as u16;
        let mut carry = d;
        for b in bytes.iter_mut().rev() {
            let v = (*b as u16) * 10 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0, "public input does not fit in 32 bytes");
    }
    bytes
}
