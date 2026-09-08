//! Regenerate `verifier/src/vk.rs` from `verifier/vk/<version>/groth16_vk.bin`.
//!
//! ```sh
//! cargo run -p sp1-solana --example gen_vk
//! ```

use sha2::{Digest, Sha256};
use sp1_solana::vkgen::{parse_sp1_groth16_vk, render_vk_rs};
use std::path::Path;

const VERSION: &str = "v6.1.0";

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let bin_path = root.join("vk").join(VERSION).join("groth16_vk.bin");
    let out_path = root.join("src").join("vk.rs");

    let bytes = std::fs::read(&bin_path).expect("read groth16_vk.bin");
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let vk = parse_sp1_groth16_vk(&bytes).expect("parse groth16_vk.bin");

    let rendered = render_vk_rs(&vk, VERSION, &digest);
    std::fs::write(&out_path, rendered).expect("write src/vk.rs");
    println!(
        "wrote {} ({} public inputs, vk prefix {})",
        out_path.display(),
        vk.nr_public_inputs(),
        hex::encode(&digest[..4])
    );
}
