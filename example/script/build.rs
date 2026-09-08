//! Compiles `../sp1-program` to a RISC-V ELF with the `succinct` toolchain
//! (installed by `sp1up`) and exposes it to `include_elf!("fibonacci-program")`.
//!
//! `docker: false` uses the local `cargo prove` toolchain. Set
//! `SP1_BUILD_DOCKER=1` to build inside SP1's reproducible Docker image
//! instead (gives a bit-identical ELF, hence a stable vkey hash, across machines).

use sp1_build::BuildArgs;

fn main() {
    let docker = std::env::var("SP1_BUILD_DOCKER")
        .map(|v| v == "1")
        .unwrap_or(false);
    sp1_build::build_program_with_args(
        "../sp1-program",
        BuildArgs {
            docker,
            ..Default::default()
        },
    );
}
