//! Compiles `../sp1-program` to a RISC-V ELF and exposes it to
//! `include_elf!("fibonacci-program")`.
//!
//! Default: **reproducible Docker build** in `ghcr.io/succinctlabs/sp1:v<sp1-build version>`.
//! The image pins the `succinct` toolchain, mounts the workspace at a fixed path and trims
//! source paths, so every machine produces the same ELF bytes — and therefore the same guest
//! vkey hash, which `example/program` hard-codes as `FIBONACCI_VKEY_HASH`.

use sp1_build::BuildArgs;

fn main() {
    let native = std::env::var("SP1_BUILD_NATIVE")
        .map(|v| v == "1")
        .unwrap_or(false);
    if native {
        println!("cargo:warning=SP1_BUILD_NATIVE=1: guest ELF built with the local toolchain; vkey hash may differ from FIBONACCI_VKEY_HASH");
    }
    println!("cargo:rerun-if-env-changed=SP1_BUILD_NATIVE");

    sp1_build::build_program_with_args(
        "../sp1-program",
        BuildArgs {
            docker: !native,
            ..Default::default()
        },
    );
}
