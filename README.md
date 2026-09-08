# `sp1-solana`

Verifies [SP1](https://github.com/succinctlabs/sp1) Groth16 proofs on Solana using the
BN254 `alt_bn128` syscalls, via Light Protocol's
[`groth16-solana`](https://github.com/Lightprotocol/groth16-solana).

> [!CAUTION]
> This repository is not audited for production use.

## Versions

| Component | Version | Notes |
|---|---|---|
| SP1 | `sp1-sdk` / `sp1-zkvm` / `sp1-build` **=6.5.0** | Circuit version **v6.1.0**. Pinned exactly; `6.x` semver would resolve to a newer SDK. The v6 SDK is async; the example uses `#[tokio::main]`. |
| groth16-solana | git `43fee1a` | Unreleased master. crates.io 0.2.0 lacks `negate_g1_be`, `vk_commitment`, pinocchio syscalls. |
| Solana crates | Agave 3.x (`solana-program 3.0`, RPC client 3.1) | |
| Solana CLI / platform-tools | Agave 4.2 / v1.54 | Anything ≥ 2.x that has the `alt_bn128` syscalls works. |

One crate version is bound to one SP1 circuit version. The Groth16 verifying key and the
recursion vk root are compiled in as constants; there is no `groth16_vk` parameter.

## Repository overview

| Path | What |
|---|---|
| [`verifier/`](verifier) | The `sp1-solana` library. `src/vk.rs` is generated from `vk/v6.1.0/groth16_vk.bin`. |
| [`example/sp1-program/`](example/sp1-program) | SP1 guest program: reads `n`, commits `n`, `fib(n-1)`, `fib(n)` (mod 7919). |
| [`example/program/`](example/program) | Solana program that verifies the guest's proof and logs the public values. |
| [`example/script/`](example/script) | Client: proves with SP1 (optional), verifies host-side, then sends the proof to the program over RPC (Surfpool by default). |
| [`proofs/`](proofs) | A pre-generated v6 Groth16 proof of `fib(20)`. |

## SP1 v6 proof format

`SP1ProofWithPublicValues::bytes()` returns **356 bytes**:

```text
[  0..  4)  groth16 vk hash prefix    sha256(groth16_vk.bin)[..4]
[  4.. 36)  exit_code                 u256 BE; 0 when the guest returned normally
[ 36.. 68)  vk_root                   recursion vk merkle root, fixed per SP1 release
[ 68..100)  proof_nonce               per-proof randomness
[100..356)  groth16 proof             A (G1, 64) || B (G2, 128) || C (G1, 64), big-endian, as gnark emits
```

The circuit has 5 public inputs: `vkey_hash, committed_values_digest, exit_code, vk_root, proof_nonce`.
`committed_values_digest = sha256(public_values) & (2^253 - 1)`.

`verify_proof` checks, in order: length, vk prefix, `vk_root == VK_ROOT_BYTES`,
`exit_code == expected`, then a single pairing. The header checks are byte comparisons and
fail before any syscall is spent.

## Library API

```rust
use sp1_solana::{verify_proof, verify_proof_with_exit_code, verify_proof_with_hash, PublicValuesHash, Error};

// Guest exited with code 0, public values committed with sha256 (sp1_zkvm::io::commit).
verify_proof(&proof_bytes, &public_values, "0x00bb9e57…")?;

// Guest exited with a specific non-zero code (a proven panic).
verify_proof_with_exit_code(&proof_bytes, &public_values, vkey_hash, expected_exit_code)?;

// Explicit hash function; exactly one pairing.
verify_proof_with_hash(&proof_bytes, &public_values, vkey_hash, [0u8; 32], PublicValuesHash::Sha256)?;
```

### Hashing on-chain

SHA-256 goes through the `sol_sha256` syscall on the SBF target (`solana-sha256-hasher`), and
the pure-Rust `sha2` crate on the host.

Blake3 is behind the opt-in `blake3` cargo feature. Solana defines a `sol_blake3` syscall but it
is feature-gated (`HTW2pSyErTj4BV6KBM9NZ9VBUJVxt7sacNWcf76wtzb3`) and inactive on every public
cluster; a program that references it fails to load with
`ELF error: Unresolved symbol (sol_blake3)`. The feature therefore compiles the pure-Rust
`blake3` crate into the program. With the feature on, `verify_proof` retries with blake3 after a
SHA-256 pairing failure.

### Verifying key

`verifier/src/vk.rs` is generated (and rustfmt-normalised, so regenerating is a no-op unless
the `.bin` changed):

```shell
cargo run -p sp1-solana --example gen_vk
```

SP1 ships the vk with compressed points (gnark `WriteTo`). Decompressing on-chain costs one
`sol_alt_bn128_compression` syscall per point (10 for this vk) on every transaction, so the
generator decompresses once on the host and emits a `pub const Groth16Verifyingkey` that lands
in the program's `.rodata`. The test `generated_vk_matches_bin` fails if `vk.rs` drifts from the
`.bin`. To move to a new SP1 circuit version: drop the new `groth16_vk.bin` under
`verifier/vk/<version>/`, update `VERSION` in `examples/gen_vk.rs`, update `VK_ROOT_BYTES` in
`lib.rs` from `sp1-verifier`, regenerate.

## Requirements

Follow [Install Dependencies](https://solana.com/docs/intro/installation/dependencies) for
Rust, the Solana CLI, and Surfpool, then:

```shell
curl -L https://sp1up.succinct.xyz | bash && sp1up --version v6.5.0   # cargo prove + succinct toolchain
```

Proving locally also needs **Docker**: SP1 runs its gnark Groth16 wrapper in
`ghcr.io/succinctlabs/sp1-gnark:v6.1.0`, and downloads ~6 GB of circuit artifacts to
`~/.sp1/circuits/groth16/v6.1.0` on first use.

## Running the example

### 1. Build and deploy the Solana program

```shell
cargo build-sbf --manifest-path example/program/Cargo.toml       # → target/deploy/fibonacci_verifier_contract.so

solana-keygen new                                                 # once; payer at ~/.config/solana/id.json
solana config set --url http://127.0.0.1:8899
surfpool start --no-tui --no-deploy --offline --airdrop-keypair-path ~/.config/solana/id.json   # separate terminal

solana program deploy target/deploy/fibonacci_verifier_contract.so \
    --program-id target/deploy/fibonacci_verifier_contract-keypair.json
```

`--offline` runs Surfpool without forking mainnet; drop it to run against a mainnet fork.

### 2. Verify the pre-generated proof on-chain

```shell
cd example/script
cargo run --release -- --program-id <PROGRAM_ID>
```

The script loads `proofs/fibonacci_proof.bin`, verifies it host-side with the same
`sp1_solana::verify_proof` the program calls, then sends it as instruction data and prints the
program logs and compute units consumed. Expected output ends with:

```text
  log: Program log: Proof verified. Public values: (n: 20, a: 6765, b: 3027)
  log: Program <PROGRAM_ID> consumed 98353 of 399850 compute units
compute units consumed: 98503
```

For reference, `groth16-solana` measures ~95k CU for a bare 5-input Groth16 verify; the SP1
wrapper (borsh, header checks, `sol_sha256`, logging) adds ~3k.

### 3. Generate a fresh proof

```shell
cd example/script
RUST_LOG=info cargo run --release -- --prove --program-id <PROGRAM_ID>
```

`build.rs` compiles `example/sp1-program` to a RISC-V ELF with `cargo prove` (`SP1_BUILD_DOCKER=1`
builds it in SP1's reproducible Docker image instead). The script asserts the guest's
`vk.bytes32()` equals `FIBONACCI_VKEY_HASH` in `example/program/src/lib.rs`; if you change the
guest, update that constant and redeploy.

Prover selection is by environment, as in the SP1 SDK:

| `SP1_PROVER` | Backend | Build flag |
|---|---|---|
| `cpu` (default) | local CPU. Add `RUSTFLAGS="-C target-cpu=native"` for AVX2 (`+avx512f` for AVX-512). | — |
| `cuda` | local NVIDIA GPU | `--features cuda` |
| `network` | Succinct Prover Network; needs `NETWORK_PRIVATE_KEY` | — |

Measured on this repo's CPU run (56 cores, no AVX flags): STARK stages ≈ 3.5 min, gnark wrap
≈ 75 s, plus a one-time 6 GB artifact download.

### GPU proving

Requirements ([SP1 docs](https://docs.succinct.xyz/docs/sp1/generating-proofs/hardware-acceleration)):
Linux x86_64, NVIDIA driver + CUDA 12 runtime, GPU with compute capability ≥ 8.0 (RTX 30/40
series, A100, H100), 24 GB VRAM recommended. **Docker is not needed for the GPU prover** as of
SP1 v6: the SDK downloads a native `sp1-gpu-server` binary (~130 MB, from the SP1 GitHub release
matching the SDK version) to `~/.sp1/bin/` and starts it itself, talking over
`/tmp/sp1-cuda-<device>.sock`. Docker is still used for the gnark Groth16 wrap.

```shell
nvidia-smi                                   # driver visible, compute capability ≥ 8.0
cd example/script
SP1_PROVER=cuda cargo run --release --features cuda -- --prove --program-id <PROGRAM_ID>
```

The script refuses to run with `SP1_PROVER=cuda` if the binary was built without the feature.
To pick a GPU other than device 0, use `ProverClient::builder().cuda().with_device_id(n)` instead
of `from_env()`.

Verified on an RTX-class desktop: `proved fib(20) in 309.9s` (includes the gnark wrap in Docker and,
on a first run, the artifact download). The CUDA client keeps a socket to `sp1-gpu-server` whose
`Drop` uses `tokio::spawn`; the prover client must therefore be created and dropped inside a tokio
runtime. Do not wrap it with `sp1_sdk::blocking` — that facade runs each call on a temporary
runtime and the client is dropped outside it, which aborts the process at the end of proving
(`there is no reactor running`).

> [!NOTE]
> The proof and public values are passed as instruction data. A transaction is limited to
> 1232 bytes; the v6 proof alone is 356 bytes, so large public values need another transport
> (an account, or a lookup table).

## Installation

```toml
[dependencies]
sp1-solana = { git = "https://github.com/succinctlabs/sp1-solana" }
```

## Acknowledgements

Groth16 verification is done by [`groth16-solana`](https://github.com/Lightprotocol/groth16-solana/)
from Light Protocol. The proof layout and public-input derivation follow
[`sp1-verifier`](https://github.com/succinctlabs/sp1/tree/main/crates/verifier).
