//! Example client: (optionally) prove the fibonacci guest with SP1, then send
//! the Groth16 proof to the deployed verifier program on a local Solana RPC
//! (Surfpool by default) and report compute units.
//!
//! Prerequisites for `--prove`: Docker (SP1 runs its gnark Groth16 wrapper in
//! `succinctlabs/sp1-gnark`), and ~6 GB of circuit artifacts which SP1 downloads
//! to `~/.sp1/circuits/groth16/<version>` on first use.
//!
//! Prover selection is by environment, unchanged from the SP1 SDK:
//!   SP1_PROVER=cpu      (default) local CPU prover
//!   SP1_PROVER=cuda     local GPU prover (needs the `cuda` sdk feature + Docker + NVIDIA runtime)
//!   SP1_PROVER=network  Succinct Prover Network (needs NETWORK_PRIVATE_KEY)
//!
//! Usage:
//!   surfpool start --no-deploy &          # local Surfnet on :8899
//!   solana program deploy ../../target/deploy/fibonacci_verifier_contract.so
//!   cargo run --release -- --program-id <PUBKEY> [--prove] [--rpc-url http://127.0.0.1:8899]

use std::{path::PathBuf, str::FromStr};

use borsh::to_vec;
use clap::Parser;
use fibonacci_verifier_contract::{SP1Groth16Proof, FIBONACCI_VKEY_HASH};
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::{read_keypair_file, Keypair};
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::UiTransactionEncoding;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, utils, Elf, HashableKey, ProvingKey, SP1ProofWithPublicValues, SP1Stdin,
};

/// The RISC-V ELF of the fibonacci guest, built by `build.rs` via `sp1-build`.
const ELF: Elf = include_elf!("fibonacci-program");

#[derive(Parser)]
#[command(
    name = "sp1-solana example",
    about = "Prove fib(n) with SP1 and verify it on Solana"
)]
struct Cli {
    /// Generate a fresh Groth16 proof (needs Docker + SP1 circuit artifacts).
    /// Otherwise the proof at --proof-file is loaded.
    #[arg(long)]
    prove: bool,

    /// Fibonacci index the guest computes.
    #[arg(long, default_value_t = 20)]
    n: u32,

    /// Where to save / load the SP1 proof.
    #[arg(long, default_value = "../../proofs/fibonacci_proof.bin")]
    proof_file: PathBuf,

    /// Deployed `fibonacci-verifier-contract` program id. Skip on-chain
    /// verification when omitted (host-side verification still runs).
    #[arg(long)]
    program_id: Option<String>,

    /// JSON-RPC endpoint. Surfpool's default.
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    rpc_url: String,

    /// Fee payer keypair. Surfpool airdrops to the default CLI keypair on start.
    #[arg(long)]
    keypair: Option<PathBuf>,

    /// Compute unit limit for the verify transaction.
    #[arg(long, default_value_t = 400_000)]
    cu_limit: u32,
}

fn default_keypair_path() -> PathBuf {
    let home = std::env::var_os("HOME").expect("HOME not set");
    PathBuf::from(home).join(".config/solana/id.json")
}

fn prove(args: &Cli) -> SP1ProofWithPublicValues {
    // `blocking` facade over the async v6 SDK; picks cpu/cuda/network from SP1_PROVER.
    let client = ProverClient::from_env();
    let pk = client.setup(ELF).expect("setup");

    let vkey_hash = pk.verifying_key().bytes32();
    println!("guest vkey hash: {vkey_hash}");
    assert_eq!(
        vkey_hash, FIBONACCI_VKEY_HASH,
        "guest ELF changed: update FIBONACCI_VKEY_HASH in example/program/src/lib.rs"
    );

    let mut stdin = SP1Stdin::new();
    stdin.write(&args.n);

    let started = std::time::Instant::now();
    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .expect("Groth16 proof generation failed");
    println!("proved fib({}) in {:.1?}", args.n, started.elapsed());

    if let Some(dir) = args.proof_file.parent() {
        std::fs::create_dir_all(dir).expect("create proofs dir");
    }
    proof.save(&args.proof_file).expect("save proof");
    println!("saved {}", args.proof_file.display());
    proof
}

fn verify_on_chain(args: &Cli, program_id: Pubkey, ix_data: &SP1Groth16Proof) {
    let rpc = RpcClient::new_with_commitment(args.rpc_url.clone(), CommitmentConfig::confirmed());
    let payer: Keypair =
        read_keypair_file(args.keypair.clone().unwrap_or_else(default_keypair_path))
            .expect("read payer keypair; run `solana-keygen new` or pass --keypair");

    let balance = rpc.get_balance(&payer.pubkey()).expect("get_balance");
    println!("payer {} balance {} lamports", payer.pubkey(), balance);
    assert!(
        balance > 0,
        "payer is unfunded: `solana airdrop 10 --url {}`",
        args.rpc_url
    );

    let data = to_vec(ix_data).expect("borsh");
    println!("instruction data: {} bytes", data.len());

    let instructions = [
        ComputeBudgetInstruction::set_compute_unit_limit(args.cu_limit),
        Instruction::new_with_bytes(program_id, &data, vec![]),
    ];
    let blockhash = rpc.get_latest_blockhash().expect("get_latest_blockhash");
    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .expect("verify transaction failed");
    println!("confirmed: {sig}");

    let meta = rpc
        .get_transaction_with_config(
            &sig,
            RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Base64),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
            },
        )
        .expect("get_transaction")
        .transaction
        .meta
        .expect("transaction meta");

    let logs: Vec<String> = Option::from(meta.log_messages).unwrap_or_default();
    for line in &logs {
        println!("  log: {line}");
    }
    let cu: Option<u64> = Option::from(meta.compute_units_consumed);
    match cu {
        Some(cu) => println!("compute units consumed: {cu}"),
        None => println!("compute units consumed: (not reported by RPC)"),
    }
}

fn main() {
    utils::setup_logger();
    let args = Cli::parse();

    let proof = if args.prove {
        prove(&args)
    } else {
        SP1ProofWithPublicValues::load(&args.proof_file).unwrap_or_else(|e| {
            panic!(
                "failed to load {}: {e}. Run with --prove to generate it.",
                args.proof_file.display()
            )
        })
    };

    let ix_data = SP1Groth16Proof {
        proof: proof.bytes(),
        sp1_public_inputs: proof.public_values.to_vec(),
    };
    println!(
        "proof: {} bytes, public values: {} bytes",
        ix_data.proof.len(),
        ix_data.sp1_public_inputs.len()
    );

    // Same code path the program runs, on the host (pure-Rust bn254 instead of
    // syscalls). Fails fast before we spend a transaction.
    sp1_solana::verify_proof(
        &ix_data.proof,
        &ix_data.sp1_public_inputs,
        FIBONACCI_VKEY_HASH,
    )
    .expect("host-side verification failed");
    println!("host-side verification OK");

    match &args.program_id {
        Some(id) => verify_on_chain(
            &args,
            Pubkey::from_str(id).expect("invalid --program-id"),
            &ix_data,
        ),
        None => println!("no --program-id given; skipping on-chain verification"),
    }
}
