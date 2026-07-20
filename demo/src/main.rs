//! One job, start to settlement, against the program deployed on devnet.
//!
//! Everything here is real: a real SPL mint, real token accounts, real transactions
//! landing on a real cluster, and a real ed25519 precompile verifying the verifier's
//! signature. Every step prints its transaction signature so anyone can open it in an
//! explorer and check the claim instead of taking this program's word for it.
//!
//! Run with: `cargo run -p demo`

use ed25519_dalek::{Signer as _, SigningKey};
use settlement_client::canonical::{canonicalize, hash, hex_encode};
use solana_address::Address;
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer as _;
use solana_transaction::Transaction;
use std::error::Error;

const PROGRAM_ID: &str = "8YpCfYtCBiLZ5SzTcmVZ5fkeBbPrvveWZnEzwpN8CQfJ";
const RPC: &str = "https://api.devnet.solana.com";
const PRICE: u64 = 25_000_000; // 25.00 of a 6-decimal token

fn main() -> Result<(), Box<dyn Error>> {
    let rpc = RpcClient::new_with_commitment(RPC.to_string(), CommitmentConfig::confirmed());
    let program_id: Address = PROGRAM_ID.parse()?;

    let payer = read_payer()?;
    println!("payer   {}", payer.pubkey());
    let balance = rpc.get_balance(&payer.pubkey())?;
    println!("balance {} SOL\n", balance as f64 / 1e9);
    if balance < 100_000_000 {
        return Err("payer needs at least 0.1 SOL on devnet".into());
    }

    // Four parties. In production these are different people and machines; here they
    // are four keypairs so the demo can drive all of them.
    let provider = Keypair::new();
    let verifier = SigningKey::from_bytes(&rand_seed());
    let arbiter = SigningKey::from_bytes(&rand_seed());

    println!("== the job ==");
    let spec = job_spec();
    let spec_bytes = canonicalize(&spec);
    let spec_hash = hash(&spec);
    let job_id = hash(&serde_json::json!({ "demo_job_at": now() }));
    println!("spec      {}", String::from_utf8_lossy(&spec_bytes));
    println!("spec_hash {}", hex(&spec_hash));
    println!("job_id    {}\n", hex(&job_id));

    // --- mint and token accounts -------------------------------------------------
    println!("== setting up a token and accounts ==");
    let mint = Keypair::new();
    let sig = create_mint(&rpc, &payer, &mint)?;
    println!("mint {}  {}", mint.pubkey(), explorer(&sig));

    let buyer_ata = ata(&payer.pubkey(), &mint.pubkey());
    let provider_ata = ata(&provider.pubkey(), &mint.pubkey());
    let sig = create_atas_and_mint_to(&rpc, &payer, &mint.pubkey(), &[
        (payer.pubkey(), PRICE),
        (provider.pubkey(), 0),
    ])?;
    println!("buyer and provider token accounts  {}\n", explorer(&sig));

    let (job_pda, _) = job_pda(&program_id, &job_id);
    let escrow = ata(&job_pda, &mint.pubkey());

    // --- create ------------------------------------------------------------------
    println!("== create_job ==");
    let terms = encode_terms(
        &job_id,
        &spec_hash,
        PRICE,
        &verifier.verifying_key().to_bytes(),
        &arbiter.verifying_key().to_bytes(),
        now() + 3600,
        1800,
        3600,
        &provider.pubkey(),
    );
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(job_pda, false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new(escrow, false),
            AccountMeta::new_readonly(token_program(), false),
            AccountMeta::new_readonly(ata_program(), false),
            AccountMeta::new_readonly(system_program(), false),
        ],
        data: anchor_data("create_job", &terms),
    };
    let sig = send(&rpc, &payer, &[ix], &[])?;
    println!("job account {}  {}", job_pda, explorer(&sig));
    println!("state       {}\n", read_state(&rpc, &job_pda)?);

    // --- fund --------------------------------------------------------------------
    println!("== fund ==");
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new(job_pda, false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new(buyer_ata, false),
            AccountMeta::new(escrow, false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data: anchor_data("fund", &[]),
    };
    let sig = send(&rpc, &payer, &[ix], &[])?;
    println!("escrow holds {}  {}", token_balance(&rpc, &escrow)?, explorer(&sig));
    println!("state        {}\n", read_state(&rpc, &job_pda)?);

    // --- the work happens, and the provider submits evidence ---------------------
    println!("== submit_evidence ==");
    let evidence = evidence_bundle(&job_id, &spec_hash);
    let evidence_hash = hash(&evidence);
    println!("evidence_hash {}", hex(&evidence_hash));

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(provider.pubkey(), true),
            AccountMeta::new(job_pda, false),
        ],
        data: anchor_data("submit_evidence", &evidence_hash),
    };
    let sig = send(&rpc, &payer, &[ix], &[&provider])?;
    println!("submitted  {}", explorer(&sig));
    println!("state      {}\n", read_state(&rpc, &job_pda)?);

    // --- the verifier checks the work against the spec ---------------------------
    println!("== the verifier evaluates the evidence against the spec ==");
    let spec_typed: settlement_client::model::JobSpec = serde_json::from_value(spec.clone())?;
    let evidence_typed: settlement_client::model::Evidence = serde_json::from_value(evidence)?;
    let evaluation = settlement_client::evaluate::evaluate(&spec_typed, &evidence_typed);
    for item in &evaluation.items {
        println!("  {:?}  {}", item.verdict, item.reason);
    }
    let verdict = match evaluation.assessment {
        settlement_client::evaluate::Assessment::Pass => settlement_core::Verdict::Pass,
        settlement_client::evaluate::Assessment::Fail => settlement_core::Verdict::Fail,
        settlement_client::evaluate::Assessment::Inconclusive { pending } => {
            return Err(format!(
                "this demo only uses machine-checkable acceptance items, but got pending: {pending:?}"
            )
            .into());
        }
    };
    println!("assessment {verdict:?}\n");

    // --- release -----------------------------------------------------------------
    println!("== release ==");
    let message =
        settlement_core::attestation_message(job_id, spec_hash, evidence_hash, verdict);
    let signature = verifier.sign(&message).to_bytes();

    // The precompile does the curve arithmetic; the program reads the instructions
    // sysvar and checks that this is exactly the key and message it expected.
    let verify_ix = solana_ed25519_program::new_ed25519_instruction_with_signature(
        &message,
        &signature,
        &verifier.verifying_key().to_bytes(),
    );
    let mut attestation = Vec::with_capacity(97);
    attestation.extend_from_slice(&evidence_hash);
    attestation.push(match verdict {
        settlement_core::Verdict::Pass => 0,
        settlement_core::Verdict::Fail => 1,
    });
    attestation.extend_from_slice(&signature);

    let settle = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(job_pda, false),
            AccountMeta::new_readonly(instructions_sysvar(), false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new(escrow, false),
            AccountMeta::new(provider_ata, false),
            AccountMeta::new(buyer_ata, false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data: anchor_data("release", &attestation),
    };
    let sig = send(&rpc, &payer, &[verify_ix, settle], &[])?;
    println!("settled  {}", explorer(&sig));
    println!("state    {}", read_state(&rpc, &job_pda)?);

    println!("\n== where the money ended up ==");
    println!("escrow   {}", token_balance(&rpc, &escrow)?);
    println!("provider {}", token_balance(&rpc, &provider_ata)?);
    println!("buyer    {}", token_balance(&rpc, &buyer_ata)?);

    Ok(())
}

// --- documents ------------------------------------------------------------------

fn job_spec() -> serde_json::Value {
    serde_json::json!({
        "version": "0.1",
        "kind": "print3d",
        "artifact": {
            "model_sha256": "a".repeat(64),
            "material": "PLA",
            "tolerance_um": 200,
            "quantity": 1
        },
        "delivery": { "region": "AR-B", "deadline_unix": now() + 3600 },
        "price": { "amount_minor": PRICE, "mint": "devnet-demo-mint" },
        // Only machine-checkable items: the point of the demo is the automatic path.
        // A spec with material_matches would come back Inconclusive by design, because
        // no instrument settles it and the evaluator refuses to sign what it cannot
        // measure.
        "acceptance": [
            { "id": "dims", "check": "dimensions_within_tolerance" },
            { "id": "on_time", "check": "delivered_before_deadline" }
        ]
    })
}

fn evidence_bundle(job_id: &[u8; 32], spec_hash: &[u8; 32]) -> serde_json::Value {
    serde_json::json!({
        "version": "0.1",
        "job_id": hex(job_id),
        "spec_sha256": hex(spec_hash),
        "submitted_unix": now(),
        "artifacts": [{ "kind": "caliper_reading", "sha256": "b".repeat(64) }],
        "measurements": { "deviation_um": 40, "delivered_unix": now() },
        "results": []
    })
}

// --- encoding -------------------------------------------------------------------

/// Anchor prefixes instruction data with sha256("global:<name>")[..8].
fn anchor_data(name: &str, args: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("global:{name}").as_bytes());
    let mut data = digest[..8].to_vec();
    data.extend_from_slice(args);
    data
}

#[allow(clippy::too_many_arguments)]
fn encode_terms(
    job_id: &[u8; 32],
    spec_hash: &[u8; 32],
    amount: u64,
    verifier: &[u8; 32],
    arbiter: &[u8; 32],
    evidence_deadline: i64,
    review: i64,
    arbitration: i64,
    provider: &Address,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(200);
    out.extend_from_slice(job_id);
    out.extend_from_slice(spec_hash);
    out.extend_from_slice(&amount.to_le_bytes());
    out.extend_from_slice(verifier);
    out.extend_from_slice(arbiter);
    out.extend_from_slice(&evidence_deadline.to_le_bytes());
    out.extend_from_slice(&review.to_le_bytes());
    out.extend_from_slice(&arbitration.to_le_bytes());
    out.extend_from_slice(&provider.to_bytes());
    out
}

fn hex(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

// --- chain helpers ---------------------------------------------------------------

fn read_payer() -> Result<Keypair, Box<dyn Error>> {
    let path = std::env::var("DEMO_KEYPAIR").unwrap_or_else(|_| {
        format!("{}/.config/solana/id.json", std::env::var("HOME").unwrap_or_default())
    });
    let bytes: Vec<u8> = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    Ok(Keypair::try_from(&bytes[..])?)
}

fn job_pda(program_id: &Address, job_id: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[b"job", job_id], program_id)
}

/// The associated token account is a PDA of [owner, token_program, mint].
fn ata(owner: &Address, mint: &Address) -> Address {
    Address::find_program_address(
        &[&owner.to_bytes(), &token_program().to_bytes(), &mint.to_bytes()],
        &ata_program(),
    )
    .0
}

fn system_program() -> Address {
    Address::from([0u8; 32])
}

fn token_program() -> Address {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".parse().expect("valid token program id")
}

fn ata_program() -> Address {
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL".parse().expect("valid ATA program id")
}

/// Size of an SPL mint account. Fixed by the token program's layout.
const MINT_LEN: u64 = 82;

fn instructions_sysvar() -> Address {
    "Sysvar1nstructions1111111111111111111111111".parse().expect("valid sysvar id")
}

fn explorer(signature: &str) -> String {
    format!("https://explorer.solana.com/tx/{signature}?cluster=devnet")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}

fn rand_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .subsec_nanos();
    let keypair = Keypair::new();
    seed.copy_from_slice(&keypair.pubkey().to_bytes());
    seed[0] ^= nanos as u8;
    seed
}

fn send(
    rpc: &RpcClient,
    payer: &Keypair,
    instructions: &[Instruction],
    extra: &[&Keypair],
) -> Result<String, Box<dyn Error>> {
    let blockhash = rpc.get_latest_blockhash()?;
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(
        instructions,
        Some(&payer.pubkey()),
        &signers,
        blockhash,
    );
    Ok(rpc.send_and_confirm_transaction(&tx)?.to_string())
}

fn read_state(rpc: &RpcClient, job: &Address) -> Result<&'static str, Box<dyn Error>> {
    let data = rpc.get_account_data(job)?;
    // 8-byte Anchor discriminator, then job_id (32), then the state byte.
    let state = data.get(8 + 32).copied().ok_or("job account too short")?;
    Ok(match state {
        0 => "Created",
        1 => "Funded",
        2 => "UnderReview",
        3 => "Released",
        4 => "Refunded",
        5 => "Disputed",
        _ => "unknown",
    })
}

fn token_balance(rpc: &RpcClient, account: &Address) -> Result<u64, Box<dyn Error>> {
    match rpc.get_token_account_balance(account) {
        Ok(balance) => Ok(balance.amount.parse()?),
        Err(_) => Ok(0),
    }
}

fn create_mint(
    rpc: &RpcClient,
    payer: &Keypair,
    mint: &Keypair,
) -> Result<String, Box<dyn Error>> {
    let rent = rpc.get_minimum_balance_for_rent_exemption(MINT_LEN as usize)?;
    let create = solana_system_interface::instruction::create_account(
        &payer.pubkey(),
        &mint.pubkey(),
        rent,
        MINT_LEN,
        &token_program(),
    );

    // InitializeMint: tag 0, decimals, mint authority, then an option for the freeze
    // authority. Six decimals to match the stablecoins this would settle in.
    let mut data = vec![0u8, 6];
    data.extend_from_slice(&payer.pubkey().to_bytes());
    data.push(0);
    let init = Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::new(mint.pubkey(), false),
            AccountMeta::new_readonly(rent_sysvar(), false),
        ],
        data,
    };
    send(rpc, payer, &[create, init], &[mint])
}

fn create_atas_and_mint_to(
    rpc: &RpcClient,
    payer: &Keypair,
    mint: &Address,
    owners_and_amounts: &[(Address, u64)],
) -> Result<String, Box<dyn Error>> {
    let mut instructions = Vec::new();
    for (owner, amount) in owners_and_amounts {
        let account = ata(owner, mint);
        // Create: the ATA program takes no instruction data for the idempotent-free
        // variant; it derives everything from the accounts.
        instructions.push(Instruction {
            program_id: ata_program(),
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(account, false),
                AccountMeta::new_readonly(*owner, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new_readonly(system_program(), false),
                AccountMeta::new_readonly(token_program(), false),
            ],
            data: vec![],
        });

        if *amount > 0 {
            // MintTo: tag 7 followed by the amount.
            let mut data = vec![7u8];
            data.extend_from_slice(&amount.to_le_bytes());
            instructions.push(Instruction {
                program_id: token_program(),
                accounts: vec![
                    AccountMeta::new(*mint, false),
                    AccountMeta::new(account, false),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                ],
                data,
            });
        }
    }
    send(rpc, payer, &instructions, &[])
}

fn rent_sysvar() -> Address {
    "SysvarRent111111111111111111111111111111111".parse().expect("valid rent sysvar id")
}
