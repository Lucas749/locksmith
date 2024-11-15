use crate::data::Input;
mod rss;

use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use std::time::Duration;

use maestro::aes::VectorAesState;
use maestro::aes::AesKeyState;

use maestro::{rep3_core::{network::{Config, ConnectedParty}, party::{error::MpcResult, CombinedCommStats}}, lut256::lut256_ss::{Lut256SSMalParty}};
#[derive(Parser)]
struct Cli {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
}

fn get_combined_key() -> [u8; 16] {
    let mut combined_key = [0u8; 16];
    for i in 0..16 {
        combined_key[i] = AES_KEYSHARE[0][i] ^ AES_KEYSHARE[1][i] ^ AES_KEYSHARE[2][i];
    }
    combined_key
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    // Remove "0x" prefix if present
    let hex: &str = hex.trim_start_matches("0x");
    
    // Convert pairs of hex chars to bytes
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn setup_party() -> ConnectedParty {
    let cli: Cli = Cli::parse();

    let (party_index, config) = Config::from_file(&cli.config)
        .expect("Failed to load config");
    
    let conn: ConnectedParty = ConnectedParty::bind_and_connect(
        party_index,
        config.clone(),
        Some(Duration::from_secs(60)),
    ).unwrap();

    conn
}

pub fn encrypt(data_input: &Input) -> bool {
    let conn: ConnectedParty = setup_party();

    let mut party: Lut256SSMalParty = Lut256SSMalParty::setup(conn, true, Some(0), Some("".to_string())).unwrap();
    println!("After setup");

    println!("{:?}", get_combined_key());

    let input: VectorAesState = rss::share_input::rss_input(data_input, &mut party).unwrap();
    
    println!("Local input bytes as hex: 0x{}", input.to_bytes().iter()
        .map(|x| format!("{:02x}", x.si.0 ^ x.sii.0))
        .collect::<Vec<_>>()
        .join(""));

    let ks: Vec<AesKeyState> = keyshare_keyschedule(&mut party);


    true
}

    
