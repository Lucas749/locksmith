use crate::data::Input;
mod rss;

use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use std::time::Duration;

use maestro::aes::VectorAesState;
use crate::aes::{AesKeyState, ss::aes128_no_keyschedule_mal};

use maestro::{rep3_core::{network::{Config, ConnectedParty}, party::{error::MpcResult, CombinedCommStats}, share::RssShare}, lut256::lut256_ss::{Lut256SSMalParty}};
use maestro::aes::ss::GF8InvBlackBoxSSMal;
use maestro::share::gf8::GF8;


#[derive(Parser)]
struct Cli {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
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

    // Preprocessing
    // 3 parties need preprocessed triples to generate the key schedule
    // so 98 blocks of preprocessed OHV
    party.do_preprocessing(3, 95).unwrap();

    // Print the combined key – no parties know this, only server does
    println!("{:?}", rss::key_schedule::get_combined_key());

    let input: VectorAesState = rss::share_input::rss_input(data_input, &mut party).unwrap();
    
    println!("Local input bytes as hex: 0x{}", input.to_bytes().iter()
        .map(|x| format!("{:02x}", x.si.0 ^ x.sii.0))
        .collect::<Vec<_>>()
        .join(""));

    let ks: Vec<maestro::aes::AesKeyState> = rss::key_schedule::keyshare_keyschedule(&mut party);
    let output: VectorAesState = aes128_no_keyschedule_mal(&mut party, input, &ks).unwrap();

    party.finalize().unwrap();

    let output = output.to_bytes();
    let (output_i, output_ii): (Vec<_>, Vec<_>) = output.into_iter().map(|rss: RssShare<GF8>| (rss.si, rss.sii)).unzip();
    let output_str: Vec<maestro::share::gf8::GF8> = party.output(&output_i, &output_ii).unwrap();

    for (i, chunk) in output_str.chunks(16).enumerate() {
        // raw representation
        // println!("- Block {} : {:?}", i, chunk);
        // hex representation
        println!("- Block {} : 0x{}", i, chunk.iter().map(|x| format!("{:02x}", x.0)).collect::<Vec<_>>().join(""));
        // binary representation
        // println!("- Block {} : [{}]", i, chunk.iter().map(|x| format!("{:08b}", x.0)).collect::<Vec<_>>().join(", "));
    }
    

    party.main_party_mut().teardown().unwrap();


    true
}

    
