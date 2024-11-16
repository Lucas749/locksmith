use crate::data::Input;
pub mod rss;

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

pub fn print_gf8_bytes(bytes: &Vec<GF8>) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        // raw representation
        // println!("- Block {} : {:?}", i, chunk);
        // hex representation
        println!("- Block {} : 0x{}", i, chunk.iter().map(|x| format!("{:02x}", x.0)).collect::<Vec<_>>().join(""));
        // binary representation
        // println!("- Block {} : [{}]", i, chunk.iter().map(|x| format!("{:08b}", x.0)).collect::<Vec<_>>().join(", "));
    }
}

pub fn encrypt_ecb(data_input: &Input) -> Result<String, Box<dyn std::error::Error>> {
    let conn: ConnectedParty = setup_party();

    let mut party: Lut256SSMalParty = Lut256SSMalParty::setup(conn, true, Some(0), Some("".to_string())).unwrap();
    println!("After setup");

    // Preprocessing
    // 3 parties need preprocessed triples to generate the key schedule
    // so 98 blocks of preprocessed OHV
    println!("Preprocessing with {} blocks", data_input.num_blocks());
    party.do_preprocessing(3, 95).unwrap(); // 95 or data_input.num_blocks()

    // Print the combined key – no parties know this, only server does
    // println!("Symmetric key: {:?}", rss::key_schedule::get_combined_key());

    let input_ss: VectorAesState = rss::share_input::rss_input(data_input, &mut party).unwrap();
    
    println!("Local input bytes as hex: 0x{}", input_ss.to_bytes().iter()
        .map(|x| format!("{:02x}", x.si.0 ^ x.sii.0))
        .collect::<Vec<_>>()
        .join(""));

    let ks: Vec<maestro::aes::AesKeyState> = rss::key_schedule::keyshare_keyschedule(&mut party);
    let output: VectorAesState = aes128_no_keyschedule_mal(&mut party, input_ss, &ks).unwrap();

    party.finalize().unwrap();

    let output = output.to_bytes();
    let (output_i, output_ii): (Vec<_>, Vec<_>) = output.into_iter().map(|rss: RssShare<GF8>| (rss.si, rss.sii)).unzip();
    let ciphertext: Vec<maestro::share::gf8::GF8> = party.output(&output_i, &output_ii).unwrap();

    // print_gf8_bytes(&ciphertext);

    party.main_party_mut().teardown().unwrap();

    // Convert to hex string
    Ok(ciphertext.iter()
        .map(|x| format!("{:02x}", x.0))
        .collect::<String>())
}


pub fn encrypt_ctr(data_input: &Input, nonce: u128) -> Result<String, Box<dyn std::error::Error>> {
    let conn: ConnectedParty = setup_party();

    let mut party: Lut256SSMalParty = Lut256SSMalParty::setup(conn, true, Some(0), Some("".to_string())).unwrap();
    println!("After setup");

    party.do_preprocessing(3, 95).unwrap(); // 95 or data_input.num_blocks()
    let nonce_input: Input = Input::from_nonce(nonce, data_input.num_blocks());
    let input_ss: VectorAesState = rss::share_input::rss_input(&nonce_input, &mut party).unwrap();

    println!("Local input bytes as hex: 0x{}", input_ss.to_bytes().iter()
        .map(|x| format!("{:02x}", x.si.0 ^ x.sii.0))
        .collect::<Vec<_>>()
        .join(""));

    let ks: Vec<maestro::aes::AesKeyState> = rss::key_schedule::keyshare_keyschedule(&mut party);
    let output: VectorAesState = aes128_no_keyschedule_mal(&mut party, input_ss, &ks).unwrap();

    party.finalize().unwrap();

    let output = output.to_bytes();
    let (output_i, output_ii): (Vec<_>, Vec<_>) = output.into_iter().map(|rss: RssShare<GF8>| (rss.si, rss.sii)).unzip();
    let output_bytes: Vec<maestro::share::gf8::GF8> = party.output(&output_i, &output_ii).unwrap();
    // print_gf8_bytes(&output_bytes);

    party.main_party_mut().teardown().unwrap();

    // XOR output_bytes with data_input bytes
    let input_data_bytes: Vec<u8> = data_input.to_bytes(); //Input::zero(data_input.num_blocks()).to_bytes();
    println!("Input data bytes as hex: 0x{}", input_data_bytes.iter()
        .map(|x| format!("{:02x}", x))
        .collect::<String>());
    
    println!("Output bytes as hex: 0x{}", output_bytes.iter()
        .map(|x| format!("{:02x}", x.0))
        .collect::<String>());

    let ciphertext: Vec<maestro::share::gf8::GF8> = output_bytes.iter().zip(input_data_bytes.iter())
        .map(|(out, data)| maestro::share::gf8::GF8(out.0 ^ data))
        .collect();


    // Convert to hex string
    Ok(ciphertext.iter()
        .map(|x| format!("{:02x}", x.0))
        .collect::<String>())
}

    
