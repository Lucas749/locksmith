use maestro::rep3_core::share::{HasZero, RssShare};
use maestro::share::gf8::GF8;

use mpz_fields::p256::P256;

pub mod data;
pub mod encrypt;
pub mod rust_impl;
pub mod aes;

use data::Input;

fn main() {
    println!("This is Locksmith!");

    // Create a new replicated secret share (using Araki optimisation)
    let rss_share: RssShare<GF8> = RssShare::<GF8>::from(GF8::ZERO, GF8::ZERO);
    println!("{:?}", rss_share);

    // Create element of P256 field for multi-party ECDH
    let p256_element: P256 = P256::new(0).unwrap();  
    println!("{:?}", p256_element);

    let input: &Input = &data::get_input("short");
    let ciphertext: String = encrypt::encrypt_ecb(input).unwrap();
    // let ciphertext: String = encrypt::encrypt_ctr(input, 0).unwrap();
    println!("Ciphertext: 0x{}", ciphertext);
}

#[test]
fn test_rust_aes_ecb() {
    let input: &Input = &data::get_input("short");

    let ecb_rust_ciphertext: String = rust_impl::rust_aes_ecb(input);
    let ecb_locksmith_ciphertext: String = data::get_ciphertext("short-ecb");
    assert_eq!(ecb_rust_ciphertext, ecb_locksmith_ciphertext);
}

#[test]
fn test_rust_aes_ctr() {
    let input: &Input = &data::get_input("short");

    let ctr_rust_ciphertext: String = rust_impl::rust_aes_ctr(input,0);
    let ctr_locksmith_ciphertext: String = data::get_ciphertext("short-ctr");

    assert_eq!(ctr_rust_ciphertext, ctr_locksmith_ciphertext);
}