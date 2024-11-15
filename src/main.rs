use maestro::rep3_core::share::{HasZero, RssShare};
use maestro::share::gf8::GF8;

use mpz_fields::p256::P256;

pub mod data;
pub mod encrypt;
use encrypt::encrypt;

use data::Input;

fn main() {
    println!("This is Locksmith!");

    // Create a new replicated secret share (using Araki optimisation)
    let rss_share: RssShare<GF8> = RssShare::<GF8>::from(GF8::ZERO, GF8::ZERO);
    println!("{:?}", rss_share);

    // Create element of P256 field for multi-party ECDH
    let p256_element: P256 = P256::new(0).unwrap();  
    println!("{:?}", p256_element);

    let input: &Input = data::get_input("long");
    println!("{}", encrypt(input));
}
