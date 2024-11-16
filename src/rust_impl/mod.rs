use aes::cipher::inout::InOut;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes::Aes128;

pub fn rust_aes_ecb(input: &crate::Input) -> String {
    // Create AES key from our test key
    let key_bytes: [u8; 16] = crate::encrypt::rss::key_schedule::get_combined_key();
    let key: &GenericArray<u8, aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UTerm, aes::cipher::consts::B1>, aes::cipher::consts::B0>, aes::cipher::consts::B0>, aes::cipher::consts::B0>, aes::cipher::consts::B0>> = GenericArray::from_slice(&key_bytes);
    let cipher: Aes128 = Aes128::new(key);

    // Get input blocks
    let input_bytes: Vec<u8> = input.to_bytes();
    let num_blocks: usize = input.num_blocks();

    // Encrypt each block (ECB mode)
    let mut ciphertext: Vec<u8> = Vec::with_capacity(num_blocks * 16);
    for chunk in input_bytes.chunks(16) {
        let mut block: GenericArray<u8, aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UTerm, aes::cipher::consts::B1>, aes::cipher::consts::B0>, aes::cipher::consts::B0>, aes::cipher::consts::B0>, aes::cipher::consts::B0>> = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
    }

    println!("ECB ciphertext: 0x{}", hex::encode(&ciphertext));

    return hex::encode(&ciphertext);
}

pub fn rust_aes_ctr(input: &crate::Input, nonce: u128) -> String {
    // Create AES key from our test key
    let key_bytes: [u8; 16] = crate::encrypt::rss::key_schedule::get_combined_key();
    let key = GenericArray::from_slice(&key_bytes);
    let cipher: Aes128 = Aes128::new(key);

    // Get input bytes
    let input_bytes: Vec<u8> = input.to_bytes();
    
    // Initialize counter (nonce + counter)
    let mut counter = [0u8; 16];
    counter[..16].copy_from_slice(&nonce.to_be_bytes());
    let mut ctr_value = 0u128;

    // Encrypt in CTR mode
    let mut ciphertext: Vec<u8> = Vec::with_capacity(input_bytes.len());
    for chunk in input_bytes.chunks(16) {
        // Update counter block
        counter[..16].copy_from_slice(&(nonce.wrapping_add(ctr_value)).to_be_bytes());
        let mut counter_block = GenericArray::clone_from_slice(&counter);
        
        // Encrypt counter
        cipher.encrypt_block(&mut counter_block);
        
        // XOR with plaintext
        for (i, &byte) in chunk.iter().enumerate() {
            ciphertext.push(byte ^ counter_block[i]);
        }
        
        ctr_value = ctr_value.wrapping_add(1);
    }

    println!("CTR ciphertext: 0x{}", hex::encode(&ciphertext));
    hex::encode(&ciphertext)
}