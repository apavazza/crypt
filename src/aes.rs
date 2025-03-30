use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::rngs::OsRng;
use rand::RngCore;

use std::error::Error;
use std::process::exit;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn encrypt(plaintext: Vec<u8>, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // Create an AES-CBC cipher instance
    let cipher = Aes256Cbc::new_from_slices(key, &iv)?;

    // Encrypt the contents
    let ciphertext = cipher.encrypt_vec(&plaintext);

    // Return the encrypted contents
    Ok(ciphertext)
}

pub fn decrypt(ciphertext: Vec<u8>, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // Create an AES-CBC cipher instance
    let cipher = Aes256Cbc::new_from_slices(&key, &iv)?;

    // Decrypt the contents
    let plaintext = cipher.decrypt_vec(&ciphertext).unwrap_or_else(|e| {
        eprintln!("Failed to decrypt: {}", e);
        eprintln!("The password may be incorrect.");
        eprintln!("Exiting...");
        exit(0);
    });

    // Return the decrypted contents
    Ok(plaintext)
}

pub fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    iv
}