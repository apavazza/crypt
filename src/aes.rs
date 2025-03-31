use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use block_padding::Pkcs7;
use rand::{rngs::OsRng, TryRngCore};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub const BLOCK_SIZE: usize = 16;
pub const KEY_SIZE : usize = 32;

pub fn encrypt(plaintext: Vec<u8>, key: &[u8; KEY_SIZE], iv: &[u8; BLOCK_SIZE]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let padded_len = plaintext.len() + BLOCK_SIZE - (plaintext.len() % BLOCK_SIZE);
    let mut buffer = vec![0u8; padded_len];

    buffer[..plaintext.len()].copy_from_slice(&plaintext);

    let enc = Aes256CbcEnc::new(key.into(), iv.into());
    enc.encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len()).unwrap();

    Ok(buffer)
}

pub fn decrypt(ciphertext: Vec<u8>, key: &[u8; KEY_SIZE], iv: &[u8; BLOCK_SIZE]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = ciphertext.clone();

    let dec = Aes256CbcDec::new(key.into(), iv.into());
    dec.decrypt_padded_mut::<Pkcs7>(&mut buffer).unwrap();

    let last_byte = *buffer.last().unwrap();
    if last_byte > 16 {
        return Err("Invalid padding".into());
    }

    let plaintext_len = buffer.len() - last_byte as usize;
    Ok(buffer[..plaintext_len].to_vec())
}



pub fn generate_iv() -> [u8; BLOCK_SIZE] {
    let mut rng = OsRng;
    let mut iv = [0u8; BLOCK_SIZE];
    rng.try_fill_bytes(&mut iv).unwrap();
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_iv() {
        let iv = generate_iv();
        assert_eq!(iv.len(), BLOCK_SIZE);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; KEY_SIZE];
        let iv = generate_iv();
        let plaintext = b"Hello, world!".to_vec();
        let ciphertext = encrypt(plaintext.clone(), &key, &iv).unwrap();
        let decrypted_plaintext = decrypt(ciphertext.clone(), &key, &iv).unwrap();

        assert_eq!(plaintext, decrypted_plaintext);
    }
}