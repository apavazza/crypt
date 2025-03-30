use std::process::exit;
use crate::aes;
use crate::argon2;
use crate::file;
use crate::header;
use crate::password;

const CIPHER : &str = "AES";
const KEY_SIZE : u32 = 32;
const MODE : &str = "CBC";
const KDF : &str = "Argon2id";

pub fn encrypt(input_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let m_cost = argon2::DEFAULT_M_COST;
    let t_cost = argon2::DEFAULT_T_COST;
    let p_cost = argon2::DEFAULT_P_COST;
    let password = password::create();
    let contents = file::load_unencrypted(&input_file)?;
    let salt = argon2::generate_salt();
    let key = argon2::generate_key(m_cost, t_cost, p_cost, Some(KEY_SIZE.try_into().unwrap()), password.as_bytes(), &salt.as_bytes()).unwrap();
    let iv = aes::generate_iv();
    let ciphertext = aes::encrypt(contents, &key, &iv).unwrap();
    let header = header::Header::new(CIPHER, KEY_SIZE, MODE, KDF, &m_cost, &t_cost, &p_cost, &salt.as_bytes(), &iv);
    let output_file = file::get_unique_file_name(input_file, Some(crate::APP_NAME.to_lowercase().as_str()));
    let result = file::save_encrypted(&header, &ciphertext, &output_file);
    if result.is_err() {
        eprintln!("Failed to save encrypted file.");
        exit(0);
    }
    println!("File encrypted successfully: {}", output_file);
    Ok(())
}

pub fn decrypt(input_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (header, ciphertext) = file::load_encrypted(input_file)?;
    if !header.is_supported() {
        eprintln!("This encryption format is not supported.");
        eprintln!("File may be encrypted with a different version of {}.", crate::APP_NAME);
        exit(0);
    }

    if !header.check_integrity() {
        eprintln!("File integrity check failed.");
        eprintln!("File may be corrupted or tampered with.");
        exit(0);
    }

    let password = password::ask();
    let m_cost = header.get_m_cost();
    let t_cost = header.get_t_cost();
    let p_cost = header.get_p_cost();
    let salt = header.get_salt();
    let key = argon2::generate_key(m_cost, t_cost, p_cost, Some(32), password.as_bytes(), &salt).unwrap();
    let iv = header.get_iv();
    let plaintext = aes::decrypt(ciphertext, &key, &iv).unwrap();

    // Determine the base name for the output file
    let base_name = input_file.strip_suffix(&format!(".{}", crate::APP_NAME.to_lowercase())).unwrap_or(input_file);
    let output_file = file::get_unique_file_name(base_name, None);

    let result = file::save_unencrypted(&plaintext, &output_file);
    if result.is_err() {
        eprintln!("Failed to save decrypted file.");
        exit(0);
    }
    println!("File decrypted successfully: {}", output_file);
    Ok(())
}