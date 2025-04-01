use argon2::{Argon2, Algorithm, Params};
use rand::{rngs::OsRng, TryRngCore};

pub const DEFAULT_M_COST: u32 = 4096;
pub const DEFAULT_T_COST: u32 = 100;
pub const DEFAULT_P_COST: u32 = 16;

pub fn generate_key(m_cost: u32, t_cost: u32, p_cost: u32, output_len: Option<usize>, password: &[u8], salt: &[u8]) -> Result<[u8; crate::aes::KEY_SIZE], argon2::password_hash::Error> {
    let mut output_key_material = [0u8; crate::aes::KEY_SIZE];

    // Configure Argon2 parameters
    let params = Params::new(m_cost, t_cost, p_cost, output_len).unwrap_or_else(|e| {
        panic!("Failed to create Argon2 parameters: {}", e);
    });
    let kdf = Argon2::new(Algorithm::Argon2id, argon2::Version::V0x13, params);

    // Derive the key
    kdf.hash_password_into(&password, &salt, &mut output_key_material)?;

    Ok(output_key_material)
}

pub fn generate_salt() -> Result<[u8; 22], Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let mut salt = [0u8; 22];
    rng.try_fill_bytes(&mut salt).unwrap();
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt() {
        let salt = generate_salt();
        assert_eq!(salt.unwrap().len(), 22);
    }

    #[test]
    fn test_generate_key() {
        let password = b"password";
        let salt = generate_salt().unwrap();
        let m_cost = DEFAULT_M_COST;
        let t_cost = DEFAULT_T_COST;
        let p_cost = DEFAULT_P_COST;
        let key_size: usize = crate::aes::KEY_SIZE;
        let key = generate_key(m_cost, t_cost, p_cost, Some(key_size), password, &salt).unwrap();
        assert_eq!(key.len(), key_size);
    }
}