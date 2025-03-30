use argon2::{
    password_hash::{
        rand_core::OsRng,
        SaltString,
    },
    Argon2, Params, Algorithm,
};

pub const DEFAULT_M_COST: u32 = 4096;
pub const DEFAULT_T_COST: u32 = 100;
pub const DEFAULT_P_COST: u32 = 16;

pub fn generate_key(m_cost: u32, t_cost: u32, p_cost: u32, output_len: Option<usize>, password: &[u8], salt: &[u8]) -> Result<[u8; 32], argon2::password_hash::Error> {
    let mut output_key_material = [0u8; 32];

    // Configure Argon2 parameters
    let params = Params::new(m_cost, t_cost, p_cost, output_len).unwrap_or_else(|e| {
        panic!("Failed to create Argon2 parameters: {}", e);
    });
    let kdf = Argon2::new(Algorithm::Argon2id, argon2::Version::V0x13, params);

    // Derive the key
    kdf.hash_password_into(&password, &salt, &mut output_key_material)?;

    Ok(output_key_material)
}

pub fn generate_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}