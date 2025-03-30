use serde::Serialize;
use prettytable::{Table, row};
use sha3::{Digest, Sha3_256};
use semver::Version;

#[derive(Serialize)]
#[derive(serde::Deserialize)]
pub struct Header {
    app: String,
    version: String,
    cipher: String,
    key_size: u32,
    mode: String,
    kdf: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: Vec<u8>,
    iv: Vec<u8>,
    integrity: Vec<u8>,
}

impl Header {
    pub fn new(cipher: &str, key_size: u32, mode: &str, kdf: &str, m_cost: &u32, t_cost: &u32, p_cost: &u32, salt: &[u8], iv: &[u8]) -> Self {
        let mut header = Header {
            app: crate::APP_NAME.to_string(),
            version: crate::APP_VERSION.to_string(),
            cipher: cipher.to_string(),
            key_size,
            mode: mode.to_string(),
            kdf: kdf.to_string(),
            m_cost: *m_cost,
            t_cost: *t_cost,
            p_cost: *p_cost,
            salt: salt.to_vec(),
            iv: iv.to_vec(),
            integrity: Vec::new(),
        };
        let integrity = header.calculate_hash();
        header.integrity.extend(integrity);
        header
    }

    pub fn print(&self) {
        let mut table = Table::new();
        table.add_row(row!["FIELD", "VALUE"]);
        table.add_row(row!["App", self.app]);
        table.add_row(row!["Version", self.version.to_string()]);
        table.add_row(row!["Cipher", self.cipher]);
        table.add_row(row!["Key Size", self.key_size.to_string()]);
        table.add_row(row!["Mode", self.mode]);
        table.add_row(row!["KDF", self.kdf]);
        table.add_row(row!["Memory", self.m_cost.to_string()]);
        table.add_row(row!["Iterations", self.t_cost.to_string()]);
        table.add_row(row!["Parallelism", self.p_cost.to_string()]);
        table.add_row(row!["Salt", format!("{:?}", self.salt)]);
        table.add_row(row!["IV", format!("{:?}", self.iv)]);
        table.add_row(row!["Integrity", format!("{:?}", self.integrity)]);

        table.printstd();
    }

    pub fn is_supported(&self) -> bool {
        // Parse the file version and the app version
        let file_version = Version::parse(&self.version);
        let app_version = Version::parse(crate::APP_VERSION);

        // Allow all versions <= APP_VERSION and patch-level changes for the same major.minor
        if let (Ok(file), Ok(app)) = (file_version, app_version) {
            // Check if the major and minor versions match
            if file.major == app.major && file.minor == app.minor {
                true // Allow any patch version
            } else {
                file <= app // Allow versions <= APP_VERSION
            }
        } else {
            false // Return false if version parsing fails
        }
    }

    fn calculate_hash(&self) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(self.app.as_bytes());
        hasher.update(self.version.as_bytes());
        hasher.update(self.cipher.as_bytes());
        hasher.update(self.key_size.to_be_bytes());
        hasher.update(self.mode.as_bytes());
        hasher.update(self.kdf.as_bytes());
        hasher.update(self.m_cost.to_be_bytes());
        hasher.update(self.t_cost.to_be_bytes());
        hasher.update(self.p_cost.to_be_bytes());
        hasher.update(&self.salt);
        hasher.update(&self.iv);
    
        hasher.finalize().to_vec()
    }

    pub fn check_integrity(&self) -> bool {
        let calculated_hash = self.calculate_hash();
        self.integrity == calculated_hash
    }

    pub fn get_m_cost(&self) -> u32 {
        self.m_cost
    }

    pub fn get_t_cost(&self) -> u32 {
        self.t_cost
    }

    pub fn get_p_cost(&self) -> u32 {
        self.p_cost
    }

    pub fn get_salt(&self) -> Vec<u8> {
        self.salt.clone()
    }

    pub fn get_iv(&self) -> Vec<u8> {
        self.iv.clone()
    }
    
}