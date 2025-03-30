use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = crate::APP_NAME)]
#[command(version = crate::APP_VERSION)]
#[command(about = crate::APP_DESCRIPTION, long_about = None)]

pub struct Cli {
    /// The command to run (encrypt, decrypt, header)
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a file
    #[command(visible_aliases = &["e"])] // Short alias for "encrypt"
    Encrypt {
        /// Path to the file to encrypt (positional argument)
        input_file: String,
    },
    /// Decrypt a file
    #[command(visible_aliases = &["d"])] // Short alias for "decrypt"
    Decrypt {
        /// Path to the file to decrypt (positional argument)
        input_file: String,
    },
    /// Display the header of an encrypted file
    #[command(visible_aliases = &["h"])] // Short alias for "header"
    Header {
        /// Path to the encrypted file (positional argument)
        input_file: String,
    },
}