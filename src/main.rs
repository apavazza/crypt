use std::env;
use clap::Parser;

mod aes;
mod argon2;
mod cli;
mod crypt;
mod file;
mod header;
mod password;

// Constants for the application
pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const APP_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

fn main() -> std::io::Result<()> {
    let cli = cli::Cli::parse();

    match cli.command {
        cli::Commands::Encrypt { input_file } => {
            crypt::encrypt(&input_file).unwrap();
        }
        cli::Commands::Decrypt { input_file } => {
            crypt::decrypt(&input_file).unwrap();
        }
        cli::Commands::Header { input_file } => {
            let (header, _) = file::load_encrypted(&input_file)?;
            header.print();
        }
    }

    Ok(())
}