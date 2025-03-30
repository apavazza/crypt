use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use crate::header::Header;


pub fn load_unencrypted(path: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(path).expect("File not found.");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();

    Ok(contents)
}

pub fn save_encrypted(header: &Header, contents: &Vec<u8>, path: &str) -> std::io::Result<()> {
    let header = serde_json::to_string(&header).unwrap();
    let mut file = File::create(path).expect("File could not be created.");
    file.write(header.as_bytes()).unwrap();
    file.write(b"\n").unwrap();
    file.write_all(contents.as_slice()).unwrap();
    Ok(())
}

pub fn load_encrypted(path: &str) -> std::io::Result<(Header, Vec<u8>)> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    // Deserialize the header
    let header_end = contents.iter().position(|&b| b == b'\n').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Invalid file format: missing header")
    })?;
    let header_bytes = &contents[..header_end];
    let body_bytes = &contents[header_end + 1..];

    let header: Header = serde_json::from_slice(header_bytes).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse header: {}", e))
    })?;

    Ok((header, body_bytes.to_vec()))
}

pub fn save_unencrypted(plaintext: &Vec<u8>, path: &str) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(plaintext)?;
    Ok(())
}

pub fn get_unique_file_name(base_name: &str, extension: Option<&str>) -> String {
    let mut file_name = match extension {
        Some(ext) => format!("{}.{}", base_name, ext),
        None => base_name.to_string(),
    };
    let mut counter = 1;

    // Check if the file already exists
    while Path::new(&file_name).exists() {
        file_name = match extension {
            Some(ext) => format!("{}({}).{}", base_name, counter, ext),
            None => format!("{}({})", base_name, counter),
        };
        counter += 1;
    }

    file_name
}