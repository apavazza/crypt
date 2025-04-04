use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::exit;
use crate::header::Header;

pub fn load_unencrypted(path: &str) -> io::Result<Vec<u8>> {
    Ok(load_content(path))
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
    let contents = load_content(path);

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

fn load_content(path: &str) -> Vec<u8> {
    let mut file = File::open(path).unwrap_or_else(|e| -> File {
        println!("{}", e);
        exit(0);
    });

    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    contents
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

    let dot_count: usize = base_name.chars().filter(|&c| c == '.').count();
    let base_name_without_ext:String;
    let base_ext;
    if dot_count >=2 {
        let parts: Vec<&str> = base_name.split('.').collect();
        base_name_without_ext = parts[..parts.len() - 1].join(".");
        base_ext = parts[parts.len() - 1];
    } else {
        base_name_without_ext = base_name.to_string();
        base_ext = "";
    }

    // Check if the file already exists
    while Path::new(&file_name).exists() {
        file_name = match extension {
            Some(ext) => {
                format!("{}({}){}{}.{}", base_name_without_ext, counter, if dot_count == 1 {""} else {"."}, base_ext, ext)
            },
            None => format!("{}({}).{}", base_name_without_ext, counter, base_ext),
        };
        counter += 1;
    }

    file_name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_unique_file_name() {
        let base_name = "test_file.txt";
        let binding = crate::APP_NAME.to_lowercase();
        let extension = Some(binding.as_str());
        let unique_name = get_unique_file_name(base_name, extension);
        assert!(unique_name.starts_with(base_name));
        assert!(unique_name.ends_with(extension.unwrap()));
    }

    // Test saving and loading unencrypted files
    #[test]
    fn test_file_save_load_unencryted() {
        // Save the unencrypted file
        let sample_contents = vec![1, 2, 3, 4, 5];
        let base_name = "test_file.txt";
        let test_file_path = get_unique_file_name(base_name, None);
        save_unencrypted(&sample_contents, &test_file_path).unwrap();

        // Load the unencrypted file and check the contents
        let loaded_contents = load_unencrypted(&test_file_path).unwrap();
        assert_eq!(sample_contents, loaded_contents);
        std::fs::remove_file(test_file_path).unwrap(); // Clean up the test file
    }

    // Test saving and loading encrypted files
    #[test]
    fn test_file_save_load_encrypted() {
        // Save the encrypted file with a header
        let sample_header = Header::new(crate::crypt::CIPHER, crate::aes::KEY_SIZE, crate::crypt::MODE, crate::crypt::KDF, &crate::argon2::DEFAULT_M_COST, &crate::argon2::DEFAULT_T_COST, &crate::argon2::DEFAULT_P_COST, &[0; 22], [0; crate::aes::BLOCK_SIZE]);
        let sample_contents = vec![1, 2, 3, 4, 5];
        let base_name = "test_file.txt";
        let test_file_path = get_unique_file_name(base_name, Some(crate::APP_NAME.to_lowercase().as_str()));
        save_encrypted(&sample_header, &sample_contents, &test_file_path).unwrap();

        // Load the encrypted file and check the header and contents
        let (loaded_header, loaded_contents) = load_encrypted(&test_file_path).unwrap();
        assert!(loaded_header.is_supported());
        assert!(loaded_header.check_integrity());
        assert_eq!(sample_contents, loaded_contents);
        std::fs::remove_file(test_file_path).unwrap(); // Clean up the test file
    }
}