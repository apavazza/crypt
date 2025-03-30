use std::process::exit;

pub fn create() -> String {
    println!("Enter password:");
    let password1 = rpassword::read_password().unwrap();
    println!("Confirm password:");
    let password2 = rpassword::read_password().unwrap();
    if password1 != password2 {
        eprintln!("Passwords do not match.");
        exit(0)
    }
    password1
}

pub fn ask() -> String {
    println!("Enter password:");
    let password = rpassword::read_password().unwrap();
    password
}