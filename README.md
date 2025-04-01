# Crypt

A file encryption and decryption tool using AES and Argon2id

[![Tests](https://github.com/apavazza/crypt/actions/workflows/tests.yml/badge.svg)](https://github.com/apavazza/crypt/actions/workflows/tests.yml)
![Rust version](https://img.shields.io/badge/Rust-1.85.1-brightgreen.svg)

## Usage

### Encrypting a File

To encrypt a file, run:

```shell
crypt encrypt <filename>
```

or

```shell
crypt e <filename>
```

### Decrypting a File

To decrypt a file, run:

```shell
crypt decrypt <filename>
```

or

```shell
crypt d <filename>
```

### Examining File Headers

To display the header information, run:
```shell
crypt header <filename>
```

or

```shell
crypt h <filename>
```

## Encryption

Files are encrypted using AES-256-CBC with argon2id hashing.

## Compiling

To compile the program, run:

```shell
cargo build --release
```

To run tests, run:

```shell
cargo test
```

## License

This software is provided under the terms of the [GNU General Public License v3.0](LICENSE).
