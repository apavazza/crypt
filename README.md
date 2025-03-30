# Crypt

A file encryption and decryption tool using AES and Argon2id

## Usage

### Encrypting a file

To encrypt a file run

```shell
crypt encrypt <filename>
```

or

```shell
crypt e <filename>
```

### Decrypting a file

To decrypt a file run

```shell
crypt decrypt <filename>
```

or

```shell
crypt d <filename>
```

## Encryption

Files are encrypted using AES-256-CBC with argon2id hashing.

## Compiling

To compile the program run

```shell
cargo build --release
```

## License

This software is provided under the terms of the [GNU General Public License v3.0](LICENSE).
