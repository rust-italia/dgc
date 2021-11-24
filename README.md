# dgc

<img src="https://github.com/rust-italia/dgc/raw/main/dgc-rust-logo.svg" alt="DGC rust library logo" width="300">

[![Test](https://github.com/rust-italia/dgc/actions/workflows/Test.yml/badge.svg)](https://github.com/rust-italia/dgc/actions/workflows/Test.yml)
[![codecov](https://codecov.io/gh/rust-italia/dgc/branch/main/graph/badge.svg?token=4CNbvgaDc1)](https://codecov.io/gh/rust-italia/dgc)
[![crates.io badge](https://img.shields.io/crates/v/dgc.svg)](https://crates.io/crates/dgc)
[![Documentation](https://docs.rs/dgc/badge.svg)](https://docs.rs/dgc)

A parser and validator for the EU Digital Green Certificate (dgc) a.k.a. greenpass 📲✅

  - **Parses** the text content of a European Digital Green Certificate (dgc or greenpass) and extract the embedded data
  - Uses a **Trustlist** of **public keys** and **Elliptic Curve** cryptography to be able to validate the signature of a given certificate
  - It offers a **minimal and easy to use API**
  - The certificate data can be easily serialized/deserialized for ease of testing and reporting
  - It embeds the [official **valueset**](https://github.com/ehn-dcc-development/ehn-dcc-schema/) so that internal IDs (diseases, result types, countries, testing authorities, etc.) can be easily expanded to their descriptive equivalents
  - It reports errors for all fallible operations minimising the opportunity for panicking
  - Offers utilities for easily populate a Trustlist from various types of keys and apis
  - It's tested against the [official testing dataset](https://github.com/eu-digital-green-certificates/dgc-testdata)


Current limitations:

  - It only supports EC signatures (see [#2](https://github.com/rust-italia/dgc/issues/2))
  - It does not support KID in the COSE unprotected header (see [#1](https://github.com/rust-italia/dgc/issues/1))


## Usage

To install the latest version of `dgc`, add this to your Cargo.toml:

```toml
[dependencies]
dgc = "*"
```


## Dgc in action

This library tries to address 2 main use cases:

### 1. Decode a certificate without validating its signature

```rust
let raw_certificate_data = "HC1:NCF:603A0T9WTWGSLKC..."; // all the raw certificate data (extracted from a QR code)
let certificate_container = dgc::decode(raw_certificate_data).expect("Cannot parse certificate data");
println!("{:#?}", certificate_container);
```


### 2. Decode a certificate and validate the signature against a trustlist

```rust
let raw_certificate_data = "HC1:NCF:603A0T9WTWGSLKC..."; // all the raw certificate data (extracted from a QR code)
// This is a X509 certificate that contains a Public Key
let signature_certificate = "MIIDujCCAaKgAwIBAgIIKUgZWBL1pnMw...";
// Key ID of the Public Key embedded in the certificate above
let key_id: Vec<u8> = vec![83, 155, 239, 7, 121, 54, 10, 62];

// We create a new Trustlist (container of "trusted" public keys)
let mut trustlist = dgc::TrustList::default();
// We add the public key in the certificate to the trustlist
trustlist
    .add_key_from_certificate(&key_id, signature_certificate)
    .expect("Failed to add key from certificate");

// Now we can validate the signature (this returns)
let (certificate_container, signature_validity) =
    dgc::validate(raw_certificate_data, &trustlist).expect("Cannot parse certificate data");

println!("{:#?}", &certificate_container);

// Checks the validity of the signature
match signature_validity {
    dgc::SignatureValidity::Valid => println!("The certificate signature is Valid!"),
    e => println!("Could not validate the signature: {}", e),
}
```


### Other examples?

To get started using `dgc`, see the [`examples`](https://github.com/rust-italia/dgc/tree/main/examples) or the [docs](https://docs.rs/dgc).

If you clone the repository locally, you can easily run the example files with:

```bash
cargo run --example <name of example file>
```


## Contributing

Everyone is very welcome to contribute to this project.
You can contribute just by submitting bugs or suggesting improvements by
[opening an issue on GitHub](https://github.com/rust-italia/dgc/issues).


## License

Licensed under [MIT License](LICENSE). © Luciano Mammino.
