# dgc

<img src="https://github.com/rust-italia/dgc/raw/main/dgc-rust-logo.svg" alt="DGC rust library logo" width="300">

[![Test](https://github.com/rust-italia/dgc/actions/workflows/Test.yml/badge.svg)](https://github.com/rust-italia/dgc/actions/workflows/Test.yml)
[![codecov](https://codecov.io/gh/rust-italia/dgc/branch/main/graph/badge.svg?token=4CNbvgaDc1)](https://codecov.io/gh/rust-italia/dgc)
[![crates.io badge](https://img.shields.io/crates/v/dgc.svg)](https://crates.io/crates/dgc)
[![Documentation](https://docs.rs/dgc/badge.svg)](https://docs.rs/dgc)
[![dependency status](https://deps.rs/repo/github/rust-italia/dgc/status.svg)](https://deps.rs/repo/github/rust-italia/dgc)

A parser and validator for the **EU Digital Green Certificate (dgc)** a.k.a. _greenpass_ 📲✅

  - **Parses** the text content of a European Digital Green Certificate (dgc or greenpass) and extract the embedded data
  - Uses a **Trustlist** of **public keys** and **Elliptic Curve** cryptography to be able to validate the signature of a given certificate
  - It's tested against 500+ certificates from the [official testing dataset](https://github.com/eu-digital-green-certificates/dgc-testdata)
  - It offers a **minimal and easy to use API**
  - The certificate data can be easily serialized/deserialized for ease of testing and reporting
  - It embeds the [official **valueset**](https://github.com/ehn-dcc-development/ehn-dcc-schema/) so that internal IDs (diseases, result types, countries, testing authorities, etc.) can be easily expanded to their descriptive equivalents
  - It reports errors for all fallible operations minimising the opportunity for panicking
  - Offers utilities for easily populate a Trustlist from various types of keys and apis


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
let raw_certificate_data = "HC1:NCF:603A0T9WTWGSLKC 4K694WJN.0J$6C-7WAB0XK3JCSGA2F3R8PP4V2F35VPP.EY50.FK8ZKO/EZKEZ96LF6/A6..DV%DZJC0/D5UA QELPCG/DYUCHY83UAGVC*JCNF6F463W5KF6VF6IECSHG4KCD3DX47B46IL6646H*6MWEWJDA6A:961A6Q47EM6B$DFOC0R63KCZPCNF6OF63W5$Q6+96/SA5R6NF61G73564KC*KETF6A46.96646B565WEC.D1$CKWEDZC6VCS446$C4WEUPC3JCUIA+ED$.EF$DMWE8$CBJEMVCB445$CBWER.CGPC4WEOPCE8FHZA1+9LZAZM81G72A62+8OG7J09U47AB8V59T%6ZHBO57X48RUIY03XQOK*FZUNM UFY4D5C S3R9UW-2R*4KZJT5M MIM:03RMZNA LKTO34PA.H51966PS0KAP-KLPH.Q6$KSTJ0-G658RL5HR1";
let certificate_container = dgc::decode(raw_certificate_data).expect("Cannot parse certificate data");
println!("{:#?}", certificate_container);
```


### 2. Decode a certificate and validate the signature against a trustlist

```rust
let raw_certificate_data = "HC1:NCF:603A0T9WTWGSLKC 4K694WJN.0J$6C-7WAB0XK3JCSGA2F3R8PP4V2F35VPP.EY50.FK8ZKO/EZKEZ96LF6/A6..DV%DZJC0/D5UA QELPCG/DYUCHY83UAGVC*JCNF6F463W5KF6VF6IECSHG4KCD3DX47B46IL6646H*6MWEWJDA6A:961A6Q47EM6B$DFOC0R63KCZPCNF6OF63W5$Q6+96/SA5R6NF61G73564KC*KETF6A46.96646B565WEC.D1$CKWEDZC6VCS446$C4WEUPC3JCUIA+ED$.EF$DMWE8$CBJEMVCB445$CBWER.CGPC4WEOPCE8FHZA1+9LZAZM81G72A62+8OG7J09U47AB8V59T%6ZHBO57X48RUIY03XQOK*FZUNM UFY4D5C S3R9UW-2R*4KZJT5M MIM:03RMZNA LKTO34PA.H51966PS0KAP-KLPH.Q6$KSTJ0-G658RL5HR1";
// This is a X509 certificate that contains a Public Key
let signature_certificate = "MIIDujCCAaKgAwIBAgIIKUgZWBL1pnMwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCRlIxHTAbBgNVBAoTFElNUFJJTUVSSUUgTkFUSU9OQUxFMR4wHAYDVQQLExVGT1IgVEVTVCBQVVJQT1NFIE9OTFkxGDAWBgNVBAMTD0lOR1JPVVBFIERTYyBDQTAeFw0yMTA2MDIxMjE0MDBaFw0yMTA5MDIxMjE0MDBaMEAxCzAJBgNVBAYTAkZSMREwDwYDVQQKDAhDRVJUSUdOQTEeMBwGA1UEAwwVQ0VSVElHTkEgLSBURVNUIERHQyAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETdygPqv/l6tWFqHFEIEZxfdhtbrBpDgVjmUN4CKOu/EQFwkVVQ/4N0BamwtI0hSnSZP72byk6XqpMErYWRTCbKNdMFswCQYDVR0TBAIwADAdBgNVHQ4EFgQUUjXs7mCY2ZgROQSsw1CN0qM4Zj8wHwYDVR0jBBgwFoAUYLoYTllzE2jOy3VMAuU4OJjOingwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQAvxuSBWNOrk+FRIbU42tnwZBllUeNH7cWcrYHV0O+1k3RbpvYa0YE2J0du301/a+0+pqlatR8o8Coe/NFt4/KSu+To+i8uZXiHJn2XrAZgwPqqTvsMUVwFPWhwJpLMCejmU0A8JEhXH7s0BN6orqIH0JKLpl0/MdVviIUksnxPnP2wdCtz6dL5zKhi+Qt8BFr55PL1dvuWxnuFOsKr89MqaexQVe/WvKhG5GXBaJFDbp4USVX9Z8vwp4SfEs5nh0ti0M2fyGrpfPvWWFra/qoRGAUJEPHHPMqZT45c1rXo12+cpme2CYM4rsliQsaqdH462p7YNNI5reBC+WHhzGr9FGq9yZ1gu/yhz1cJxNwE5gsBTWnJmSnRE75lYj1a/GAb+9wfABd1Vx68Fnww3Ngp8lG2T1vEWhwQusj/OmloVbqjJiCi6PcZ1/OSTbx58Zv9ySwDd3QGxPygfMy87FuhT6iWlPv57qTMrgtEjq89J8v3WnReAhp12ru5ehN2Zv0ZkO1Of0H3yxNBsvfHUgpgwsRn4zjLVbkU+a3hr4famOThmB1X0tuikY0mbNtVejPGS0qCgeLgj8ILlUrRtsW4R6WzZdIsz7H9AYnpyZbdMPsa856xBR9s0+AzguJI9kkJxvVcpR//GiXMhs0EdgWj2rouOEPZiFNdWpVRrxv/kw==";

// We create a new Trustlist (container of "trusted" public keys)
let mut trustlist = dgc::TrustList::default();
// We add the public key in the certificate to the trustlist
trustlist
    .add_key_from_certificate(signature_certificate)
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

To get started using `dgc`, see the [`examples`](https://github.com/rust-italia/dgc/tree/main/dgc/examples) or the [docs](https://docs.rs/dgc).

If you clone the repository locally, you can easily run the example files with:

```bash
cargo run --example <name of example file>
```

## Italian support

Do you need support for Italian validation rules? Check [`dgc-italy-core`](https://github.com/rust-italia/dgc/tree/main/dgc-italy-core)!


## Data structure

The information is stored inside a certification in a multi-layered format.

This library tries to find a compromise between making the information as accessible as possible and respecting the original structure of
the raw data.

The following diagram represents how the information is organised once a certificate has been decoded:

[![Dgc data organisation diagram](https://github.com/rust-italia/dgc/raw/main/docs/certificate_structure.svg)](https://github.com/rust-italia/dgc/raw/main/docs/certificate_structure.svg)


## FAQ

### Is it legal to use this library?

You can certainly use this library to look into your own personal DGC (or the ones provided in the [official test dataset](https://github.com/eu-digital-green-certificates/dgc-testdata)).

If you are trying to use this library to look into certificates of arbitrarty individuals, you need to be aware that you will have access to privacy-sensitive personal information. Privacy-related regulation might limit you or prevent you from using this library (or the data acquired through this library). It is recommended to consult the relevant legal sources and authorities for any significant production use case.

Note that this software is licensed under [MIT license](https://github.com/rust-italia/dgc/blob/main/LICENSE) and it is provided "as is". The authors of this library take no responsibility on any issue (especially legal ones) that might arise from using this library or the data acquired through it.


## Contributing

Everyone is very welcome to contribute to this project.
You can contribute just by submitting bugs or suggesting improvements by
[opening an issue on GitHub](https://github.com/rust-italia/dgc/issues).


## License

Licensed under [MIT License](https://github.com/rust-italia/dgc/blob/main/LICENSE). © Luciano Mammino + Rust Italia.
