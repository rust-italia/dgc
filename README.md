# dgc

<img src="https://github.com/lmammino/dgc/raw/main/dgc-rust-logo.svg" alt="DGC rust library logo" width="300">

[![Test](https://github.com/lmammino/dgc/actions/workflows/Test.yml/badge.svg)](https://github.com/lmammino/dgc/actions/workflows/Test.yml)
[![codecov](https://codecov.io/gh/lmammino/dgc/branch/main/graph/badge.svg?token=4CNbvgaDc1)](https://codecov.io/gh/lmammino/dgc)
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

  - It only supports EC signatures (see [#2](https://github.com/lmammino/dgc/issues/2))
  - It does not support KID in the COSE unprotected header (see [#1](https://github.com/lmammino/dgc/issues/1))


## Dgc in action

TODO:
ADD examples 🤞


## Usage

To install the latest version of `dgc`, add this to your Cargo.toml:

```toml
[dependencies]
dgc = "*"
```

To get started using `dgc`, see the [`examples`](https://github.com/lmammino/dgc/tree/main/examples) or the [docs](https://docs.rs/dgc).

If you clone the repository locally, you can easily run the example files with:

```bash
cargo run --example <name of example file>
```


## Contributing

Everyone is very welcome to contribute to this project.
You can contribute just by submitting bugs or suggesting improvements by
[opening an issue on GitHub](https://github.com/lmammino/dgc/issues).


## License

Licensed under [MIT License](LICENSE). © Luciano Mammino.
