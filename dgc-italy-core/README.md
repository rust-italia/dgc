[![Test](https://github.com/rust-italia/dgc/actions/workflows/Test.yml/badge.svg)](https://github.com/rust-italia/dgc/actions/workflows/Test.yml)
[![codecov](https://codecov.io/gh/rust-italia/dgc/branch/main/graph/badge.svg?token=4CNbvgaDc1)](https://codecov.io/gh/rust-italia/dgc)
[![crates.io badge](https://img.shields.io/crates/v/dgc-italy-core.svg)](https://crates.io/crates/dgc-italy-core)
[![Documentation](https://docs.rs/dgc-italy-core/badge.svg)](https://docs.rs/dgc-italy-core)
[![dependency status](https://deps.rs/repo/github/rust-italia/dgc-italy-core/status.svg)](https://deps.rs/repo/github/rust-italia/dgc-italy-core)

A validator for Italian specification of the Digital Green Certificate (dgc).

This crate provides the algorithms to verify DGCs using Italian criteria, without any _high-level tools_ to download data, cache management or similar. The aim is to give the bare bones that could be easily integrated with different HTTP and concurrency systems.
