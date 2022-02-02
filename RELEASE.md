# How to release a new version of this crate

> This is a guide for the maintainers of the crate

The release is managed by a [GitHub Action pipeline](https://github.com/rust-italia/dgc/actions/workflows/Release.yml) that is triggered when a new release is created on GitHub.

These are the steps that are recommended in order to create a new release of the crate:

  1. Make sure all the changes that you want to release have been correctly merged to the `main` branch.
  2. Choose the crate you want to release. It can be `dgc` or `dgc-italy-core`.
  2. Make sure the crate version has been bumped in `Cargo.toml` following the rules of [Semantic Versioning](https://semver.org/)
  3. Create a [new release](https://github.com/rust-italia/dgc/releases/new) targeting the latest commit in `main`:
      - Name the release using the name of the crate and the version number you want to publish, separated by a _slash_ (e.g. `dgc/0.1.0`)
      - Create a new tag with the same name (e.g. `dgc/0.1.0`)
      - Create a description for the release describing all the changes from the previous release (you can use the _Auto-generate release notes_ feature from GitHub to speed up this process)
  4. Publish the release and check the that the related GitHub action is triggered and completes successfully.
  5. A new release should now be available on crates.io! 🥳🍻
