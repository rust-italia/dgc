#!/usr/bin/env bash

# Downloads the repo https://github.com/eu-digital-green-certificates/dgc-testdata and copies the test data into the tests

set -e

REPO_URL="https://codeload.github.com/eu-digital-green-certificates/dgc-testdata/zip/refs/heads/main"
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
TMP_FOLDER=$(mktemp -d)

curl -s -o "${TMP_FOLDER}/main.zip" "${REPO_URL}"
cd "${TMP_FOLDER}"
unzip -qq "main"
rm -rf "${SCRIPT_DIR}/data"

cd "dgc-testdata-main"
for f in $(find . -type f -name "*.json")
do
    rel=$(echo "${f}" | cut -c3-)
    rel_folder=$(dirname "${rel}")
    name=$(echo "${rel}" | sed -r 's/[\/.+\-]/_/g' | tr '[:upper:]' '[:lower:]')
    mkdir -p "${SCRIPT_DIR}/data/${rel_folder}"
    cp "${rel}" "${SCRIPT_DIR}/data/${rel}"
    echo "#[case::${name}(\"${rel}\")]"
done

rm -rf "${TMP_FOLDER}"
