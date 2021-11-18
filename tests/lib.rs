#[cfg(test)]
use green_pass::*;
// Tests the library against some of the test data available at https://github.com/eu-digital-green-certificates/dgc-testdata
use rstest::rstest;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

#[rstest]
#[case::ae_1_json("AE_1.json")]
#[case::ae_2_json("AE_2.json")]
#[case::it_1_json("IT_1.json")]
#[case::it_2_json("IT_2.json")]
#[case::it_3_json("IT_3.json")]
#[case::it_4_json("IT_4.json")]
fn test_case(#[case] test_file: &str) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("data");
    path.push(test_file);

    let file_content = fs::read_to_string(path).unwrap();
    let test_data: Value = serde_json::from_str(file_content.as_str()).unwrap();

    let raw_hcert = test_data["PREFIX"].as_str().unwrap();
    let expected = &test_data["JSON"];
    let decoded = decode(raw_hcert).unwrap();

    assert_eq!(decoded["-260"]["1"], *expected);
}
