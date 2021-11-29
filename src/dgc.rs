use crate::{Recovery, Test, Vaccination};
use serde::{Deserialize, Deserializer, Serialize};

/// Contains all the info related to the subject name (forename, surname, etc.).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DgcName {
    /// The forename(s) of the person addressed in the certificate
    #[serde(rename = "gn", skip_serializing_if = "Option::is_none")]
    pub forename: Option<String>,
    /// The surname or primary name(s) of the person addressed in the certificate
    #[serde(rename = "fn", skip_serializing_if = "Option::is_none")]
    pub surname: Option<String>,
    /// The forename(s) of the person, transliterated ICAO 9303
    #[serde(rename = "gnt", skip_serializing_if = "Option::is_none")]
    pub forename_standard: Option<String>,
    /// The surname(s) of the person, transliterated ICAO 9303
    #[serde(rename = "fnt")]
    pub surname_standard: String,
}

fn empty_if_null<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let opt = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// The main certificate.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Dgc {
    /// The certificate version as per the published [schemas](https://github.com/ehn-dcc-development/ehn-dcc-schema).
    #[serde(rename = "ver")]
    pub version: String,
    /// The name of the person addressed in the DGC.
    #[serde(rename = "nam")]
    pub name: DgcName,
    /// Date of Birth of the person addressed in the DGC. ISO 8601 date format restricted to range 1900-2099 or empty
    #[serde(rename = "dob")]
    pub date_of_birth: String,
    /// Test Group
    #[serde(
        rename = "t",
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "empty_if_null"
    )]
    pub tests: Vec<Test>,
    /// Vaccination Group
    #[serde(
        rename = "v",
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "empty_if_null"
    )]
    pub vaccines: Vec<Vaccination>,
    /// Recovery Group
    #[serde(
        rename = "r",
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "empty_if_null"
    )]
    pub recoveries: Vec<Recovery>,
}

impl Dgc {
    /// Updates all the ids in all the entries with their descriptive counterparts using
    /// the official valueset.
    ///
    /// Useful shortcut to print all the details in a more descriptive way.
    pub fn expand_values(&mut self) {
        self.tests.iter_mut().for_each(|t| t.expand_values());
        self.vaccines.iter_mut().for_each(|v| v.expand_values());
        self.recoveries.iter_mut().for_each(|r| r.expand_values());
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    #[test]
    fn test_json_serialization() {
        let expected_json = "{\"ver\":\"1.3.0\",\"nam\":{\"gn\":\"ALSTON\",\"fn\":\"BLAKE\",\"gnt\":\"ALSTON\",\"fnt\":\"BLAKE\"},\"dob\":\"1990-01-01\",\"t\":[{\"tg\":\"840539006\",\"tt\":\"LP6464-4\",\"sc\":\"2021-10-09T12:03:12Z\",\"tr\":\"260415000\",\"tc\":\"Alhosn One Day Surgery\",\"co\":\"AE\",\"is\":\"Ministry of Health & Prevention\",\"ci\":\"URN:UVCI:V1:AE:8KST0RH057HI8XKW3M8K2NAD06\"}]}";
        let cert = Dgc {
            version: String::from("1.3.0"),
            name: DgcName {
                forename: Some(String::from("ALSTON")),
                surname: Some(String::from("BLAKE")),
                forename_standard: Some(String::from("ALSTON")),
                surname_standard: String::from("BLAKE"),
            },
            date_of_birth: String::from("1990-01-01"),
            tests: vec![Test {
                targeted_disease: Cow::from("840539006"),
                test_type: Cow::from("LP6464-4"),
                date_of_collection: String::from("2021-10-09T12:03:12Z"),
                result: Cow::from("260415000"),
                testing_centre: Some(String::from("Alhosn One Day Surgery")),
                country: Cow::from("AE"),
                issuer: Cow::from("Ministry of Health & Prevention"),
                id: String::from("URN:UVCI:V1:AE:8KST0RH057HI8XKW3M8K2NAD06"),
                name: None,
                manufacturer: None,
                date_of_result: None,
            }],
            vaccines: vec![],
            recoveries: vec![],
        };

        let serialized = serde_json::to_string(&cert).unwrap();

        assert_eq!(expected_json, serialized);
    }

    #[test]
    fn test_json_deserialization() {
        let json_data = r#"{
            "ver": "1.0.0",
            "nam": {
              "fn": "Di Caprio",
              "fnt": "DI<CAPRIO",
              "gn": "Marilù Teresa",
              "gnt": "MARILU<TERESA"
            },
            "dob": "1977-06-16",
            "t": [
              {
                "tg": "840539006",
                "tt": "LP6464-4",
                "nm": "Roche LightCycler qPCR",
                "ma": "1232",
                "sc": "2021-05-03T10:27:15Z",
                "dr": "2021-05-11T12:27:15Z",
                "tr": "260415000",
                "tc": "Policlinico Umberto I",
                "co": "IT",
                "is": "IT",
                "ci": "01IT053059F7676042D9BEE9F874C4901F9B#3"
              }
            ]
          }
"#;
        let cert: Dgc = serde_json::from_str(json_data).unwrap();
        assert_eq!(cert.version, String::from("1.0.0"));
        assert_eq!(cert.name.surname, Some(String::from("Di Caprio")));
        assert_eq!(cert.name.surname_standard, String::from("DI<CAPRIO"));
        assert_eq!(cert.name.forename, Some(String::from("Marilù Teresa")));
        assert_eq!(
            cert.name.forename_standard,
            Some(String::from("MARILU<TERESA"))
        );
        assert_eq!(cert.date_of_birth, String::from("1977-06-16"));
        assert_eq!(cert.tests[0].targeted_disease, String::from("840539006"));
        assert_eq!(cert.tests[0].test_type, String::from("LP6464-4"));
        assert_eq!(
            cert.tests[0].name,
            Some(String::from("Roche LightCycler qPCR"))
        );
        assert_eq!(cert.tests[0].manufacturer, Some(Cow::from("1232")));
        assert_eq!(
            cert.tests[0].date_of_collection,
            String::from("2021-05-03T10:27:15Z")
        );
        assert_eq!(
            cert.tests[0].date_of_result,
            Some(String::from("2021-05-11T12:27:15Z"))
        );
        assert_eq!(cert.tests[0].result, String::from("260415000"));
        assert_eq!(
            cert.tests[0].testing_centre,
            Some(String::from("Policlinico Umberto I"))
        );
        assert_eq!(cert.tests[0].country, String::from("IT"));
        assert_eq!(cert.tests[0].issuer, String::from("IT"));
        assert_eq!(
            cert.tests[0].id,
            String::from("01IT053059F7676042D9BEE9F874C4901F9B#3")
        );
    }

    #[test]
    fn test_json_deserialization_and_expansion() {
        let json_data = r#"{
            "ver": "1.0.0",
            "nam": {
              "fn": "Di Caprio",
              "fnt": "DI<CAPRIO",
              "gn": "Marilù Teresa",
              "gnt": "MARILU<TERESA"
            },
            "dob": "1977-06-16",
            "t": [
              {
                "tg": "840539006",
                "tt": "LP6464-4",
                "nm": "Roche LightCycler qPCR",
                "ma": "1232",
                "sc": "2021-05-03T10:27:15Z",
                "dr": "2021-05-11T12:27:15Z",
                "tr": "260415000",
                "tc": "Policlinico Umberto I",
                "co": "IT",
                "is": "IT",
                "ci": "01IT053059F7676042D9BEE9F874C4901F9B#3"
              }
            ]
          }
"#;
        let mut cert: Dgc = serde_json::from_str(json_data).unwrap();
        cert.expand_values();
        assert_eq!(cert.version, String::from("1.0.0"));
        assert_eq!(cert.name.surname, Some(String::from("Di Caprio")));
        assert_eq!(cert.name.surname_standard, String::from("DI<CAPRIO"));
        assert_eq!(cert.name.forename, Some(String::from("Marilù Teresa")));
        assert_eq!(
            cert.name.forename_standard,
            Some(String::from("MARILU<TERESA"))
        );
        assert_eq!(cert.date_of_birth, String::from("1977-06-16"));
        assert_eq!(cert.tests[0].targeted_disease, String::from("COVID-19"));
        assert_eq!(
            cert.tests[0].test_type,
            String::from("Nucleic acid amplification with probe detection")
        );
        assert_eq!(
            cert.tests[0].name,
            Some(String::from("Roche LightCycler qPCR"))
        );
        assert_eq!(
            cert.tests[0].manufacturer,
            Some(Cow::from(
                "Abbott Rapid Diagnostics, Panbio COVID-19 Ag Rapid Test"
            ))
        );
        assert_eq!(
            cert.tests[0].date_of_collection,
            String::from("2021-05-03T10:27:15Z")
        );
        assert_eq!(
            cert.tests[0].date_of_result,
            Some(String::from("2021-05-11T12:27:15Z"))
        );
        assert_eq!(cert.tests[0].result, String::from("Not detected"));
        assert_eq!(
            cert.tests[0].testing_centre,
            Some(String::from("Policlinico Umberto I"))
        );
        assert_eq!(cert.tests[0].country, String::from("Italy"));
        assert_eq!(cert.tests[0].issuer, String::from("Italy"));
        assert_eq!(
            cert.tests[0].id,
            String::from("01IT053059F7676042D9BEE9F874C4901F9B#3")
        );
    }
}
