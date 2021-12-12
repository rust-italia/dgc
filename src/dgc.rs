use std::borrow::Cow;
use std::fmt;

use crate::{Recovery, Test, Vaccination};
use serde::{Deserialize, Deserializer, Serialize};

/// Contains all the info related to the subject name (forename, surname, etc.).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DgcName {
    /// The forename(s) of the person addressed in the certificate
    #[serde(rename = "gn", skip_serializing_if = "Option::is_none")]
    pub forename: Option<Cow<'static, str>>,
    /// The surname or primary name(s) of the person addressed in the certificate
    #[serde(rename = "fn", skip_serializing_if = "Option::is_none")]
    pub surname: Option<Cow<'static, str>>,
    /// The forename(s) of the person, transliterated ICAO 9303
    #[serde(rename = "gnt", skip_serializing_if = "Option::is_none")]
    pub forename_standard: Option<Cow<'static, str>>,
    /// The surname(s) of the person, transliterated ICAO 9303
    #[serde(rename = "fnt")]
    pub surname_standard: Cow<'static, str>,
}

impl fmt::Display for DgcName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.forename.as_ref(), self.surname.as_ref()) {
            (Some(forename), Some(surname)) => write!(f, "{} {}", forename, surname),
            (Some(forename), None) => write!(f, "{}", forename),
            (None, Some(surname)) => write!(f, "{}", surname),
            (None, None) => write!(f, "{}", self.surname_standard),
        }
    }
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
    pub version: Cow<'static, str>,
    /// The name of the person addressed in the DGC.
    #[serde(rename = "nam")]
    pub name: DgcName,
    /// Date of Birth of the person addressed in the DGC. ISO 8601 date format restricted to range 1900-2099 or empty
    #[serde(rename = "dob")]
    pub date_of_birth: Cow<'static, str>,
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

impl fmt::Display for Dgc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} ({})", self.name, self.date_of_birth)?;
        for test in &self.tests {
            writeln!(f, "{}", test)?;
        }

        for vaccine in &self.vaccines {
            writeln!(f, "{}", vaccine)?;
        }

        for recovery in &self.recoveries {
            writeln!(f, "{}", recovery)?;
        }
        Ok(())
    }
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
    use super::*;

    #[test]
    fn test_json_serialization() {
        let expected_json = "{\"ver\":\"1.3.0\",\"nam\":{\"gn\":\"ALSTON\",\"fn\":\"BLAKE\",\"gnt\":\"ALSTON\",\"fnt\":\"BLAKE\"},\"dob\":\"1990-01-01\",\"t\":[{\"tg\":\"840539006\",\"tt\":\"LP6464-4\",\"sc\":\"2021-10-09T12:03:12Z\",\"tr\":\"260415000\",\"tc\":\"Alhosn One Day Surgery\",\"co\":\"AE\",\"is\":\"Ministry of Health & Prevention\",\"ci\":\"URN:UVCI:V1:AE:8KST0RH057HI8XKW3M8K2NAD06\"}]}";
        let cert = Dgc {
            version: "1.3.0".into(),
            name: DgcName {
                forename: Some("ALSTON".into()),
                surname: Some("BLAKE".into()),
                forename_standard: Some("ALSTON".into()),
                surname_standard: "BLAKE".into(),
            },
            date_of_birth: "1990-01-01".into(),
            tests: vec![Test {
                targeted_disease: "840539006".into(),
                test_type: "LP6464-4".into(),
                date_of_collection: "2021-10-09T12:03:12Z".into(),
                result: "260415000".into(),
                testing_centre: Some("Alhosn One Day Surgery".into()),
                country: "AE".into(),
                issuer: "Ministry of Health & Prevention".into(),
                id: "URN:UVCI:V1:AE:8KST0RH057HI8XKW3M8K2NAD06".into(),
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
        assert_eq!(cert.version, "1.0.0");
        assert_eq!(cert.name.surname, Some("Di Caprio".into()));
        assert_eq!(cert.name.surname_standard, "DI<CAPRIO");
        assert_eq!(cert.name.forename, Some("Marilù Teresa".into()));
        assert_eq!(cert.name.forename_standard, Some("MARILU<TERESA".into()));
        assert_eq!(cert.date_of_birth, "1977-06-16");
        assert_eq!(cert.tests[0].targeted_disease, "840539006");
        assert_eq!(cert.tests[0].test_type, "LP6464-4");
        assert_eq!(cert.tests[0].name, Some("Roche LightCycler qPCR".into()));
        assert_eq!(cert.tests[0].manufacturer, Some("1232".into()));
        assert_eq!(cert.tests[0].date_of_collection, "2021-05-03T10:27:15Z");
        assert_eq!(
            cert.tests[0].date_of_result,
            Some("2021-05-11T12:27:15Z".into())
        );
        assert_eq!(cert.tests[0].result, "260415000");
        assert_eq!(
            cert.tests[0].testing_centre,
            Some("Policlinico Umberto I".into())
        );
        assert_eq!(cert.tests[0].country, "IT");
        assert_eq!(cert.tests[0].issuer, "IT");
        assert_eq!(cert.tests[0].id, "01IT053059F7676042D9BEE9F874C4901F9B#3");
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
        assert_eq!(cert.version, "1.0.0");
        assert_eq!(cert.name.surname, Some("Di Caprio".into()));
        assert_eq!(cert.name.surname_standard, "DI<CAPRIO");
        assert_eq!(cert.name.forename, Some("Marilù Teresa".into()));
        assert_eq!(cert.name.forename_standard, Some("MARILU<TERESA".into()));
        assert_eq!(cert.date_of_birth, "1977-06-16");
        assert_eq!(cert.tests[0].targeted_disease, "COVID-19");
        assert_eq!(
            cert.tests[0].test_type,
            "Nucleic acid amplification with probe detection"
        );
        assert_eq!(cert.tests[0].name, Some("Roche LightCycler qPCR".into()));
        assert_eq!(
            cert.tests[0].manufacturer,
            Some("Abbott Rapid Diagnostics, Panbio COVID-19 Ag Rapid Test".into())
        );
        assert_eq!(cert.tests[0].date_of_collection, "2021-05-03T10:27:15Z");
        assert_eq!(
            cert.tests[0].date_of_result,
            Some("2021-05-11T12:27:15Z".into())
        );
        assert_eq!(cert.tests[0].result, "Not detected");
        assert_eq!(
            cert.tests[0].testing_centre,
            Some("Policlinico Umberto I".into())
        );
        assert_eq!(cert.tests[0].country, "Italy");
        assert_eq!(cert.tests[0].issuer, "Italy");
        assert_eq!(cert.tests[0].id, "01IT053059F7676042D9BEE9F874C4901F9B#3");
    }

    #[test]
    fn test_json_deserialization_and_display() {
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
        let display = format!("{}", cert);
        assert_eq!(display, "Marilù Teresa Di Caprio (1977-06-16)\nTEST: COVID-19 Not detected on 2021-05-03T10:27:15Z. Issued by Italy\n");
    }
}
