// https://github.com/ehn-dcc-development/ehn-dcc-schema

use serde::{Deserialize, Serialize};

pub mod recovery;
pub mod test;
pub mod vaccination;
pub mod valuesets;
use recovery::Recovery;
use test::Test;
use vaccination::Vaccination;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DgcCertName {
    pub gn: String,
    pub r#fn: String,
    pub gnt: String,
    pub fnt: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DgcCert {
    pub ver: String,
    pub nam: DgcCertName,
    pub dob: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub t: Vec<Test>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub v: Vec<Vaccination>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub r: Vec<Recovery>,
}

impl DgcCert {
    pub fn expand_values(&self) -> Self {
        let mut expanded = self.clone();
        expanded.t = self.t.iter().map(|t| t.expand_values()).collect();
        expanded.v = self.v.iter().map(|v| v.expand_values()).collect();
        expanded.r = self.r.iter().map(|r| r.expand_values()).collect();
        expanded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_serialization() {
        let expected_json = "{\"ver\":\"1.3.0\",\"nam\":{\"gn\":\"ALSTON\",\"fn\":\"BLAKE\",\"gnt\":\"ALSTON\",\"fnt\":\"BLAKE\"},\"dob\":\"1990-01-01\",\"t\":[{\"tg\":\"840539006\",\"tt\":\"LP6464-4\",\"sc\":\"2021-10-09T12:03:12Z\",\"tr\":\"260415000\",\"tc\":\"Alhosn One Day Surgery\",\"co\":\"AE\",\"is\":\"Ministry of Health & Prevention\",\"ci\":\"URN:UVCI:V1:AE:8KST0RH057HI8XKW3M8K2NAD06\"}]}";
        let cert = DgcCert {
            ver: String::from("1.3.0"),
            nam: DgcCertName {
                gn: String::from("ALSTON"),
                r#fn: String::from("BLAKE"),
                gnt: String::from("ALSTON"),
                fnt: String::from("BLAKE"),
            },
            dob: String::from("1990-01-01"),
            t: vec![Test {
                tg: String::from("840539006"),
                tt: String::from("LP6464-4"),
                sc: String::from("2021-10-09T12:03:12Z"),
                tr: String::from("260415000"),
                tc: Some(String::from("Alhosn One Day Surgery")),
                co: String::from("AE"),
                is: String::from("Ministry of Health & Prevention"),
                ci: String::from("URN:UVCI:V1:AE:8KST0RH057HI8XKW3M8K2NAD06"),
                nm: None,
                ma: None,
                dr: None,
            }],
            v: vec![],
            r: vec![],
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
        let cert: DgcCert = serde_json::from_str(json_data).unwrap();
        assert_eq!(cert.ver, String::from("1.0.0"));
        assert_eq!(cert.nam.r#fn, String::from("Di Caprio"));
        assert_eq!(cert.nam.fnt, String::from("DI<CAPRIO"));
        assert_eq!(cert.nam.gn, String::from("Marilù Teresa"));
        assert_eq!(cert.nam.gnt, String::from("MARILU<TERESA"));
        assert_eq!(cert.dob, String::from("1977-06-16"));
        assert_eq!(cert.t[0].tg, String::from("840539006"));
        assert_eq!(cert.t[0].tt, String::from("LP6464-4"));
        assert_eq!(cert.t[0].nm, Some(String::from("Roche LightCycler qPCR")));
        assert_eq!(cert.t[0].ma, Some(String::from("1232")));
        assert_eq!(cert.t[0].sc, String::from("2021-05-03T10:27:15Z"));
        assert_eq!(cert.t[0].dr, Some(String::from("2021-05-11T12:27:15Z")));
        assert_eq!(cert.t[0].tr, String::from("260415000"));
        assert_eq!(cert.t[0].tc, Some(String::from("Policlinico Umberto I")));
        assert_eq!(cert.t[0].co, String::from("IT"));
        assert_eq!(cert.t[0].is, String::from("IT"));
        assert_eq!(
            cert.t[0].ci,
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
        let cert: DgcCert = serde_json::from_str(json_data).unwrap();
        let cert = cert.expand_values();
        assert_eq!(cert.ver, String::from("1.0.0"));
        assert_eq!(cert.nam.r#fn, String::from("Di Caprio"));
        assert_eq!(cert.nam.fnt, String::from("DI<CAPRIO"));
        assert_eq!(cert.nam.gn, String::from("Marilù Teresa"));
        assert_eq!(cert.nam.gnt, String::from("MARILU<TERESA"));
        assert_eq!(cert.dob, String::from("1977-06-16"));
        assert_eq!(cert.t[0].tg, String::from("COVID-19"));
        assert_eq!(
            cert.t[0].tt,
            String::from("Nucleic acid amplification with probe detection")
        );
        assert_eq!(cert.t[0].nm, Some(String::from("Roche LightCycler qPCR")));
        assert_eq!(
            cert.t[0].ma,
            Some(String::from(
                "Abbott Rapid Diagnostics, Panbio COVID-19 Ag Rapid Test"
            ))
        );
        assert_eq!(cert.t[0].sc, String::from("2021-05-03T10:27:15Z"));
        assert_eq!(cert.t[0].dr, Some(String::from("2021-05-11T12:27:15Z")));
        assert_eq!(cert.t[0].tr, String::from("Not detected"));
        assert_eq!(cert.t[0].tc, Some(String::from("Policlinico Umberto I")));
        assert_eq!(cert.t[0].co, String::from("Italy"));
        assert_eq!(cert.t[0].is, String::from("Italy"));
        assert_eq!(
            cert.t[0].ci,
            String::from("01IT053059F7676042D9BEE9F874C4901F9B#3")
        );
    }
}
