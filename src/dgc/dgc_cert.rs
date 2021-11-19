use serde::{Deserialize, Serialize};

use super::{Recovery, Test, Vaccination};

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
