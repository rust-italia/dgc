use serde::{Deserialize, Serialize};

use super::DgcCert;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DgcCertContainer {
    #[serde(alias = "1")]
    #[serde(rename(serialize = "1"))]
    pub issuer: String,
    #[serde(alias = "6")]
    #[serde(rename(serialize = "6"))]
    pub issued_at: String,
    #[serde(alias = "4")]
    #[serde(rename(serialize = "4"))]
    pub expiration_time: String,
    #[serde(alias = "-260")]
    #[serde(rename(serialize = "-260"))]
    pub certs: Vec<DgcCert>,
}

impl DgcCertContainer {
    pub fn expand_values(&self) -> Self {
        let mut expanded = self.clone();
        expanded.certs = self.certs.iter().map(|t| t.expand_values()).collect();
        expanded
    }
}

// TODO: impl custom deserializer (see: https://serde.rs/deserialize-struct.html)
