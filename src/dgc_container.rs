use crate::DgcCert;
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Serialize,
};
use std::collections::HashMap;

const ISSUER: i64 = 1;
const ISSUED_AT: i64 = 6;
const EXPIRATION_TIME: i64 = 4;
const CERTS: i64 = -260;

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct DgcCertContainer {
    #[serde(rename = "1")]
    pub issuer: String,
    #[serde(rename = "6")]
    pub issued_at: IntegerOrFloat,
    #[serde(rename = "4", skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<IntegerOrFloat>,
    #[serde(rename = "-260")]
    pub certs: HashMap<usize, DgcCert>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IntegerOrFloat {
    Float(f64),
    Integer(u64),
}

impl DgcCertContainer {
    pub fn expand_values(&mut self) {
        self.certs.iter_mut().for_each(|(_, t)| t.expand_values());
    }
}

struct DgcCertContainerVisitor;

impl<'de> Visitor<'de> for DgcCertContainerVisitor {
    type Value = DgcCertContainer;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("struct DgcCertContainer")
    }

    fn visit_map<V>(self, mut map: V) -> Result<DgcCertContainer, V::Error>
    where
        V: MapAccess<'de>,
    {
        let mut issuer = None;
        let mut issued_at = None;
        let mut expiration_time = None;
        let mut certs = None;

        while let Some(key) = map.next_key()? {
            match key {
                ISSUER => {
                    if issuer.is_some() {
                        return Err(serde::de::Error::duplicate_field("issuer"));
                    }
                    issuer = Some(map.next_value()?);
                }
                ISSUED_AT => {
                    if issued_at.is_some() {
                        return Err(serde::de::Error::duplicate_field("issued_at"));
                    }
                    issued_at = Some(map.next_value()?);
                }
                EXPIRATION_TIME => {
                    if expiration_time.is_some() {
                        return Err(serde::de::Error::duplicate_field("expiration_time"));
                    }
                    expiration_time = Some(map.next_value()?);
                }
                CERTS => {
                    if certs.is_some() {
                        return Err(serde::de::Error::duplicate_field("certs"));
                    }
                    certs = Some(map.next_value()?);
                }
                _ => {
                    // ignore other fields
                }
            }
        }
        let issuer = issuer.ok_or_else(|| serde::de::Error::missing_field("issuer"))?;
        let issued_at = issued_at.ok_or_else(|| serde::de::Error::missing_field("issued_at"))?;
        let certs = certs.ok_or_else(|| serde::de::Error::missing_field("certs"))?;

        Ok(DgcCertContainer {
            issuer,
            issued_at,
            expiration_time,
            certs,
        })
    }
}

/// Needs a specialized deserializer to be able to deal with keys as integers
impl<'de> Deserialize<'de> for DgcCertContainer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(DgcCertContainerVisitor)
    }
}
