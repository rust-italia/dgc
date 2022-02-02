use crate::Dgc;
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Serialize,
};
use std::{borrow::Cow, collections::HashMap};

const ISSUER: i64 = 1;
const ISSUED_AT: i64 = 6;
const EXPIRATION_TIME: i64 = 4;
const CERTS: i64 = -260;

/// The main container for one or more DGC entries.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct DgcContainer {
    /// The issuer of the data in the container
    #[serde(rename = "1")]
    pub issuer: Cow<'static, str>,
    /// A unix timestamp representing the moment in time when the data in the container was issued
    #[serde(rename = "6")]
    pub issued_at: IntegerOrFloat,
    /// A unix timestamp representing the moment in time when the data in the container is to be considered expired
    #[serde(rename = "4", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<IntegerOrFloat>,
    /// A collection of certificates embedded in the container
    #[serde(rename = "-260")]
    pub certs: HashMap<usize, Dgc>,
}

/// Represents an integer or a float value.
///
/// Used to parse unix timestamps (which are sometime stored as floats).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IntegerOrFloat {
    /// A unix timestamp as float value
    Float(f64),
    /// A unix timestamp as integer value
    Integer(u64),
}

impl DgcContainer {
    /// Updates all the ids in all the entries with their descriptive counterparts using
    /// the official valueset.
    ///
    /// Useful shortcut to print all the details in a more descriptive way.
    pub fn expand_values(&mut self) {
        self.certs.iter_mut().for_each(|(_, t)| t.expand_values());
    }
}

struct DgcContainerVisitor;

impl<'de> Visitor<'de> for DgcContainerVisitor {
    type Value = DgcContainer;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("struct DgcCertContainer")
    }

    fn visit_map<V>(self, mut map: V) -> Result<DgcContainer, V::Error>
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

        Ok(DgcContainer {
            issuer,
            issued_at,
            expires_at: expiration_time,
            certs,
        })
    }
}

/// Needs a specialized deserializer to be able to deal with keys as integers
impl<'de> Deserialize<'de> for DgcContainer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(DgcContainerVisitor)
    }
}
