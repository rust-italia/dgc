use crate::lookup_value;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// A recovery entry.
///
/// It provides all the necessary detail regarding the recovery from a given disease.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Recovery {
    /// Targeted Disease or agent
    #[serde(rename = "tg")]
    pub targeted_disease: Cow<'static, str>,
    /// ISO 8601 complete date of first positive NAA test result
    #[serde(rename = "fr")]
    pub result_date: Cow<'static, str>,
    /// Country of Test
    #[serde(rename = "co")]
    pub country: Cow<'static, str>,
    /// Certificate Issuer
    #[serde(rename = "is")]
    pub issuer: Cow<'static, str>,
    /// ISO 8601 complete date: Certificate Valid From
    #[serde(rename = "df")]
    pub valid_from: Cow<'static, str>,
    /// ISO 8601 complete date: Certificate Valid Until
    #[serde(rename = "du")]
    pub valid_until: Cow<'static, str>,
    /// Unique Certificate Identifier, UVCI
    #[serde(rename = "ci")]
    pub id: Cow<'static, str>,
}

impl Recovery {
    /// Updates all the ids in the recovery entry with their descriptive counterparts using
    /// the official valueset.
    pub fn expand_values(&mut self) {
        lookup_value(&mut self.targeted_disease);
        lookup_value(&mut self.country);
    }
}
