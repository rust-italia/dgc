use crate::lookup_value;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;

/// A test entry.
///
/// It provides all the necessary detail regarding a test record against a given disease.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Test {
    /// Targeted disease or agent
    #[serde(rename = "tg")]
    pub targeted_disease: Cow<'static, str>,
    /// Type of test
    #[serde(rename = "tt")]
    pub test_type: Cow<'static, str>,
    /// NAA Test Name
    #[serde(rename = "nm", skip_serializing_if = "Option::is_none")]
    pub name: Option<Cow<'static, str>>,
    /// RAT Test name and manufacturer
    #[serde(rename = "ma", skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<Cow<'static, str>>,
    /// Date/Time of Sample Collection
    #[serde(rename = "sc")]
    pub date_of_collection: Cow<'static, str>,
    /// Date/Time of Test Result
    /// Deprecated in v1.3.0 of the schema
    #[serde(rename = "dr", skip_serializing_if = "Option::is_none")]
    pub date_of_result: Option<Cow<'static, str>>,
    /// Test Result
    #[serde(rename = "tr")]
    pub result: Cow<'static, str>,
    /// Testing Centre
    #[serde(rename = "tc", skip_serializing_if = "Option::is_none")]
    pub testing_centre: Option<Cow<'static, str>>,
    /// Country of Test
    #[serde(rename = "co")]
    pub country: Cow<'static, str>,
    /// Certificate Issuer
    #[serde(rename = "is")]
    pub issuer: Cow<'static, str>,
    /// Unique Certificate Identifier, UVCI
    #[serde(rename = "ci")]
    pub id: Cow<'static, str>,
}

impl Test {
    /// Updates all the ids in the test entry with their descriptive counterparts using
    /// the official valueset.
    pub fn expand_values(&mut self) {
        lookup_value(&mut self.targeted_disease);
        lookup_value(&mut self.test_type);
        lookup_value(&mut self.result);
        if let Some(ma) = self.manufacturer.as_mut() {
            lookup_value(ma);
        }
        lookup_value(&mut self.country);
        lookup_value(&mut self.issuer);
    }
}

impl fmt::Display for Test {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TEST: {} {} on {}. Issued by {}",
            self.targeted_disease, self.result, self.date_of_collection, self.issuer
        )
    }
}
