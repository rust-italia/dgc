use crate::lookup_value;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// A vaccination entry.
///
/// It provides all the necessary detail regarding a vaccination record.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Vaccination {
    /// Disease or agent targeted
    #[serde(rename = "tg")]
    pub disease_agent_targeted: Cow<'static, str>,
    /// Vaccine or prophylaxis
    #[serde(rename = "vp")]
    pub vaccine_prophylaxis: Cow<'static, str>,
    /// Vaccine medicinal product
    #[serde(rename = "mp")]
    pub medicinal_product: Cow<'static, str>,
    /// Marketing Authorization Holder - if no MAH present, then manufacturer
    #[serde(rename = "ma")]
    pub manufacturer: Cow<'static, str>,
    /// Dose Number
    #[serde(rename = "dn")]
    pub dose_number: usize,
    /// Total Series of Doses
    #[serde(rename = "sd")]
    pub total_doses: usize,
    /// ISO8601 complete date: Date of Vaccination
    #[serde(rename = "dt")]
    pub date: String,
    /// Country of Vaccination
    #[serde(rename = "co")]
    pub country: Cow<'static, str>,
    /// Certificate Issuer
    #[serde(rename = "is")]
    pub issuer: String,
    /// Unique Certificate Identifier: UVCI
    #[serde(rename = "ci")]
    pub id: String,
}

impl Vaccination {
    /// Updates all the ids in the vaccination entry with their descriptive counterparts using
    /// the official valueset.
    pub fn expand_values(&mut self) {
        self.disease_agent_targeted = lookup_value(&self.disease_agent_targeted);
        self.vaccine_prophylaxis = lookup_value(&self.vaccine_prophylaxis);
        self.medicinal_product = lookup_value(&self.medicinal_product);
        self.manufacturer = lookup_value(&self.manufacturer);
        self.country = lookup_value(&self.country);
    }
}
