use crate::lookup_value;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;

/// A vaccination entry.
///
/// It provides all the necessary detail regarding a vaccination record.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Vaccination {
    /// Targeted Disease or agent
    #[serde(rename = "tg")]
    pub targeted_disease: Cow<'static, str>,
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
    pub date: Cow<'static, str>,
    /// Country of Vaccination
    #[serde(rename = "co")]
    pub country: Cow<'static, str>,
    /// Certificate Issuer
    #[serde(rename = "is")]
    pub issuer: Cow<'static, str>,
    /// Unique Certificate Identifier: UVCI
    #[serde(rename = "ci")]
    pub id: Cow<'static, str>,
}

impl Vaccination {
    /// Updates all the ids in the vaccination entry with their descriptive counterparts using
    /// the official valueset.
    pub fn expand_values(&mut self) {
        lookup_value(&mut self.targeted_disease);
        lookup_value(&mut self.vaccine_prophylaxis);
        lookup_value(&mut self.medicinal_product);
        lookup_value(&mut self.manufacturer);
        lookup_value(&mut self.country);
    }
}

impl fmt::Display for Vaccination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Vaccinated against {} with {} of {} doses on {}. Issued by {}",
            self.targeted_disease, self.dose_number, self.total_doses, self.date, self.issuer
        )
    }
}
